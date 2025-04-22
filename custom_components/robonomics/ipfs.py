"""
This module contains functions to work with IPFS. It allows to send and receive files from IPFS.

To start work with this module check next functions - add_telemetry_to_ipfs(), add_config_to_ipfs(), create_folders() and get_ipfs_data().
"""

from __future__ import annotations

import asyncio
import aioipfs
import json
import logging
from pickle import NONE
import typing as tp
from datetime import datetime, timedelta
import time

import ipfshttpclient2
from crustinterface import Mainnet
from homeassistant.core import HomeAssistant
from homeassistant.helpers.hassio import is_hassio
from pinatapy import PinataPy
from robonomicsinterface.utils import web_3_auth
from substrateinterface import KeypairType

from .const import (
    CONF_ADMIN_SEED,
    CONF_IPFS_GATEWAY,
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONFIG_ENCRYPTED_PREFIX,
    CONFIG_PREFIX,
    DOMAIN,
    IPFS_CONFIG_PATH,
    IPFS_MAX_FILE_NUMBER,
    IPFS_MEDIA_PATH,
    IPFS_STATUS,
    IPFS_TELEMETRY_PATH,
    MAX_NUMBER_OF_REQUESTS,
    PINATA,
    SECONDS_IN_DAY,
    IPFS_STATUS_ENTITY,
    WAIT_IPFS_DAEMON,
    IPFS_USERS_PATH,
    IPFS_DAPP_FILE_NAME,
)
from .utils import (
    create_notification,
    FileSystemUtils
)
from .ipfs_helpers.decorators import catch_ipfs_errors, catch_ipfs_errors_async
from .ipfs_helpers.add_gateways import CustomGateway, LocalGateway, PinataGateway
from .ipfs_helpers.get_data import GetIPFSData
from .ipfs_helpers.utils import IPFSLocalUtils
from .exceptions import CantConnectToIPFS

_LOGGER = logging.getLogger(__name__)


async def pin_file_to_local_node_by_hash(hass: HomeAssistant, ipfs_hash: str) -> None:
    ipfs_utils = IPFSLocalUtils(hass)
    if await ipfs_utils.hash_pinned(ipfs_hash):
        _LOGGER.debug(f"Hash {ipfs_hash} is already pinned")
        return
    _LOGGER.debug(f"Start pinnig hash {ipfs_hash} to local node")
    await ipfs_utils.remove_pin(path=f"/{IPFS_DAPP_FILE_NAME}")
    pinned = await ipfs_utils.pin_by_hash(ipfs_hash, path=f"/{IPFS_DAPP_FILE_NAME}")
    if not pinned:
        path_for_download = await FileSystemUtils(hass).get_path_in_temp_dir(IPFS_DAPP_FILE_NAME)
        await download_directory_from_ipfs(hass, ipfs_hash, path_for_download)
        await LocalGateway(hass).add(path_for_download, "/", True)
        await ipfs_utils.pin_by_hash(ipfs_hash)
        await FileSystemUtils(hass).delete_temp_dir(path_for_download)


async def get_ipfs_data(
    hass: HomeAssistant,
    ipfs_hash: str,
    number_of_requests: int = MAX_NUMBER_OF_REQUESTS,
) -> tp.Optional[str]:
    res = await GetIPFSData(hass, ipfs_hash, number_of_requests).get_file_data()
    return res


async def download_directory_from_ipfs(
    hass: HomeAssistant,
    ipfs_hash: str,
    path_to_download: str,
    number_of_requests: int = MAX_NUMBER_OF_REQUESTS,
) -> tp.Optional[bool]:
    res = await GetIPFSData(
        hass, ipfs_hash, number_of_requests
    ).get_directory_to_given_path(path_to_download)
    return res


async def handle_ipfs_status_change(hass: HomeAssistant, ipfs_daemon_ok: bool):
    if not ipfs_daemon_ok:
        if is_hassio(hass):
            ipfs_service = "add-on"
        else:
            ipfs_service = "service"
        service_data = {
            "message": f"IPFS Daemon doesn't work as expected. Check the IPFS Daemon {ipfs_service} (restart may help).",
            "title": "IPFS Error",
        }
        await create_notification(hass, service_data, "ipfs")
        await wait_ipfs_daemon(hass)
    else:
        service_data = {
            "message": "IPFS Daemon works well.",
            "title": "IPFS OK",
        }
        await create_notification(hass, service_data, "ipfs")


async def wait_ipfs_daemon(hass: HomeAssistant, timeout: tp.Optional[int] = None) -> None:
    if hass.data[DOMAIN][WAIT_IPFS_DAEMON]:
        return
    hass.data[DOMAIN][WAIT_IPFS_DAEMON] = True
    _LOGGER.debug("Wait for IPFS local node connection...")
    start_time = time.time()
    connected = await _check_connection(hass)
    while not connected:
        if timeout:
            if (time.time() - start_time) > timeout:
                raise CantConnectToIPFS
        await asyncio.sleep(10)
        connected = await _check_connection(hass)
    hass.data[DOMAIN][IPFS_STATUS] = "OK"
    hass.states.async_set(
        f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
    )
    hass.data[DOMAIN][WAIT_IPFS_DAEMON] = False


async def add_telemetry_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """Send telemetry files to IPFS

    :param hass: Home Assistant instance
    :param filename: file with telemetry

    :return: IPFS hash of the file
    """

    await _delete_ipfs_telemetry_files_if_needed(hass)
    pin = await _check_save_previous_pin(hass, filename)
    if pin is None:
        pin = True
    if not pin:
        last_file_info = await IPFSLocalUtils(hass).get_last_file_hash(IPFS_TELEMETRY_PATH)
        if last_file_info is None:
            last_file_info = (None, None)
        last_file_name, last_file_hash = last_file_info[0], last_file_info[1]
    else:
        last_file_hash = None
        last_file_name = None
    ipfs_hash, size = await _add_to_ipfs(
        hass, filename, IPFS_TELEMETRY_PATH, pin, last_file_hash, last_file_name
    )
    await hass.async_add_executor_job(_upload_to_crust, hass, ipfs_hash, size)

    return ipfs_hash


async def add_config_to_ipfs(
    hass: HomeAssistant, filename: str, filename_encrypted: str
) -> tp.Optional[str]:
    """Send configuration file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with configuration of Home Assistant dashboard and services
    :param filename_encrypted: file with encrypted configuration of Home Assistant dashboard and services

    :return: IPFS hash of the file
    """

    last_file_info = await IPFSLocalUtils(hass).get_last_file_hash(
        IPFS_CONFIG_PATH, prefix=CONFIG_PREFIX
    )
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_name, last_file_hash = last_file_info[0], last_file_info[1]

    last_file_info = await IPFSLocalUtils(hass).get_last_file_hash(
        IPFS_CONFIG_PATH, prefix=CONFIG_ENCRYPTED_PREFIX
    )
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_encrypted_name, last_file_encrypted_hash = (
        last_file_info[0],
        last_file_info[1],
    )

    await LocalGateway(hass).add(filename, IPFS_CONFIG_PATH, False, last_file_name)
    ipfs_hash, size = await _add_to_ipfs(
        hass,
        filename_encrypted,
        IPFS_CONFIG_PATH,
        False,
        last_file_encrypted_hash,
        last_file_encrypted_name,
    )
    await hass.async_add_executor_job(_upload_to_crust, hass, ipfs_hash, size)

    return ipfs_hash


async def add_media_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """Send media file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with media.

    :return: IPFS hash of the file
    """

    ipfs_hash, size = await _add_to_ipfs(
        hass, filename, IPFS_MEDIA_PATH, True, None, None
    )
    await hass.async_add_executor_job(_upload_to_crust, hass, ipfs_hash, size)

    return ipfs_hash


async def add_user_info_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """Send user info encrypted file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with media.

    :return: IPFS hash of the file
    """

    address = filename.split("/")[-1]
    last_file_info = await IPFSLocalUtils(hass).get_last_file_hash(IPFS_USERS_PATH, prefix=address)
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_name, last_file_hash = last_file_info[0], last_file_info[1]

    ipfs_hash, size = await _add_to_ipfs(
        hass, filename, IPFS_USERS_PATH, False, last_file_hash, last_file_name
    )
    await hass.async_add_executor_job(_upload_to_crust, hass, ipfs_hash, size)

    return ipfs_hash


async def get_encrypted_user_info_for_address(
    hass: HomeAssistant, address: str
) -> tp.Optional[str]:
    encrypted_user_info = await read_ipfs_local_file(hass, address, IPFS_USERS_PATH)
    return encrypted_user_info


@catch_ipfs_errors_async("Exception in create_folders:")
async def create_folders(hass: HomeAssistant) -> None:
    """Create IPFS folders to store Robonomics data files."""

    async with aioipfs.AsyncIPFS() as client:
        folder_names = await IPFSLocalUtils(hass).get_files_list("/", client = client)
        if IPFS_MEDIA_PATH[1:] not in folder_names:
            await client.files.mkdir(IPFS_MEDIA_PATH)
            _LOGGER.debug(f"IPFS folder {IPFS_MEDIA_PATH} created")
        if IPFS_TELEMETRY_PATH[1:] not in folder_names:
            await client.files.mkdir(IPFS_TELEMETRY_PATH)
            _LOGGER.debug(f"IPFS folder {IPFS_TELEMETRY_PATH} created")
        if IPFS_CONFIG_PATH[1:] not in folder_names:
            await client.files.mkdir(IPFS_CONFIG_PATH)
            _LOGGER.debug(f"IPFS folder {IPFS_CONFIG_PATH} created")
        if IPFS_USERS_PATH[1:] not in folder_names:
            await client.files.mkdir(IPFS_USERS_PATH)
            _LOGGER.debug(f"IPFS folder {IPFS_USERS_PATH} created")


@catch_ipfs_errors("Exception in reading ipfs local file")
async def read_ipfs_local_file(
    hass: HomeAssistant, filename: str, path: str
) -> tp.Union[str, dict]:
    async with aioipfs.AsyncIPFS() as client:
        _LOGGER.debug(f"Read data from local file: {path}/{filename}")
        if await IPFSLocalUtils(hass).ipfs_file_exists(f"{path}/{filename}", client=client):
            data = await client.files.read(f"{path}/{filename}")
            try:
                return json.loads(data)
            except Exception as e:
                _LOGGER.debug(f"Data is not json: {e}")
                data = data.decode("utf-8")
        else:
            _LOGGER.debug(f"File {path}/{filename} does not exist")
            data = None
    return data


@catch_ipfs_errors("Exeption in delete ipfs telemetry files")
async def _delete_ipfs_telemetry_files_if_needed(hass: HomeAssistant):
    """Delete old files from IPFS from local telemetry storage."""

    files = await IPFSLocalUtils(hass).get_files_list(IPFS_TELEMETRY_PATH)
    if len(files) > IPFS_MAX_FILE_NUMBER:
        num_files_to_delete = len(files) - IPFS_MAX_FILE_NUMBER
        if num_files_to_delete > 0:
            for i in range(num_files_to_delete):
                filename = files[i]
                await IPFSLocalUtils(hass).remove_pin(f"{IPFS_TELEMETRY_PATH}/{filename}")
                _LOGGER.debug(f"Deleted old telemetry {filename}")
        hass.data[DOMAIN][IPFS_STATUS] = "OK"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )

async def _check_save_previous_pin(hass: HomeAssistant, filename: str) -> bool:
    """Check previous telemetry pins and decide should unpin previous pin or not.

    Args:
        hass (HomeAssistant): Home Assistant instance
        filename (str): file object, with which comparing time from last pin

    Returns:
        bool: True - need to save previous file; False - need to unpin previous file

    """

    ipfs_files = await IPFSLocalUtils(hass).get_files_list(IPFS_TELEMETRY_PATH)
    if len(ipfs_files) > 1:
        last_file = ipfs_files[-2]
        last_file_time = datetime.fromtimestamp(float(last_file.split("-")[-1]))
        current_file_time = datetime.fromtimestamp(float(filename.split("-")[-1]))
        delta = current_file_time - last_file_time
        _LOGGER.debug(f"Time from the last pin: {delta}")
        if delta > timedelta(seconds=SECONDS_IN_DAY):
            _LOGGER.debug("Telemetry must be pinned")
            return True
        else:
            _LOGGER.debug("Telemetry must not be pinned")
            return False
    else:
        return True


def _upload_to_crust(
    hass: HomeAssistant, ipfs_hash: str, file_size: int
) -> tp.Optional[tp.Tuple[str, str]]:
    """Call extrinsic "Place an order" in Crust network

    :param hass: home Assistant instance
    :param ipfs_hash: IPFS hash of file, which you want to store
    :param file_size: size of file in IPFS in bytes

    :return: result of the extrinsic
    """

    seed: str = hass.data[DOMAIN][CONF_ADMIN_SEED]
    try:
        mainnet = Mainnet(seed=seed, crypto_type=KeypairType.ED25519)
        # Check balance
        balance = mainnet.get_balance()
        _LOGGER.debug(f"Actual balance in crust network - {balance}")

        # Check price in Main net. Price in pCRUs
        price = mainnet.get_appx_store_price(file_size)
        _LOGGER.debug(f"approximate cost to store the file - {price}")

    except Exception as e:
        _LOGGER.debug(f"error while get account balance - {e}")
        return None

    if price >= balance:
        _LOGGER.warning("Not enough account balance to store the file in Crust Network")
        return None

    try:
        _LOGGER.debug(f"Start adding {ipfs_hash} to crust with size {file_size}")
        file_stored = mainnet.store_file(ipfs_hash, file_size)
        _LOGGER.debug(f"file stored in Crust. Extrinsic data is  {file_stored}")
    except Exception as e:
        _LOGGER.debug(f"error while uploading file to crust - {e}")
        return None
    return file_stored


async def _add_to_ipfs(
    hass: HomeAssistant,
    filename: str,
    path: str,
    pin: bool,
    last_file_hash: tp.Optional[str],
    last_file_name: tp.Optional[str],
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
    """Function uploads file to different IPFS gateways

    :param hass: Home Assistant instance
    :param filename: file with data
    :param path: local directory where to store file
    :param pin: should save previous pin or not
    :param last_file_hash: hash of file, which should be unpinned(if needed)
    :param last_file_name: name of file, which should be unpinned(if needed)

    :return: IPFS hash of the file and file size in IPFS
    """

    pinata_ipfs_file_size, local_ipfs_file_size, custom_ipfs_file_size = 0, 0, 0

    if hass.data[DOMAIN].get(CONF_PINATA_PUB) and hass.data[DOMAIN].get(CONF_PINATA_SECRET):
        added_hash_and_size = await PinataGateway(hass).add(filename, pin, last_file_hash)
        pinata_hash, pinata_ipfs_file_size = (
            (added_hash_and_size[0], added_hash_and_size[1])
            if added_hash_and_size is not None
            else (None, None)
        )
    else:
        pinata_hash = None
    added_hash_and_size = await LocalGateway(hass).add(filename, path, pin, last_file_name)
    local_hash, local_ipfs_file_size = (
        (added_hash_and_size[0], added_hash_and_size[1])
        if added_hash_and_size is not None
        else (None, None)
    )
    if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
        added_hash_and_size = await CustomGateway(hass).add(filename, pin, last_file_hash)
        custom_hash, custom_ipfs_file_size = (
            (added_hash_and_size[0], added_hash_and_size[1])
            if added_hash_and_size is not None
            else (None, None)
        )
    else:
        custom_hash = None

    if local_hash is not None:
        return local_hash, local_ipfs_file_size
    elif pinata_hash is not None:
        return pinata_hash, pinata_ipfs_file_size
    elif custom_hash is not None:
        return custom_hash, custom_ipfs_file_size
    else:
        return None, None


async def _check_connection(hass: HomeAssistant) -> bool:
    """Check connection to IPFS local node

    :return: Connected or not
    """

    try:
        async with aioipfs.AsyncIPFS() as client:
            test_hash = await client.add_str("Test string")
            test_hash = test_hash["Hash"]
            _LOGGER.debug(f"Added test string to the local node: {test_hash}")
            await asyncio.sleep(0.5)
            files_info = await IPFSLocalUtils(hass).get_files_list("/", client = client)
            _LOGGER.debug(f"Files info: {files_info}")
            if "test_file" in files_info:
                await client.files.rm("/test_file")
                _LOGGER.debug("Deleted test string from the local node MFS")
            await asyncio.sleep(0.5)
            await client.files.cp(f"/ipfs/{test_hash}", "/test_file")
            _LOGGER.debug("Added test string to the local node MFS")
            await asyncio.sleep(0.5)
            await client.files.rm("/test_file")
            _LOGGER.debug("Deleted test string from the local node MFS")
            await asyncio.sleep(0.5)
            res = await client.pin.rm(test_hash)
            _LOGGER.debug(f"Unpinned test string from local node with res: {res}")
            await asyncio.sleep(0.5)
        _LOGGER.debug("Connected to IPFS local node")
        return True
    except Exception as e:
        hass.data[DOMAIN][IPFS_STATUS] = "Error"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )
        _LOGGER.error(f"Unexpected error in check ipfs connection: {e}")
        return False
