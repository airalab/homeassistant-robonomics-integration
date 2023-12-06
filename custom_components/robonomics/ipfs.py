"""
This module contains functions to work with IPFS. It allows to send and receive files from IPFS.

To start work with this module check next functions - add_telemetry_to_ipfs(), add_config_to_ipfs(),
add_backup_to_ipfs(), create_folders() and get_ipfs_data().
"""

from __future__ import annotations

import asyncio
import json
import logging
from pickle import NONE
import typing as tp
from datetime import datetime, timedelta
import time

import ipfshttpclient2
from aiohttp import ClientSession
from crustinterface import Mainnet
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.components.hassio import is_hassio
from pinatapy import PinataPy
from robonomicsinterface.utils import web_3_auth
from substrateinterface import KeypairType

from .const import (
    BACKUP_ENCRYPTED_PREFIX,
    BACKUP_PREFIX,
    CONF_ADMIN_SEED,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
    CONF_IPFS_GATEWAY_PORT,
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONFIG_ENCRYPTED_PREFIX,
    CONFIG_PREFIX,
    DOMAIN,
    HANDLE_IPFS_REQUEST,
    IPFS_BACKUP_PATH,
    IPFS_CONFIG_PATH,
    IPFS_GATEWAY,
    IPFS_MAX_FILE_NUMBER,
    IPFS_MEDIA_PATH,
    IPFS_TELEMETRY_PATH,
    MAX_NUMBER_OF_REQUESTS,
    MORALIS_GATEWAY,
    PINATA,
    PINATA_GATEWAY,
    SECONDS_IN_DAY,
    WAIT_IPFS_DAEMON,
    IPFS_STATUS_ENTITY,
)
from .utils import get_hash, to_thread, create_notification

_LOGGER = logging.getLogger(__name__)


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
        await create_notification(hass, service_data)
        await wait_ipfs_daemon(hass)
    else:
        service_data = {
            "message": f"IPFS Daemon now works well.",
            "title": "IPFS OK",
        }
        await create_notification(hass, service_data)


async def wait_ipfs_daemon(hass: HomeAssistant) -> None:
    if hass.data[DOMAIN][WAIT_IPFS_DAEMON]:
        return
    hass.data[DOMAIN][WAIT_IPFS_DAEMON] = True
    _LOGGER.debug("Wait for IPFS local node connection...")
    while not await _check_connection(hass):
        await asyncio.sleep(10)
    hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    hass.data[DOMAIN][WAIT_IPFS_DAEMON] = False


async def add_telemetry_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """Send telemetry files to IPFS

    :param hass: Home Assistant instance
    :param filename: file with telemetry

    :return: IPFS hash of the file
    """

    pin = await _check_save_previous_pin(hass, filename)
    if not pin:
        last_file_name, last_file_hash = await get_last_file_hash(hass, IPFS_TELEMETRY_PATH)
    else:
        last_file_hash = None
        last_file_name = None
    ipfs_hash, size = await _add_to_ipfs(hass, filename, IPFS_TELEMETRY_PATH, pin, last_file_hash, last_file_name)
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


async def add_config_to_ipfs(hass: HomeAssistant, filename: str, filename_encrypted: str) -> tp.Optional[str]:
    """Send configuration file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with configuration of Home Assistant dashboard and services
    :param filename_encrypted: file with encrypted configuration of Home Assistant dashboard and services

    :return: IPFS hash of the file
    """

    last_file_name, last_file_hash = await get_last_file_hash(hass, IPFS_CONFIG_PATH, prefix=CONFIG_PREFIX)
    last_file_encrypted_name, last_file_encrypted_hash = await get_last_file_hash(
        hass, IPFS_CONFIG_PATH, prefix=CONFIG_ENCRYPTED_PREFIX
    )
    new_hash = await get_hash(filename)
    new_hash_encrypted = await get_hash(filename_encrypted)
    if new_hash == last_file_hash:
        _LOGGER.debug(f"Last config hash and the current are the same: {last_file_hash}")
        return last_file_encrypted_hash
    await _add_to_local_node(hass, filename, False, IPFS_CONFIG_PATH, last_file_name)
    ipfs_hash, size = await _add_to_ipfs(
        hass,
        filename_encrypted,
        IPFS_CONFIG_PATH,
        False,
        last_file_encrypted_hash,
        last_file_encrypted_name,
    )
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


async def add_backup_to_ipfs(hass: HomeAssistant, filename: str, filename_encrypted: str) -> tp.Optional[str]:
    """Send backup file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with full Home Assistant backup
    :param filename_encrypted: encrypted file with full Home Assistant backup

    :return: IPFS hash of the file
    """

    last_file_name, last_file_hash = await get_last_file_hash(hass, IPFS_BACKUP_PATH, prefix=BACKUP_PREFIX)
    last_file_encrypted_name, last_file_encrypted_hash = await get_last_file_hash(
        hass, IPFS_BACKUP_PATH, prefix=BACKUP_ENCRYPTED_PREFIX
    )
    new_hash = await get_hash(filename)
    new_hash_encrypted = await get_hash(filename_encrypted)
    if new_hash == last_file_hash:
        _LOGGER.debug(f"Last backup hash and the current are the same: {last_file_hash}")
        return last_file_encrypted_hash
    await _add_to_local_node(hass, filename, False, IPFS_BACKUP_PATH, last_file_name)
    ipfs_hash, size = await _add_to_ipfs(
        hass,
        filename_encrypted,
        IPFS_BACKUP_PATH,
        False,
        last_file_encrypted_hash,
        last_file_encrypted_name,
    )
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


async def add_media_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """Send media file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with media.

    :return: IPFS hash of the file
    """

    ipfs_hash, size = await _add_to_ipfs(hass, filename, IPFS_MEDIA_PATH, True, None, None)
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


@to_thread
def delete_folder_from_local_node(hass: HomeAssistant, dirname: str) -> None:
    try:
        _LOGGER.debug(f"Start deleting ipfs folder {dirname}")
        with ipfshttpclient2.connect() as client:
            folders = client.files.ls("/")
            folder_names = [folder["Name"] for folder in folders["Entries"]]
            if dirname[1:] in folder_names:
                client.files.rm(dirname, recursive=True)
                hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
                _LOGGER.debug(f"Ipfs folder {dirname} was deleted")
    except Exception as e:
        _LOGGER.error(f"Exception in deleting folder {dirname}: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
        

@to_thread
def get_folder_hash(hass: HomeAssistant, ipfs_folder: str) -> str:
    """Get IPFS hash of the given folder in MFS

    :param ipfs_folder: the name of the folder with the path

    :return: IPFS hash of the folder
    """
    try:
        with ipfshttpclient2.connect() as client:
            res = client.files.stat(ipfs_folder)
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
            return res["Hash"]
    except Exception as e:
        _LOGGER.error(f"Exception in getting folder hash: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")


@to_thread
def create_folders(hass: HomeAssistant) -> None:
    """Function creates IPFS folders to store Robonomics telemetry, configuration and backup files"""
    try:
        with ipfshttpclient2.connect() as client:
            folders = client.files.ls("/")
            folder_names = [folder_info['Name'] for folder_info in folders['Entries']]
            _LOGGER.debug(f"IPFS folders: {folder_names}")
            if IPFS_MEDIA_PATH[1:] not in folder_names:
                client.files.mkdir(IPFS_MEDIA_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_MEDIA_PATH} created")
            if IPFS_TELEMETRY_PATH[1:] not in folder_names:
                client.files.mkdir(IPFS_TELEMETRY_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_TELEMETRY_PATH} created")
            if IPFS_BACKUP_PATH[1:] not in folder_names:
                client.files.mkdir(IPFS_BACKUP_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_BACKUP_PATH} created")
            if IPFS_CONFIG_PATH[1:] not in folder_names:
                client.files.mkdir(IPFS_CONFIG_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_CONFIG_PATH} created")
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    except Exception as e:
        _LOGGER.error(f"Exception in creating ipfs folders: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")


@to_thread
def check_if_hash_in_folder(hass: HomeAssistant, ipfs_hash: str, folder: str) -> bool:
    """Check if file with given ipfs hash is in the folder

    :param ipfs_hash: IPFS hash of the file to check
    "param folder: the name of the folder

    :return: True if the file is in the folder, False othervise
    """
    try:
        with ipfshttpclient2.connect() as client:
            list_files = client.files.ls(folder)
            if list_files["Entries"] is None:
                return False
            for fileinfo in list_files["Entries"]:
                stat = client.files.stat(f"{folder}/{fileinfo['Name']}")
                if ipfs_hash == stat["Hash"]:
                    return True
            else:
                return False
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    except Exception as e:
        _LOGGER.error(f"Exception in check if hash in folder: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")


@to_thread
def get_last_file_hash(hass: HomeAssistant, path: str, prefix: str = None) -> (str, str):
    """function return name and hash of the last telemetry, configuration and backup

    :param path: path to directory with files
    :param prefix: if not None, look for the last file with this prefix

    :return: name of the last file, and file hash
    """
    _LOGGER.debug(f"Getting last file hash from {path} with prefix {prefix}")
    try:
        with ipfshttpclient2.connect() as client:
            files = client.files.ls(path)
            if len(files["Entries"]) > 0:
                if prefix is not None:
                    last_file = None
                    last_hash = None
                    for fileinfo in files["Entries"]:
                        if fileinfo["Name"][: len(prefix)] == prefix:
                            last_file = fileinfo["Name"]
                            last_hash = client.files.stat(f"{path}/{last_file}")["Hash"]
                else:
                    last_file = files["Entries"][-1]["Name"]
                    last_hash = client.files.stat(f"{path}/{last_file}")["Hash"]
                _LOGGER.debug(f"Last {path} file {last_file}, with hash {last_hash}")
                return last_file, last_hash
            else:
                return None, None
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    except Exception as e:
        _LOGGER.error(f"Exception in get_last_file_hash: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
        return None, None


@to_thread
def read_ipfs_local_file(hass: HomeAssistant, filename: str, path: str) -> tp.Union[str, dict]:
    """Read data from file pinned in local node

    :param filename: name of the file
    :param path: path to the file in MFS

    :return: dict with the data in json, string data otherwise
    """

    with ipfshttpclient2.connect() as client:
        try:
            _LOGGER.debug(f"Read data from local file: {path}/{filename}")
            data = client.files.read(f"{path}/{filename}")
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
        except Exception as e:
            _LOGGER.warning(f"Exception in reading ipfs local file: {e}")
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
            return None
        try:
            data_json = json.loads(data)
            return data_json
        except Exception as e:
            _LOGGER.debug(f"Data is not json: {e}")
        data = data.decode("utf-8")
        return data


async def get_ipfs_data(
    hass: HomeAssistant,
    ipfs_hash: str,
    number_of_request: int,
    gateways: tp.List[str] = [
        IPFS_GATEWAY,
        MORALIS_GATEWAY,
        PINATA_GATEWAY,
    ],
) -> tp.Optional[str]:
    """Get data from IPFS.

    Call when need to download telemetry, launch or backup files.

    :param hass: Home assistant instance
    :param ipfs_hash: hash of requested file
    :param number_of_request: attempt number of get request
    :param gateways: list of IPFS gateways, where function will search a file

    :return: Data from IPFS hash or None if can't get data
    """

    if number_of_request >= MAX_NUMBER_OF_REQUESTS:
        return None
    websession = async_create_clientsession(hass)
    try:
        tasks = []
        _LOGGER.debug(f"Request to IPFS number {number_of_request}")
        tasks.append(_get_from_local_node_by_hash(hass, ipfs_hash))
        for gateway in gateways:
            if gateway[-1] != "/":
                gateway += "/"
            url = f"{gateway}{ipfs_hash}"
            tasks.append(_get_request(hass, websession, url))
        if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
            custom_gateway = hass.data[DOMAIN][CONF_IPFS_GATEWAY]
            if custom_gateway is not None:
                if custom_gateway[-1] != "/":
                    custom_gateway += "/"
                if custom_gateway[-5:] != "ipfs/":
                    custom_gateway += "ipfs/"
                url = f"{custom_gateway}{ipfs_hash}"
                tasks.append(_get_request(hass, websession, url))
        for task in asyncio.as_completed(tasks):
            res = await task
            if res:
                return res
        else:
            if hass.data[DOMAIN][HANDLE_IPFS_REQUEST]:
                res = await get_ipfs_data(
                    hass,
                    ipfs_hash,
                    number_of_request + 1,
                    gateways=gateways,
                )
                return res
    except Exception as e:
        _LOGGER.error(f"Exception in get ipfs: {e}")
        if hass.data[DOMAIN][HANDLE_IPFS_REQUEST]:
            res = await get_ipfs_data(
                hass,
                ipfs_hash,
                number_of_request + 1,
                gateways=gateways,
            )
            return res


def _delete_ipfs_telemetry_files(hass: HomeAssistant):
    """Delete old files from IPFS from local telemetry storage"""

    try:
        with ipfshttpclient2.connect() as client:
            files = client.files.ls(IPFS_TELEMETRY_PATH)["Entries"]
            num_files_to_delete = len(files) - IPFS_MAX_FILE_NUMBER
            if num_files_to_delete > 0:
                for i in range(num_files_to_delete):
                    filename = files[i]["Name"]
                    client.files.rm(f"{IPFS_TELEMETRY_PATH}/{filename}")
                    _LOGGER.debug(f"Deleted old telemetry {filename}")
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    except Exception as e:
        _LOGGER.error(f"Exeption in delete ipfs telemetry files: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")


@to_thread
def _check_save_previous_pin(hass: HomeAssistant, filename: str) -> bool:
    """Function checks previous telemetry pins and decide should unpin previous pin or not

    :param filename: file object, with which comparing time from last pin

    :return: True - need to save previous file; False - need to unpin previous file
    """

    try:
        with ipfshttpclient2.connect() as client:
            files = client.files.ls(IPFS_TELEMETRY_PATH)
            if len(files["Entries"]) > IPFS_MAX_FILE_NUMBER:
                _delete_ipfs_telemetry_files(hass)
            if len(files["Entries"]) > 0:
                last_file = files["Entries"][-2]["Name"]
                last_file_time = datetime.fromtimestamp(float(last_file.split("-")[-1]))
                current_file_time = datetime.fromtimestamp(float(filename.split("-")[-1]))
                delta = current_file_time - last_file_time
                _LOGGER.debug(f"Time from the last pin: {delta}")
                if delta > timedelta(seconds=SECONDS_IN_DAY):
                    _LOGGER.debug(f"Telemetry must be pinned")
                    return True
                else:
                    _LOGGER.debug(f"Telemetry must not be pinned")
                    return False
            else:
                return True
            hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    except Exception as e:
        _LOGGER.error(f"Exception in check_if_need_pin: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
        return True


@to_thread
def _add_to_local_node(
    hass: HomeAssistant,
    filename: str,
    pin: bool,
    path: str,
    last_file_name: tp.Optional[str] = None,
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
    """function add file to local IPFS client

    :param filename: file with data
    :param pin: should save previous pin or not
    :param path: path to folder where to store file
    :param last_file_name: name of file, which should be unpin(if needed)

    :return: IPFS hash of the file and file size in IPFS
    """

    try:
        _LOGGER.debug(f"Start adding {filename} to local node, pin: {pin}")
        with ipfshttpclient2.connect() as client:
            result = client.add(filename, pin=False)
            ipfs_hash: tp.Optional[str] = result["Hash"]
            ipfs_file_size: tp.Optional[int] = int(result["Size"])
            _LOGGER.debug(f"File {filename} was added to local node with cid: {ipfs_hash}")
            filename = filename.split("/")[-1]
            client.files.cp(f"/ipfs/{ipfs_hash}", f"{path}/{filename}")
            if not pin:
                if last_file_name is not None:
                    client.files.rm(f"{path}/{last_file_name}")
                    _LOGGER.debug(f"File {last_file_name} with was unpinned")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    except Exception as e:
        _LOGGER.error(f"Exception in add to local node: {e}")
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
        ipfs_hash = None
        ipfs_file_size = None
    return ipfs_hash, ipfs_file_size


@to_thread
def _add_to_pinata(
    hass: HomeAssistant,
    filename: str,
    pinata: PinataPy,
    pin: bool,
    last_file_hash: tp.Optional[str] = None,
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
    """Add file to Pinata service

    :param hass:  Home Assistant instance
    :param filename: file with data
    :param pinata: pinata client object
    :param pin: should save previous pin or not
    :param last_file_hash: hash of file, which should be unpinned(if needed)

    :return: IPFS hash of the file and file size in IPFS
    """

    _LOGGER.debug(f"Start adding {filename} to Pinata, pin: {pin}")
    try:
        RES = None
        res = pinata.pin_file_to_ipfs(filename, save_absolute_paths=False)
        ipfs_hash: tp.Optional[str] = res["IpfsHash"]
        ipfs_file_size: tp.Optional[int] = int(res["PinSize"])
        _LOGGER.debug(f"File {filename} was added to Pinata with cid: {ipfs_hash}")
    except Exception as e:
        _LOGGER.error(f"Exception in pinata pin: {e}, pinata response: {res}")
        ipfs_hash = None
        ipfs_file_size = None
        return ipfs_hash, ipfs_file_size
    if not pin:
        try:
            pinata.remove_pin_from_ipfs(last_file_hash)
            _LOGGER.debug(f"CID {last_file_hash} was unpinned from Pinata")
            hass.data[DOMAIN][PINATA] = PinataPy(
                hass.data[DOMAIN][CONF_PINATA_PUB],
                hass.data[DOMAIN][CONF_PINATA_SECRET],
            )
        except Exception as e:
            _LOGGER.warning(f"Exception in unpinning file from Pinata: {e}")
    return ipfs_hash, ipfs_file_size


@to_thread
def _add_to_custom_gateway(
    filename: str,
    url: str,
    port: int,
    pin: bool,
    seed: str = None,
    last_file_hash: tp.Optional[str] = None,
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
    """function sent file to provided custom IPFS gateway

    :param filename: file with data
    :param url: URL of IPFS public gateway
    :param port: port number of gateway
    :param pin: should save previous pin or not
    :param seed: seed of web3 account. Required if the gateway have web3 authorization
    :param last_file_hash: hash of file, which should be unpin(if needed)

    :return: IPFS hash of the file and file size in IPFS
    """

    if "https://" in url:
        url = url[8:]
    if url[-1] == "/":
        url = url[:-1]
    _LOGGER.debug(f"Start adding {filename} to {url}, pin: {pin}, auth: {bool(seed)}")
    try:
        if seed is not None:
            usr, pwd = web_3_auth(seed)
            with ipfshttpclient2.connect(addr=f"/dns4/{url}/tcp/{port}/https", auth=(usr, pwd)) as client:
                result = client.add(filename)
                if type(result) == list:
                    result = result[-1]
                ipfs_hash: tp.Optional[str] = result["Hash"]
                ipfs_file_size: tp.Optional[int] = int(result["Size"])
                _LOGGER.debug(f"File {filename} was added to {url} with cid: {ipfs_hash}")
        else:
            with ipfshttpclient2.connect(addr=f"/dns4/{url}/tcp/{port}/https") as client:
                result = client.add(filename)
                if type(result) == list:
                    result = result[-1]
                ipfs_hash: tp.Optional[str] = result["Hash"]
                ipfs_file_size: tp.Optional[int] = int(result["Size"])
                _LOGGER.debug(f"File {filename} was added to {url} with cid: {ipfs_hash}")
        if not pin:
            if seed is not None:
                usr, pwd = web_3_auth(seed)
                with ipfshttpclient2.connect(addr=f"/dns4/{url}/tcp/{port}/https", auth=(usr, pwd)) as client:
                    client.pin.rm(last_file_hash)
                    _LOGGER.debug(f"Hash {last_file_hash} was unpinned from {url}")
            else:
                with ipfshttpclient2.connect(addr=f"/dns4/{url}/tcp/{port}/https") as client:
                    client.pin.rm(last_file_hash)
                    _LOGGER.debug(f"Hash {last_file_hash} was unpinned from {url}")
    except Exception as e:
        _LOGGER.error(f"Exception in pinning to custom gateway: {e}")
        ipfs_hash = None
        ipfs_file_size = None
        return ipfs_hash, ipfs_file_size
    return ipfs_hash, ipfs_file_size


@to_thread
def _upload_to_crust(hass: HomeAssistant, ipfs_hash: str, file_size: int) -> tp.Optional[tp.Tuple[str, str]]:
    """Call extrinsic "Place an order" in Crust network

    :param hass: home Assistant instance
    :param ipfs_hash: IPFS hash of file, which you want to store
    :param file_size: size of file in IPFS in bytes

    :return: result of the extrinsic
    """

    seed: str = hass.data[DOMAIN][CONF_ADMIN_SEED]
    mainnet = Mainnet(seed=seed, crypto_type=KeypairType.ED25519)
    try:
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
        _LOGGER.warning(f"Not enough account balance to store the file in Crust Network")
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

    if hass.data[DOMAIN][PINATA] is not None:
        pinata_hash, pinata_ipfs_file_size = await _add_to_pinata(
            hass, filename, hass.data[DOMAIN][PINATA], pin, last_file_hash
        )
    else:
        pinata_hash = None
    local_hash, local_ipfs_file_size = await _add_to_local_node(hass, filename, pin, path, last_file_name)
    if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
        if hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH]:
            seed = hass.data[DOMAIN][CONF_ADMIN_SEED]
        else:
            seed = None
        custom_hash, custom_ipfs_file_size = await _add_to_custom_gateway(
            filename,
            hass.data[DOMAIN][CONF_IPFS_GATEWAY],
            hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT],
            pin,
            seed,
            last_file_hash,
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


async def _get_request(
    hass: HomeAssistant,
    websession: ClientSession,
    url: str,
) -> tp.Optional[str]:
    """Provide async get request to given IPFS gateway.

    :param hass: Home Assistant instance
    :param websession: aiohttp Client Session
    :param url: URL with IPFS gateway + IPFS hash of file

    :return: Data from IPFS hash or None
    """

    _LOGGER.debug(f"Request to {url}")
    try:
        resp = await websession.get(url)
    except Exception as e:
        _LOGGER.warning(f"Exception - {e} in request to {url}")
        return None
    _LOGGER.debug(f"Response from {url} is {resp.status}")
    if resp.status == 200:
        if hass.data[DOMAIN][HANDLE_IPFS_REQUEST]:
            hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = False
            result = await resp.text()
            return result
        else:
            return None
    else:
        return None


@to_thread
def _get_from_local_node_by_hash(hass: HomeAssistant, ipfs_hash: str) -> tp.Optional[str]:
    try:
        with ipfshttpclient2.connect() as client:
            res = client.cat(ipfs_hash)
            res_str = res.decode()
            _LOGGER.debug(f"Got data {ipfs_hash} from local gateway")
            return res_str
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")
    except Exception as e:
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
        _LOGGER.error(f"Exception in getting file from local node by hash: {e}")


@to_thread
def _check_connection(hass: HomeAssistant) -> bool:
    """Check connection to IPFS local node

    :return: Connected or not
    """

    try:
        with ipfshttpclient2.connect() as client:
            test_hash = client.add_str("Test string")
            _LOGGER.debug(f"Added test string to the local node: {test_hash}")
            time.sleep(0.5)
            files = [fileinfo["Name"] for fileinfo in client.files.ls("/")["Entries"]]
            if "test_file" in files:
                client.files.rm("/test_file")
                _LOGGER.debug(f"Deleted test string from the local node MFS")
            time.sleep(0.5)
            client.files.cp(f"/ipfs/{test_hash}", "/test_file")
            _LOGGER.debug(f"Added test string to the local node MFS")
            time.sleep(0.5)
            client.files.rm("/test_file")
            _LOGGER.debug(f"Deleted test string from the local node MFS")
            time.sleep(0.5)
            res = client.pin.rm(test_hash)
            _LOGGER.debug(f"Unpinned test string from local node with res: {res}")
            time.sleep(0.5)
        _LOGGER.debug("Connected to IPFS local node")
        return True
    except ipfshttpclient2.exceptions.ConnectionError:
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
        _LOGGER.debug("Can't connect to IPFS")
        return False
    except Exception as e:
        hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "Error")
        _LOGGER.error(f"Unexpected error in check ipfs connection: {e}")
        return False
