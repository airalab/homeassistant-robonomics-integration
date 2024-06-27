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
from crustinterface import Mainnet
from homeassistant.core import HomeAssistant
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
    IPFS_BACKUP_PATH,
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
    CRYPTO_TYPE,
)
from .utils import (
    get_hash,
    to_thread,
    create_notification,
    get_path_in_temp_dir,
    delete_temp_dir,
    path_is_dir,
)
from .ipfs_helpers.decorators import catch_ipfs_errors
from .ipfs_helpers.get_data import GetIPFSData

_LOGGER = logging.getLogger(__name__)


async def pin_file_to_local_node_by_hash(hass: HomeAssistant, ipfs_hash: str) -> None:
    if await _async_hash_pinned(hass, ipfs_hash):
        _LOGGER.debug(f"Hash {ipfs_hash} is already pinned")
        return
    _LOGGER.debug(f"Start pinnig hash {ipfs_hash} to local node")
    await _async_remove_pin_from_local_node_if_exists(
        hass, path=f"/{IPFS_DAPP_FILE_NAME}"
    )
    pinned = await _async_pin_by_hash_to_local_node(
        hass, ipfs_hash, path=f"/{IPFS_DAPP_FILE_NAME}"
    )
    if not pinned:
        path_for_download = get_path_in_temp_dir(IPFS_DAPP_FILE_NAME)
        await download_directory_from_ipfs(hass, ipfs_hash, path_for_download)
        await _add_to_local_node(hass, path_for_download, True, "/")
        await _async_pin_by_hash_to_local_node(hass, ipfs_hash)
        delete_temp_dir(path_for_download)


@to_thread
@catch_ipfs_errors("Exception in pin by hash")
def _async_pin_by_hash_to_local_node(
    hass: HomeAssistant, ipfs_hash: str, path: tp.Optional[str] = None
) -> tp.Optional[bool]:
    _LOGGER.debug(f"Start pinning hash {ipfs_hash} to local node")
    try:
        with ipfshttpclient2.connect(timeout=40) as client:
            if path is not None:
                client.files.cp(f"/ipfs/{ipfs_hash}", path)
            client.pin.add(ipfs_hash)
            _LOGGER.debug(
                f"Hash {ipfs_hash} was pinned to local node with path: {path}"
            )
            return True
    except ipfshttpclient2.exceptions.TimeoutError:
        _LOGGER.debug(f"Can't pin hash {ipfs_hash} to local node by timeout")
        return False


@to_thread
@catch_ipfs_errors("Exception in pin by hash")
def _async_remove_pin_from_local_node_if_exists(
    hass: HomeAssistant,
    ipfs_hash: tp.Optional[str] = None,
    path: tp.Optional[str] = None,
) -> tp.Optional[bool]:
    if (ipfs_hash is None) and (path is None):
        _LOGGER.error("Can't remove pin without path and name")
        return False
    _LOGGER.debug(f"Start removing pin with hash: {ipfs_hash} or path: {path}")
    with ipfshttpclient2.connect() as client:
        if path is not None:
            if _ipfs_file_exists(hass, client, path):
                ipfs_hash = client.files.stat(path).get("Hash")
                recursive = _ipfs_path_is_dir(hass, client, path)
                client.files.rm(path, recursive=recursive)
                _LOGGER.debug(f"Removed {path} from ipfs")
            else:
                _LOGGER.debug(f"Path {path} does not exist")
        if ipfs_hash is not None:
            if _hash_pinned(hass, client, ipfs_hash):
                client.pin.rm(ipfs_hash)
                _LOGGER.debug(f"Removed pin {ipfs_hash} from local node")
                return True
            else:
                _LOGGER.debug(f"Hash {ipfs_hash} is not pinned in local node")
                return False


@catch_ipfs_errors("Exception in check if file exists")
def _ipfs_file_exists(hass: HomeAssistant, client, filename_with_path: str) -> bool:
    try:
        client.files.stat(filename_with_path)
        return True
    except ipfshttpclient2.exceptions.ErrorResponse:
        return False


@catch_ipfs_errors("Exception in check if ipfs path is dir")
def _ipfs_path_is_dir(hass: HomeAssistant, client, filename_with_path: str) -> bool:
    if _ipfs_file_exists(hass, client, filename_with_path):
        path_type = client.files.stat(filename_with_path)["Type"]
        return path_type == "directory"
    else:
        return False


@catch_ipfs_errors("Exception in check if hash pinned")
def _hash_pinned(hass: HomeAssistant, client, ipfs_hash: str) -> bool:
    pins = client.pin.ls()
    pinned_hashes = list(pins["Keys"].keys())
    return ipfs_hash in pinned_hashes


@to_thread
@catch_ipfs_errors("Exception in check if hash pinned async")
def _async_hash_pinned(hass: HomeAssistant, ipfs_hash: str) -> bool:
    with ipfshttpclient2.connect() as client:
        pins = client.pin.ls()
        pinned_hashes = list(pins["Keys"].keys())
        return ipfs_hash in pinned_hashes


@to_thread
def _async_get_files_list(hass: HomeAssistant, path: str = "/") -> tp.List[str]:
    with ipfshttpclient2.connect() as client:
        files_list = _get_files_list(hass, client, path)
    return files_list


@catch_ipfs_errors("Exception in get ipfs files list")
def _get_files_list(hass: HomeAssistant, client, path: str = "/") -> tp.List[str]:
    files_list = client.files.ls(path)["Entries"]
    if files_list is None:
        files_list = []
    item_names = [item["Name"] for item in files_list]
    return item_names


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
        await create_notification(hass, service_data)
        await wait_ipfs_daemon(hass)
    else:
        service_data = {
            "message": "IPFS Daemon now works well.",
            "title": "IPFS OK",
        }
        await create_notification(hass, service_data)


async def wait_ipfs_daemon(hass: HomeAssistant) -> None:
    if hass.data[DOMAIN][WAIT_IPFS_DAEMON]:
        return
    hass.data[DOMAIN][WAIT_IPFS_DAEMON] = True
    _LOGGER.debug("Wait for IPFS local node connection...")
    connected = await hass.async_add_executor_job(_check_connection, hass)
    while not connected:
        await asyncio.sleep(10)
        connected = await hass.async_add_executor_job(_check_connection, hass)
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

    pin = await _check_save_previous_pin(hass, filename)
    if pin is None:
        pin = True
    if not pin:
        last_file_info = await get_last_file_hash(hass, IPFS_TELEMETRY_PATH)
        if last_file_info is None:
            last_file_info = (None, None)
        last_file_name, last_file_hash = last_file_info[0], last_file_info[1]
    else:
        last_file_hash = None
        last_file_name = None
    ipfs_hash, size = await _add_to_ipfs(
        hass, filename, IPFS_TELEMETRY_PATH, pin, last_file_hash, last_file_name
    )
    await _upload_to_crust(hass, ipfs_hash, size)

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

    last_file_info = await get_last_file_hash(
        hass, IPFS_CONFIG_PATH, prefix=CONFIG_PREFIX
    )
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_name, last_file_hash = last_file_info[0], last_file_info[1]

    last_file_info = await get_last_file_hash(
        hass, IPFS_CONFIG_PATH, prefix=CONFIG_ENCRYPTED_PREFIX
    )
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_encrypted_name, last_file_encrypted_hash = (
        last_file_info[0],
        last_file_info[1],
    )

    new_hash = await get_hash(filename)
    if new_hash == last_file_hash:
        _LOGGER.debug(
            f"Last config hash and the current are the same: {last_file_hash}"
        )
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


async def add_backup_to_ipfs(
    hass: HomeAssistant, filename: str, filename_encrypted: str
) -> tp.Optional[str]:
    """Send backup file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with full Home Assistant backup
    :param filename_encrypted: encrypted file with full Home Assistant backup

    :return: IPFS hash of the file
    """

    last_file_info = await get_last_file_hash(
        hass, IPFS_BACKUP_PATH, prefix=BACKUP_PREFIX
    )
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_name, last_file_hash = last_file_info[0], last_file_info[1]

    last_file_info = await get_last_file_hash(
        hass, IPFS_BACKUP_PATH, prefix=BACKUP_ENCRYPTED_PREFIX
    )
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_encrypted_name, last_file_encrypted_hash = (
        last_file_info[0],
        last_file_info[1],
    )

    new_hash = await get_hash(filename)
    if new_hash == last_file_hash:
        _LOGGER.debug(
            f"Last backup hash and the current are the same: {last_file_hash}"
        )
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

    ipfs_hash, size = await _add_to_ipfs(
        hass, filename, IPFS_MEDIA_PATH, True, None, None
    )
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


async def add_user_info_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """Send user info encrypted file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with media.

    :return: IPFS hash of the file
    """

    address = filename.split("/")[-1]
    last_file_info = await get_last_file_hash(hass, IPFS_USERS_PATH, prefix=address)
    if last_file_info is None:
        last_file_info = (None, None)
    last_file_name, last_file_hash = last_file_info[0], last_file_info[1]

    ipfs_hash, size = await _add_to_ipfs(
        hass, filename, IPFS_USERS_PATH, False, last_file_hash, last_file_name
    )
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


async def get_encrypted_user_info_for_address(
    hass: HomeAssistant, address: str
) -> tp.Optional[str]:
    encrypted_user_info = await read_ipfs_local_file(hass, address, IPFS_USERS_PATH)
    return encrypted_user_info


@to_thread
def delete_folder_from_local_node(hass: HomeAssistant, dirname: str) -> None:
    try:
        _LOGGER.debug(f"Start deleting ipfs folder {dirname}")
        with ipfshttpclient2.connect() as client:
            folders = client.files.ls("/")["Entries"]
            if folders is not None:
                folder_names = [folder["Name"] for folder in folders]
            else:
                folder_names = []
            if dirname[1:] in folder_names:
                client.files.rm(dirname, recursive=True)
                hass.data[DOMAIN][IPFS_STATUS] = "OK"
                hass.states.async_set(
                    f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
                )
                _LOGGER.debug(f"Ipfs folder {dirname} was deleted")
    except Exception as e:
        _LOGGER.error(f"Exception in deleting folder {dirname}: {e}")
        hass.data[DOMAIN][IPFS_STATUS] = "Error"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )


@to_thread
def get_folder_hash(hass: HomeAssistant, ipfs_folder: str) -> str:
    """Get IPFS hash of the given folder in MFS

    :param ipfs_folder: the name of the folder with the path

    :return: IPFS hash of the folder
    """
    try:
        with ipfshttpclient2.connect() as client:
            res = client.files.stat(ipfs_folder)
            hass.data[DOMAIN][IPFS_STATUS] = "OK"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
            return res["Hash"]
    except Exception as e:
        _LOGGER.error(f"Exception in getting folder hash: {e}")
        hass.data[DOMAIN][IPFS_STATUS] = "Error"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )


@to_thread
def create_folders(hass: HomeAssistant) -> None:
    """Function creates IPFS folders to store Robonomics telemetry, configuration and backup files"""
    try:
        with ipfshttpclient2.connect() as client:
            folders = client.files.ls("/")["Entries"]
            if folders is not None:
                folder_names = [folder_info["Name"] for folder_info in folders]
                _LOGGER.debug(f"IPFS folders: {folder_names}")
            else:
                folder_names = []
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
            if IPFS_USERS_PATH[1:] not in folder_names:
                client.files.mkdir(IPFS_USERS_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_USERS_PATH} created")
            hass.data[DOMAIN][IPFS_STATUS] = "OK"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
    except Exception as e:
        _LOGGER.error(f"Exception in creating ipfs folders: {e}")
        hass.data[DOMAIN][IPFS_STATUS] = "Error"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )


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
                hass.data[DOMAIN][IPFS_STATUS] = "OK"
                hass.states.async_set(
                    f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
                )
                if ipfs_hash == stat["Hash"]:
                    return True
            else:
                return False
    except Exception as e:
        _LOGGER.error(f"Exception in check if hash in folder: {e}")
        hass.data[DOMAIN][IPFS_STATUS] = "Error"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )


@to_thread
@catch_ipfs_errors("Exception in get_last_file_hash:")
def get_last_file_hash(
    hass: HomeAssistant, path: str, prefix: str = None
) -> (str, str):
    """function return name and hash of the last telemetry, configuration and backup

    :param path: path to directory with files
    :param prefix: if not None, look for the last file with this prefix

    :return: name of the last file, and file hash
    """
    _LOGGER.debug(f"Getting last file hash from {path} with prefix {prefix}")
    with ipfshttpclient2.connect() as client:
        last_file = None
        last_hash = None
        filenames = _get_files_list(hass, client, path)
        if len(filenames) > 0:
            if prefix is not None:
                for filename in filenames:
                    if filename[: len(prefix)] == prefix:
                        last_file = filename
                        last_hash = client.files.stat(f"{path}/{last_file}")["Hash"]
            else:
                last_file = filenames[-1]
                last_hash = client.files.stat(f"{path}/{last_file}")["Hash"]
        _LOGGER.debug(f"Last {path} file {last_file}, with hash {last_hash}")
        return last_file, last_hash


@to_thread
@catch_ipfs_errors("Exception in reading ipfs local file")
def read_ipfs_local_file(
    hass: HomeAssistant, filename: str, path: str
) -> tp.Union[str, dict]:
    """Read data from file pinned in local node

    :param filename: name of the file
    :param path: path to the file in MFS

    :return: dict with the data in json, string data otherwise
    """

    with ipfshttpclient2.connect() as client:
        _LOGGER.debug(f"Read data from local file: {path}/{filename}")
        if _ipfs_file_exists(hass, client, f"{path}/{filename}"):
            data = client.files.read(f"{path}/{filename}")
            try:
                data_json = json.loads(data)
                return data_json
            except Exception as e:
                _LOGGER.debug(f"Data is not json: {e}")
                data = data.decode("utf-8")
        else:
            _LOGGER.debug(f"File {path}/{filename} does not exist")
            data = None
    return data


@catch_ipfs_errors("Exeption in delete ipfs telemetry files")
def _delete_ipfs_telemetry_files(hass: HomeAssistant):
    """Delete old files from IPFS from local telemetry storage"""

    with ipfshttpclient2.connect() as client:
        files = _get_files_list(hass, client, IPFS_TELEMETRY_PATH)
        num_files_to_delete = len(files) - IPFS_MAX_FILE_NUMBER
        if num_files_to_delete > 0:
            for i in range(num_files_to_delete):
                filename = files[i]
                client.files.rm(f"{IPFS_TELEMETRY_PATH}/{filename}")
                _LOGGER.debug(f"Deleted old telemetry {filename}")
        hass.data[DOMAIN][IPFS_STATUS] = "OK"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )


@to_thread
@catch_ipfs_errors("Exception in check_if_need_pin")
def _check_save_previous_pin(hass: HomeAssistant, filename: str) -> bool:
    """Function checks previous telemetry pins and decide should unpin previous pin or not

    :param filename: file object, with which comparing time from last pin

    :return: True - need to save previous file; False - need to unpin previous file
    """

    with ipfshttpclient2.connect() as client:
        ipfs_files = _get_files_list(hass, client, IPFS_TELEMETRY_PATH)
        if len(ipfs_files) > IPFS_MAX_FILE_NUMBER:
            _delete_ipfs_telemetry_files(hass)
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


@to_thread
@catch_ipfs_errors("Exception in add to local node")
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

    ipfs_hash = None
    ipfs_file_size = None
    _LOGGER.debug(f"Start adding {filename} to local node, pin: {pin}")
    with ipfshttpclient2.connect() as client:
        if not pin:
            if last_file_name is not None:
                is_dir = _ipfs_path_is_dir(hass, client, f"{path}/{last_file_name}")
                client.files.rm(f"{path}/{last_file_name}", recursive=is_dir)
                _LOGGER.debug(f"File {last_file_name} with was unpinned")
        result = client.add(filename, pin=False, recursive=path_is_dir(filename))
        if isinstance(result, list):
            for res in result:
                if "/" not in res["Name"]:
                    result = res
                    break
        ipfs_hash: tp.Optional[str] = result["Hash"]
        ipfs_file_size: tp.Optional[int] = int(result["Size"])
        _LOGGER.debug(f"File {filename} was added to local node with cid: {ipfs_hash}")
        filename = filename.split("/")[-1]
        client.files.cp(f"/ipfs/{ipfs_hash}", f"{path}/{filename}")
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
        res = None
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
            with ipfshttpclient2.connect(
                addr=f"/dns4/{url}/tcp/{port}/https", auth=(usr, pwd)
            ) as client:
                result = client.add(filename)
                if isinstance(result, list):
                    result = result[-1]
                ipfs_hash: tp.Optional[str] = result["Hash"]
                ipfs_file_size: tp.Optional[int] = int(result["Size"])
                _LOGGER.debug(
                    f"File {filename} was added to {url} with cid: {ipfs_hash}"
                )
        else:
            with ipfshttpclient2.connect(
                addr=f"/dns4/{url}/tcp/{port}/https"
            ) as client:
                result = client.add(filename)
                if isinstance(result, list):
                    result = result[-1]
                ipfs_hash: tp.Optional[str] = result["Hash"]
                ipfs_file_size: tp.Optional[int] = int(result["Size"])
                _LOGGER.debug(
                    f"File {filename} was added to {url} with cid: {ipfs_hash}"
                )
        if not pin:
            try:
                if seed is not None:
                    usr, pwd = web_3_auth(seed)
                    with ipfshttpclient2.connect(
                        addr=f"/dns4/{url}/tcp/{port}/https", auth=(usr, pwd)
                    ) as client:
                        client.pin.rm(last_file_hash)
                        _LOGGER.debug(f"Hash {last_file_hash} was unpinned from {url}")
                else:
                    with ipfshttpclient2.connect(
                        addr=f"/dns4/{url}/tcp/{port}/https"
                    ) as client:
                        client.pin.rm(last_file_hash)
                        _LOGGER.debug(f"Hash {last_file_hash} was unpinned from {url}")
            except Exception as e:
                _LOGGER.warning(f"Can't unpin from custom gateway: {e}")
    except Exception as e:
        _LOGGER.error(f"Exception in pinning to custom gateway: {e}")
        ipfs_hash = None
        ipfs_file_size = None
        return ipfs_hash, ipfs_file_size
    return ipfs_hash, ipfs_file_size


@to_thread
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
    mainnet = Mainnet(seed=seed, crypto_type=CRYPTO_TYPE)
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

    if hass.data[DOMAIN][PINATA] is not None:
        added_hash_and_size = await _add_to_pinata(
            hass, filename, hass.data[DOMAIN][PINATA], pin, last_file_hash
        )
        pinata_hash, pinata_ipfs_file_size = (
            (added_hash_and_size[0], added_hash_and_size[1])
            if added_hash_and_size is not None
            else (None, None)
        )
    else:
        pinata_hash = None
    added_hash_and_size = await _add_to_local_node(
        hass, filename, pin, path, last_file_name
    )
    local_hash, local_ipfs_file_size = (
        (added_hash_and_size[0], added_hash_and_size[1])
        if added_hash_and_size is not None
        else (None, None)
    )
    if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
        if hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH]:
            seed = hass.data[DOMAIN][CONF_ADMIN_SEED]
        else:
            seed = None
        added_hash_and_size = await _add_to_custom_gateway(
            filename,
            hass.data[DOMAIN][CONF_IPFS_GATEWAY],
            hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT],
            pin,
            seed,
            last_file_hash,
        )
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


def _check_connection(hass: HomeAssistant) -> bool:
    """Check connection to IPFS local node

    :return: Connected or not
    """

    try:
        with ipfshttpclient2.connect() as client:
            test_hash = client.add_str("Test string")
            _LOGGER.debug(f"Added test string to the local node: {test_hash}")
            time.sleep(0.5)
            files_info = client.files.ls("/")["Entries"]
            if files_info is not None:
                files = [fileinfo["Name"] for fileinfo in files_info]
                if "test_file" in files:
                    client.files.rm("/test_file")
                    _LOGGER.debug("Deleted test string from the local node MFS")
                time.sleep(0.5)
            client.files.cp(f"/ipfs/{test_hash}", "/test_file")
            _LOGGER.debug("Added test string to the local node MFS")
            time.sleep(0.5)
            client.files.rm("/test_file")
            _LOGGER.debug("Deleted test string from the local node MFS")
            time.sleep(0.5)
            res = client.pin.rm(test_hash)
            _LOGGER.debug(f"Unpinned test string from local node with res: {res}")
            time.sleep(0.5)
        _LOGGER.debug("Connected to IPFS local node")
        return True
    except ipfshttpclient2.exceptions.ConnectionError:
        hass.data[DOMAIN][IPFS_STATUS] = "Error"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )
        _LOGGER.debug("Can't connect to IPFS")
        return False
    except Exception as e:
        hass.data[DOMAIN][IPFS_STATUS] = "Error"
        hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
        )
        _LOGGER.error(f"Unexpected error in check ipfs connection: {e}")
        return False
