"""
This module contains functions to work with IPFS. It allows to send and receive files from IPFS.

To start work with this module check next functions - add_telemetry_to_ipfs(), add_config_to_ipfs(), add_backup_to_ipfs(),
create_folders() and get_ipfs_data().

write_data_to_file() function is used in "get_states.py" module
"""

from __future__ import annotations

from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.core import HomeAssistant

from substrateinterface import Keypair, KeypairType
from robonomicsinterface.utils import web_3_auth
from crustinterface import Mainnet

from datetime import datetime, timedelta
from pinatapy import PinataPy
from ast import literal_eval
from pathlib import Path
import ipfshttpclient2
import typing as tp
import asyncio
import logging
import time
import json
import os

from .backup_control import restore_from_backup, unpack_backup, get_hash
from .utils import decrypt_message, to_thread

from .const import (
    MORALIS_GATEWAY,
    IPFS_GATEWAY,
    CONF_ADMIN_SEED,
    DOMAIN,
    PINATA,
    LOCAL_GATEWAY,
    HANDLE_LAUNCH,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
    DATA_BACKUP_ENCRYPTED_PATH,
    TWIN_ID,
    MAX_NUMBER_OF_REQUESTS,
    IPFS_TELEMETRY_PATH,
    SECONDS_IN_DAY,
    CONF_IPFS_GATEWAY_PORT,
    IPFS_BACKUP_PATH,
    IPFS_CONFIG_PATH,
    CONF_PINATA_SECRET,
    CONF_PINATA_PUB,
    IPFS_MAX_FILE_NUMBER,
)
from .utils import decrypt_message, to_thread, get_hash
from .backup_control import restore_from_backup, unpack_backup

_LOGGER = logging.getLogger(__name__)


async def add_telemetry_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """
    Send telemetry files to IPFS

    :param hass: Home Assistant instance
    :param filename: file with telemetry
    :return: IPFS hash of file
    """
    pin = await check_if_need_pin_telemetry(filename)
    if not pin:
        last_file_name, last_file_hash = await get_last_file_hash(IPFS_TELEMETRY_PATH)
    else:
        last_file_hash = None
        last_file_name = None
    ipfs_hash, size = await add_to_ipfs(
        hass, filename, IPFS_TELEMETRY_PATH, pin, last_file_hash, last_file_name
    )
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


async def add_config_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """
    Send configuration file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with configuration of Home Assistant dashboard and services
    :return: IPFS hash of file
    """
    last_file_name, last_file_hash = await get_last_file_hash(IPFS_CONFIG_PATH)
    new_hash = await get_hash(filename)
    if new_hash == last_file_hash:
        _LOGGER.debug(f"Last config hash and the current are the same: {last_file_hash}")
        return last_file_hash
    ipfs_hash, size = await add_to_ipfs(
        hass, filename, IPFS_CONFIG_PATH, False, last_file_hash, last_file_name
    )
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


async def add_backup_to_ipfs(hass: HomeAssistant, filename: str) -> tp.Optional[str]:
    """
    Send backup file to IPFS

    :param hass: Home Assistant instance
    :param filename: file with full Home Assistant backup.
    :return: IPFS hash of file
    """
    last_file_name, last_file_hash = await get_last_file_hash(IPFS_BACKUP_PATH)
    new_hash = await get_hash(filename)
    if new_hash == last_file_hash:
        _LOGGER.debug(f"Last backup hash and the current are the same: {last_file_hash}")
        return last_file_hash
    ipfs_hash, size = await add_to_ipfs(
        hass, filename, IPFS_BACKUP_PATH, False, last_file_hash, last_file_name
    )
    await _upload_to_crust(hass, ipfs_hash, size)

    return ipfs_hash


@to_thread
def create_folders() -> None:
    """
    Function creates IPFS folders to store Robonomics telemetry, configuration and backup files
    """
    with ipfshttpclient2.connect() as client:
        try:
            client.files.mkdir(IPFS_TELEMETRY_PATH)
        except ipfshttpclient2.exceptions.ErrorResponse:
            _LOGGER.debug(f"IPFS folder {IPFS_TELEMETRY_PATH} exists")
        except Exception as e:
            _LOGGER.error(f"Exception - {e} in creating ipfs folder {IPFS_TELEMETRY_PATH}")
        try:
            client.files.mkdir(IPFS_BACKUP_PATH)
        except ipfshttpclient2.exceptions.ErrorResponse:
            _LOGGER.debug(f"IPFS folder {IPFS_BACKUP_PATH} exists")
        except Exception as e:
            _LOGGER.error(f"Exception - {e} in creating ipfs folder {IPFS_BACKUP_PATH}")
        try:
            client.files.mkdir(IPFS_CONFIG_PATH)
        except ipfshttpclient2.exceptions.ErrorResponse:
            _LOGGER.debug(f"IPFS folder {IPFS_CONFIG_PATH} exists")
        except Exception as e:
            _LOGGER.error(f"Exception - {e} in creating ipfs folder {IPFS_CONFIG_PATH}")


async def get_ipfs_data(
    hass: HomeAssistant,
    ipfs_hash: str,
    sender_address: str,
    number_of_request: int,
    launch: bool = True,
    telemetry: bool = False,
    gateways: tp.List[str] = [
        LOCAL_GATEWAY,
        IPFS_GATEWAY,
        MORALIS_GATEWAY,
    ],
) -> bool:
    """
    Get data from IPFS
    """
    if number_of_request >= MAX_NUMBER_OF_REQUESTS:
        return False
    websession = async_create_clientsession(hass)
    try:
        tasks = []
        _LOGGER.debug(f"Request to IPFS number {number_of_request}")
        if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
            custom_gateway = hass.data[DOMAIN][CONF_IPFS_GATEWAY]
            if custom_gateway is not None:
                if custom_gateway[-1] != "/":
                    custom_gateway += "/"
                if custom_gateway[-5:] != "ipfs/":
                    custom_gateway += "ipfs/"
                url = f"{custom_gateway}{ipfs_hash}"
                tasks.append(
                    asyncio.create_task(
                        get_request(
                            hass, websession, url, sender_address, launch, telemetry
                        )
                    )
                )
        for gateway in gateways:
            if gateway[-1] != "/":
                gateway += "/"
            url = f"{gateway}{ipfs_hash}"
            tasks.append(
                asyncio.create_task(
                    get_request(
                        hass, websession, url, sender_address, launch, telemetry
                    )
                )
            )
        for task in tasks:
            res = await task
            if res:
                return True
        else:
            if hass.data[DOMAIN][HANDLE_LAUNCH]:
                res = await get_ipfs_data(
                    hass,
                    ipfs_hash,
                    sender_address,
                    number_of_request + 1,
                    launch=launch,
                    telemetry=telemetry,
                    gateways=gateways,
                )
                return res
    except Exception as e:
        _LOGGER.error(f"Exception in get ipfs: {e}")
        if hass.data[DOMAIN][HANDLE_LAUNCH]:
            res = await get_ipfs_data(
                hass,
                ipfs_hash,
                sender_address,
                number_of_request + 1,
                launch=launch,
                telemetry=telemetry,
                gateways=gateways,
            )
            return res


def write_data_to_file(data: str, data_path: str, config: bool = False) -> str:
    """
    Create file and store data in it

    :param data: data, which to be written to the file
    :param data_path: path, where to store file
    :param config:
    :return:
    """
    if config:
        filename = f"{data_path}/config_encrypted-{time.time()}"
    else:
        filename = f"{data_path}/data-{time.time()}"
    with open(filename, "w") as f:
        f.write(data)
    return filename


def delete_ipfs_telemetry_files():
    """
    Delete old files from IPFS
    """
    with ipfshttpclient2.connect() as client:
        files = client.files.ls(IPFS_TELEMETRY_PATH)["Entries"]
        num_files_to_delete = len(files) - IPFS_MAX_FILE_NUMBER
        if num_files_to_delete > 0:
            for i in range(num_files_to_delete):
                filename = files[i]["Name"]
                client.files.rm(f"{IPFS_TELEMETRY_PATH}/{filename}")
                _LOGGER.debug(f"Deleted old telemetry {filename}")


@to_thread
def check_if_need_pin_telemetry(filename: str) -> bool:
    try:
        with ipfshttpclient2.connect() as client:
            files = client.files.ls(IPFS_TELEMETRY_PATH)
            if len(files["Entries"]) > IPFS_MAX_FILE_NUMBER:
                delete_ipfs_telemetry_files()
            if len(files["Entries"]) > 0:
                last_file = files["Entries"][-2]["Name"]
                last_file_time = datetime.fromtimestamp(float(last_file.split("-")[-1]))
                current_file_time = datetime.fromtimestamp(
                    float(filename.split("-")[-1])
                )
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
    except Exception as e:
        _LOGGER.error(f"Exception in check_if_need_pin: {e}")
        return True


@to_thread
def get_last_file_hash(path: str) -> (str, str):
    try:
        with ipfshttpclient2.connect() as client:
            files = client.files.ls(path)
            if len(files["Entries"]) > 0:
                last_file = files["Entries"][-1]["Name"]
                last_hash = client.files.stat(f"{path}/{last_file}")["Hash"]
                _LOGGER.debug(f"Last telemetry file {last_file}, with hash {last_hash}")
                return last_file, last_hash
            else:
                return None, None
    except Exception as e:
        _LOGGER.error(f"Exception in get_last_file_hash: {e}")
        return None, None


@to_thread
def add_to_local_node(
    filename: str,
    pin: bool,
    path: str,
    last_file_name: tp.Optional[str] = None,
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
    try:
        _LOGGER.debug(f"Start adding {filename} to local node, pin: {pin}")
        with ipfshttpclient2.connect() as client:
            result = client.add(filename, pin=False)
            ipfs_hash: tp.Optional[str] = result["Hash"]
            ipfs_file_size: tp.Optional[int] = int(result["Size"])
            result = None
            _LOGGER.debug(
                f"File {filename} was added to local node with cid: {ipfs_hash}"
            )
            filename = filename.split("/")[-1]
            client.files.cp(f"/ipfs/{ipfs_hash}", f"{path}/{filename}")
            if not pin:
                if last_file_name is not None:
                    client.files.rm(f"{path}/{last_file_name}")
                    _LOGGER.debug(
                        f"File {last_file_name} with was unpinned"
                    )
    except Exception as e:
        _LOGGER.error(f"Exception in add to local node: {e}")
        ipfs_hash = None
        ipfs_file_size = None
    return ipfs_hash, ipfs_file_size


@to_thread
def add_to_pinata(
    hass: HomeAssistant,
    filename: str,
    pinata: PinataPy,
    pin: bool,
    last_file_hash: tp.Optional[str] = None,
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
    _LOGGER.debug(f"Start adding {filename} to Pinata, pin: {pin}")
    try:
        res = pinata.pin_file_to_ipfs(filename)
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
                hass.data[DOMAIN][CONF_PINATA_PUB], hass.data[DOMAIN][CONF_PINATA_SECRET]
            )
        except Exception as e:
            _LOGGER.warning(f"Exception in unpinning file from Pinata: {e}")
    return ipfs_hash, ipfs_file_size


@to_thread
def add_to_custom_gateway(
    filename: str,
    url: str,
    port: int,
    pin: bool,
    seed: str = None,
    last_file_hash: tp.Optional[str] = None,
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
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
                ipfs_hash: tp.Optional[str] = result["Hash"]
                ipfs_file_size: tp.Optional[int] = int(result["Size"])
                result = None
                _LOGGER.debug(
                    f"File {filename} was added to {url} with cid: {ipfs_hash}"
                )
        else:
            with ipfshttpclient2.connect(
                addr=f"/dns4/{url}/tcp/{port}/https"
            ) as client:
                result = client.add(filename)
                ipfs_hash: tp.Optional[str] = result["Hash"]
                ipfs_file_size: tp.Optional[int] = int(result["Size"])
                result = None
                _LOGGER.debug(
                    f"File {filename} was added to {url} with cid: {ipfs_hash}"
                )
        if not pin:
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
        _LOGGER.error(f"Exception in pinning to custom gateway: {e}")
        ipfs_hash = None
        ipfs_file_size = None
        return ipfs_hash, ipfs_file_size
    return ipfs_hash, ipfs_file_size


@to_thread
def _upload_to_crust(hass: HomeAssistant, ipfs_hash: str, file_size: int) -> tp.Optional[tp.Tuple[str, str]]:
    """
    Call extrinsic "Place an order" in Crust network

    @param hass: home Assistant instance
    @param ipfs_hash: IPFS hash of file, which you want to store
    @param file_size: size of file in IPFS in bytes
    @return: result of extrinsic
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
        _LOGGER.warning(f"Not enough account balance to store the file")
        return None

    try:
        _LOGGER.debug(f"Start adding {ipfs_hash} to crust with size {file_size}")
        file_stored = mainnet.store_file(ipfs_hash, file_size)
        _LOGGER.debug(f"file stored in Crust. Extrinsic data is  {file_stored}")
    except Exception as e:
        _LOGGER.debug(f"error while uploading file to crust - {e}")
        return None
    return file_stored


async def add_to_ipfs(
    hass: HomeAssistant,
    filename: str,
    path: str,
    pin: bool,
    last_file_hash: tp.Optional[str],
    last_file_name: tp.Optional[str],
) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
    if hass.data[DOMAIN][PINATA] is not None:
        pinata_hash, pinata_ipfs_file_size = await add_to_pinata(
            hass, filename, hass.data[DOMAIN][PINATA], pin, last_file_hash
        )
    else:
        pinata_hash = None
    local_hash, local_ipfs_file_size = await add_to_local_node(
        filename, pin, path, last_file_name
    )
    if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
        if hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH]:
            seed = hass.data[DOMAIN][CONF_ADMIN_SEED]
        else:
            seed = None
        custom_hash, custom_ipfs_file_size = await add_to_custom_gateway(
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


def run_launch_command(
    hass: HomeAssistant, encrypted_command: str, sender_address: str
):
    try:
        if encrypted_command is None:
            _LOGGER.error(f"Can't get command")
            return
    except Exception as e:
        _LOGGER.error(f"Exception in get ipfs command: {e}")
        return
    _LOGGER.debug(f"Got from launch: {encrypted_command}")
    if "platform" in encrypted_command:
        message = literal_eval(encrypted_command)
    else:
        kp_sender = Keypair(
            ss58_address=sender_address, crypto_type=KeypairType.ED25519
        )
        sub_admin_kp = Keypair.create_from_mnemonic(
            hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
        )
        try:
            decrypted = decrypt_message(
                encrypted_command, kp_sender.public_key, sub_admin_kp
            )
        except Exception as e:
            _LOGGER.error(f"Exception in decrypt command: {e}")
            return
        decrypted = str(decrypted)[2:-1]
        _LOGGER.debug(f"Decrypted command: {decrypted}")
        message = literal_eval(decrypted)
    try:
        # domain="light", service="turn_on", service_data={"rgb_color": [30, 30, 230]}, target={"entity_id": "light.shapes_9275"}
        message_entity_id = message["params"]["entity_id"]
        params = message["params"].copy()
        del params["entity_id"]
        if params == {}:
            params = None
        hass.async_create_task(
            hass.services.async_call(
                domain=message["platform"],
                service=message["name"],
                service_data=params,
                target={"entity_id": message_entity_id},
            )
        )
    except Exception as e:
        _LOGGER.error(f"Exception in sending command: {e}")


async def get_request(
    hass: HomeAssistant,
    websession,
    url: str,
    sender_address: str,
    launch: bool,
    telemetry: bool,
) -> None:
    _LOGGER.debug(f"Request to {url}")
    try:
        resp = await websession.get(url)
    except Exception as e:
        _LOGGER.warning(f"Exception in request to {url}")
        return False
    _LOGGER.debug(
        f"Response from {url} is {resp.status}, telemetry: {telemetry}, launch: {launch}"
    )
    if resp.status == 200:
        if hass.data[DOMAIN][HANDLE_LAUNCH]:
            hass.data[DOMAIN][HANDLE_LAUNCH] = False
            result = await resp.text()
            if launch:
                _LOGGER.debug(f"Result: {result}")
                run_launch_command(hass, result, sender_address)
                return True
            elif telemetry:
                try:
                    _LOGGER.debug("Start getting info about telemetry")
                    sub_admin_kp = Keypair.create_from_mnemonic(
                        hass.data[DOMAIN][CONF_ADMIN_SEED],
                        crypto_type=KeypairType.ED25519,
                    )
                    decrypted = decrypt_message(
                        result, sub_admin_kp.public_key, sub_admin_kp
                    )
                    ##############################################
                    decrypted_str = decrypted.decode("utf-8")
                    decrypted_json = json.loads(decrypted_str)
                    _LOGGER.debug(f"Restored twin id is {decrypted_json['twin_id']}")
                    hass.data[DOMAIN][TWIN_ID] = decrypted_json["twin_id"]
                    return True
                except Exception as e:
                    _LOGGER.debug(f"Can't decrypt last telemetry: {e}")
                    return False
            else:
                backup_path = f"{os.path.expanduser('~')}/{DATA_BACKUP_ENCRYPTED_PATH}"
                with open(backup_path, "w") as f:
                    f.write(result)
                sub_admin_kp = Keypair.create_from_mnemonic(
                    hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
                )
                await unpack_backup(hass, Path(backup_path), sub_admin_kp)
                await restore_from_backup(hass, Path(hass.config.path()))
                return True
        else:
            return False
    else:
        return False
