from __future__ import annotations
from platform import platform

from homeassistant.core import HomeAssistant

from homeassistant.helpers.aiohttp_client import async_create_clientsession

from substrateinterface import Keypair, KeypairType
import asyncio
import logging
from robonomicsinterface import Account
from robonomicsinterface.utils import ipfs_upload_content
import typing as tp
from pinatapy import PinataPy
from ast import literal_eval
import ipfsApi
import time

_LOGGER = logging.getLogger(__name__)

from .const import (
    MORALIS_GATEWAY,
    IPFS_GATEWAY,
    CONF_ADMIN_SEED,
    DOMAIN,
    ROBONOMICS,
    PINATA,
    IPFS_API,
    CRUST_GATEWAY,
    LOCAL_GATEWAY,
    HANDLE_LAUNCH,
)
from .utils import decrypt_message, to_thread


def write_data_to_file(data: str, data_path: str, config: bool = False) -> str:
    if config:
        filename = f"{data_path}/config_encrypted"
    else:
        filename = f"{data_path}/data{time.time()}"
    with open(filename, "w") as f:
        f.write(data)
    return filename

@to_thread
def add_to_ipfs(hass: HomeAssistant, filename: str, pinata: PinataPy = None, pin_to_crust: bool = True) -> str:
    """
    Create file with data and pin it to IPFS.
    """
    api = hass.data[DOMAIN][IPFS_API]
    if pinata is not None:
        try:
            res = pinata.pin_file_to_ipfs(filename)
            if 'IpfsHash' in res:
                ipfs_hash = res['IpfsHash']
        except Exception as e:
            _LOGGER.error(f"Exception in pinata: {e}")
    _LOGGER.debug(f"IPFS data file: {filename}")
    try:
        res = api.add(filename)
        ipfs_hash_local = res[0]['Hash']
    except Exception as e:
        _LOGGER.error(f"Exception in add data to ipfs witk local node: {e}")
        ipfs_hash_local = None

    # Pin to Crust
    if pin_to_crust:
        with open(filename) as f:
            data = f.read()
        try:
            crust_res = ipfs_upload_content(hass.data[DOMAIN][CONF_ADMIN_SEED], data, pin=True)
        except Exception as e:
            if str(e) == "202":
                _LOGGER.warn(f"202 response from crust")
                crust_res = ['202']
            else:
                _LOGGER.error(f"Exception in add ipfs crust: {e}")
                crust_res = ['error']
    else:
        crust_res = ['not pinned']

    _LOGGER.debug(f"Data pinned to IPFS with hash: {ipfs_hash_local}, crust hash: {crust_res[0]}")
    return ipfs_hash_local

def run_launch_command(hass, HomeAssistant, encrypted_command: str, sender_address: str):
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
        kp_sender = Keypair(ss58_address=sender_address, crypto_type=KeypairType.ED25519)
        sub_admin_kp = Keypair.create_from_mnemonic(
                hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
            )
        try:
            decrypted = decrypt_message(encrypted_command, kp_sender.public_key, sub_admin_kp)
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
                target={"entity_id": message_entity_id}
            )
        )
    except Exception as e:
        _LOGGER.error(f"Exception in sending command: {e}")

async def get_request(hass: HomeAssistant, websession, url: str, sender_address: str) -> None:
    resp = await websession.get(url)
    _LOGGER.debug(f"Responce from {url} is {resp.status}")
    if resp.status == 200:
        if hass.data[DOMAIN][HANDLE_LAUNCH]:
            hass.data[DOMAIN][HANDLE_LAUNCH] = False
            result = await resp.text()
            _LOGGER.debug(f"Result: {result}")
            run_launch_command(hass, result, sender_address)
        
async def get_ipfs_data(
            hass: HomeAssistant, 
            ipfs_hash: str, 
            sender_address: str,
            number_of_request: int,
            gateways: tp.List[str] = [CRUST_GATEWAY, 
                                    LOCAL_GATEWAY,
                                    IPFS_GATEWAY,
                                    MORALIS_GATEWAY]   
            ) -> str:
    """
    Get data from IPFS
    """
    if number_of_request > 4:
        return None
    websession = async_create_clientsession(hass)
    try:
        tasks = []
        _LOGGER.debug(f"Request to IPFS number {number_of_request}")
        for gateway in gateways:
            if gateway[-1] != "/":
                gateway += "/"
            url = f"{gateway}{ipfs_hash}"
            tasks.append(asyncio.create_task(get_request(hass, websession, url, sender_address)))
        for task in tasks:
            await task
    except Exception as e:
        _LOGGER.error(f"Exception in get ipfs: {e}")
        if hass.data[DOMAIN][HANDLE_LAUNCH]:
            await get_ipfs_data(hass, ipfs_hash, sender_address, number_of_request + 1, gateways)