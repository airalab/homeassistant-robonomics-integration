from __future__ import annotations
from platform import platform

from homeassistant.core import HomeAssistant

from homeassistant.helpers.aiohttp_client import async_create_clientsession

from substrateinterface import Keypair, KeypairType
import asyncio
import logging
from robonomicsinterface import Account
from robonomicsinterface.utils import ipfs_32_bytes_to_qm_hash
from robonomicsinterface.ipfs_utils import ipfs_get_content, ipfs_upload_content, web_3_auth
import typing as tp
from pinatapy import PinataPy
from ast import literal_eval
import time
import os
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

from .const import (
    MORALIS_GATEWAY,
    IPFS_GATEWAY,
    CONF_ADMIN_SEED,
    DOMAIN,
    ROBONOMICS,
    PINATA,
    IPFS_API,
    LOCAL_GATEWAY,
    HANDLE_LAUNCH,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
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
def add_to_ipfs(
    hass: HomeAssistant,
    filename: str,
    pinata: PinataPy = None
) -> str:
    """
    Create file with data and pin it to IPFS.
    """
    with open(filename) as f:
        data = f.read()
    if pinata is not None:
        try:
            _LOGGER.debug(f"Adding data to Pinata")
            res = pinata.pin_file_to_ipfs(filename)
            if 'IpfsHash' in res:
                pinata_ipfs_hash = res['IpfsHash']
            else:
                pinata_ipfs_hash = None
        except Exception as e:
            _LOGGER.error(f"Exception in pinata: {e}")
            pinata_ipfs_hash = None
    else:
        pinata_ipfs_hash = None
    try:
        _LOGGER.debug(f"Adding data to local gateway")
        ipfs_hash_local, size = ipfs_upload_content(data)
    except Exception as e:
        _LOGGER.error(f"Exception in add data to ipfs with local node: {e}")
        ipfs_hash_local = None

    # Pin to custom gateway
    if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
        try:
            _LOGGER.debug(f"Adding data to {hass.data[DOMAIN][CONF_IPFS_GATEWAY]}")
            if hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH]:
                auth = web_3_auth(hass.data[DOMAIN][CONF_ADMIN_SEED])
                custom_gateway_res, size = ipfs_upload_content(data, gateway=hass.data[DOMAIN][CONF_IPFS_GATEWAY], auth=auth)
            else:
                custom_gateway_res, size = ipfs_upload_content(data, gateway=hass.data[DOMAIN][CONF_IPFS_GATEWAY])
        except Exception as e:
            _LOGGER.error(f"Exception in add ipfs custom gateway: {e}")
            custom_gateway_res = ['error']
    else:
        custom_gateway_res = None
    _LOGGER.debug(f"Data pinned to IPFS with hash: {ipfs_hash_local}, custom gateway hash: {custom_gateway_res}, pinata: {pinata_ipfs_hash}")
    return ipfs_hash_local


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
    hass: HomeAssistant, websession, url: str, sender_address: str, launch: bool
) -> None:
    resp = await websession.get(url)
    _LOGGER.debug(f"Responce from {url} is {resp.status}")
    if resp.status == 200:
        if hass.data[DOMAIN][HANDLE_LAUNCH]:
            hass.data[DOMAIN][HANDLE_LAUNCH] = False
            result = await resp.text()
            if launch:
                _LOGGER.debug(f"Result: {result}")
                run_launch_command(hass, result, sender_address)
                


async def get_ipfs_data(
    hass: HomeAssistant,
    ipfs_hash: str,
    sender_address: str,
    number_of_request: int,
    launch: bool = True,
    gateways: tp.List[str] = [
        LOCAL_GATEWAY,
        IPFS_GATEWAY,
        MORALIS_GATEWAY,
    ],
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
        if CONF_IPFS_GATEWAY in hass.data[DOMAIN]:
            custom_gateway = hass.data[DOMAIN][CONF_IPFS_GATEWAY]
            if custom_gateway is not None:
                if custom_gateway[-1] != "/":
                    custom_gateway += "/"
                if custom_gateway[-5:] != "ipfs/":
                    custom_gateway += "ipfs/"
                url = f"{custom_gateway}{ipfs_hash}"
                tasks.append(asyncio.create_task(get_request(hass, websession, url, sender_address, launch)))
        for gateway in gateways:
            if gateway[-1] != "/":
                gateway += "/"
            url = f"{gateway}{ipfs_hash}"
            tasks.append(
                asyncio.create_task(get_request(hass, websession, url, sender_address, launch))
            )
        for task in tasks:
            await task
    except Exception as e:
        _LOGGER.error(f"Exception in get ipfs: {e}")
        if hass.data[DOMAIN][HANDLE_LAUNCH]:
            await get_ipfs_data(
                hass, ipfs_hash, sender_address, number_of_request + 1, gateways
            )
