from __future__ import annotations
from platform import platform

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.event import async_track_time_interval

from substrateinterface import Keypair, KeypairType
import asyncio
from pathlib import Path
from homeassistant.config_entries import ConfigEntry
import logging
from robonomicsinterface import Account
from robonomicsinterface.utils import ipfs_32_bytes_to_qm_hash
import typing as tp
from pinatapy import PinataPy
import os
import ipfsApi
import time
import json
from datetime import timedelta
import shutil

_LOGGER = logging.getLogger(__name__)

from .const import (
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_SUB_OWNER_ADDRESS,
    CONF_ADMIN_SEED,
    DOMAIN,
    CONF_SENDING_TIMEOUT,
    ROBONOMICS,
    PINATA,
    IPFS_API,
    HANDLE_TIME_CHANGE,
    TIME_CHANGE_UNSUB,
    CONF_ENERGY_SENSORS,
    HANDLE_LAUNCH,
    DATA_CONFIG_PATH,
    DATA_PATH,
    TWIN_ID,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
)
from .utils import decrypt_message, to_thread
from .robonomics import Robonomics
from .ipfs import get_ipfs_data, add_to_ipfs, write_data_to_file
from .get_states import get_and_send_data
from .manage_users import change_password, manage_users

async def update_listener(hass, entry):
    """
    Handle options update.
    """
    try:
        _LOGGER.debug("Reconfigure Robonomics Integration")
        _LOGGER.debug(f"HASS.data before: {hass.data[DOMAIN]}")
        _LOGGER.debug(f"entry options before: {entry.options}")
        if CONF_IPFS_GATEWAY in entry.options:
            hass.data[DOMAIN][CONF_IPFS_GATEWAY] = entry.options[CONF_IPFS_GATEWAY]
        hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = entry.options[CONF_IPFS_GATEWAY_AUTH]
        hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(minutes=entry.options[CONF_SENDING_TIMEOUT])
        if (CONF_PINATA_PUB in entry.options) and (CONF_PINATA_SECRET in entry.options):
            hass.data[DOMAIN][PINATA] = PinataPy(entry.options[CONF_PINATA_PUB], entry.options[CONF_PINATA_SECRET])
            _LOGGER.debug("Use Pinata to pin files")
        else: 
            hass.data[DOMAIN][PINATA] = None
            _LOGGER.debug("Use local node to pin files")
        hass.data[DOMAIN][TIME_CHANGE_UNSUB]()
        hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(hass, hass.data[DOMAIN][HANDLE_TIME_CHANGE], hass.data[DOMAIN][CONF_SENDING_TIMEOUT])
        _LOGGER.debug(f"HASS.data after: {hass.data[DOMAIN]}")
    except Exception as e:
        _LOGGER.error(f"Exception in update_listener: {e}")

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """
    Set up Robonomics Control from a config entry.
    """
    hass.data.setdefault(DOMAIN, {})
    _LOGGER.debug(f"Robonomics user control starting set up")
    conf = entry.data
    if CONF_IPFS_GATEWAY in conf:
        hass.data[DOMAIN][CONF_IPFS_GATEWAY] = conf[CONF_IPFS_GATEWAY]
    hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = conf[CONF_IPFS_GATEWAY_AUTH]
    hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(minutes=conf[CONF_SENDING_TIMEOUT])
    _LOGGER.debug(f"Sending interval: {conf[CONF_SENDING_TIMEOUT]} minutes")
    hass.data[DOMAIN][CONF_ADMIN_SEED] = conf[CONF_ADMIN_SEED]
    hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS] = conf[CONF_SUB_OWNER_ADDRESS]

    sub_admin_acc = Account(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
    _LOGGER.debug(f"sub admin: {sub_admin_acc.get_address()}")
    _LOGGER.debug(f"sub owner: {hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS]}")
    hass.data[DOMAIN][ROBONOMICS]: Robonomics = Robonomics(
                            hass,
                            hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS],
                            hass.data[DOMAIN][CONF_ADMIN_SEED]
                            )
    if (CONF_PINATA_PUB in conf) and (CONF_PINATA_SECRET in conf):
        hass.data[DOMAIN][PINATA] = PinataPy(conf[CONF_PINATA_PUB], conf[CONF_PINATA_SECRET])
        _LOGGER.debug("Use Pinata to pin files")
    else: 
        hass.data[DOMAIN][PINATA] = None
        _LOGGER.debug("Use local node to pin files")
    data_path = f"{os.path.expanduser('~')}/{DATA_PATH}"
    if not os.path.isdir(data_path):
        os.mkdir(data_path)
    data_config_path = f"{os.path.expanduser('~')}/{DATA_CONFIG_PATH}"
    if not os.path.isdir(data_config_path):
        os.mkdir(data_config_path)
    if not os.path.exists(f"{data_config_path}/config"):
        with open(f"{data_config_path}/config", "w"):
            pass

    hass.data[DOMAIN][HANDLE_LAUNCH] = False
    entry.async_on_unload(entry.add_update_listener(update_listener))

    async def handle_state_changed(event):
        try:
            if (
                    event.data["old_state"] != None
                    and event.data["old_state"].state != "unknown"
                    and event.data["old_state"].state != "unavailable"
                    and event.data["new_state"].state != "unknown"
                    and event.data["new_state"].state != "unavailable"
                    and event.data["entity_id"].split(".")[0] != "sensor"
                    and event.data["old_state"].state != event.data["new_state"].state
                ):
                _LOGGER.debug(f"State changed: {event.data}")
                await get_and_send_data(hass)
        except Exception as e:
            _LOGGER.error(f"Exception in handle_state_changed: {e}")


    async def handle_time_changed(event):
        try:
            _LOGGER.debug(f"Time changed: {event}")
            await get_and_send_data(hass)
        except Exception as e:
            _LOGGER.error(f"Exception in handle_time_changed: {e}")
    
    hass.data[DOMAIN][HANDLE_TIME_CHANGE] = handle_time_changed

    #hass.bus.async_listen("state_changed", handle_state_changed)
    hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(hass, hass.data[DOMAIN][HANDLE_TIME_CHANGE], hass.data[DOMAIN][CONF_SENDING_TIMEOUT])
    asyncio.ensure_future(hass.data[DOMAIN][ROBONOMICS].subscribe())

    if TWIN_ID not in hass.data[DOMAIN]:
        try:
            with open(f"{data_config_path}/config", "r") as f:
                current_config = json.load(f)
                _LOGGER.debug(f"Current twin id is {current_config['twin_id']}")
                hass.data[DOMAIN][TWIN_ID] = current_config["twin_id"]
        except Exception as e:
            _LOGGER.debug(f"Can't load config: {e}")
            hass.data[DOMAIN][TWIN_ID] = await hass.data[DOMAIN][ROBONOMICS].create_digital_twin()
            _LOGGER.debug(f"New twin id is {hass.data[DOMAIN][TWIN_ID]}")
 
    hass.states.async_set(f"{DOMAIN}.state", "Online")

    #Checking rws devices to user list correlation
    try:
        start_devices_list = hass.data[DOMAIN][ROBONOMICS].get_devices_list()
        _LOGGER.debug(f"Start devices list is {start_devices_list}")
        hass.async_create_task(manage_users(hass, ('0', start_devices_list)))
    except Exception as e:
        print(f"Exception in fist check devices {e}")
    
    await asyncio.sleep(60)
    await get_and_send_data(hass)
    
    # hass.config_entries.async_setup_platforms(entry, PLATFORMS)
    _LOGGER.debug(f"Robonomics user control successfuly set up")
    return True


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    _LOGGER.debug(f"setup data: {config.get(DOMAIN)}")
    return True


# async def async_unload_entry(
#     hass: core.HomeAssistant, entry: config_entries.ConfigEntry
# ) -> bool:
#     """Unload a config entry."""
#     unload_ok = all(
#         await asyncio.gather(
#             *[hass.config_entries.async_forward_entry_unload(entry, platform)]
#         )
#     )
#     # Remove config entry from domain.
#     if unload_ok:
#         hass.data[DOMAIN].pop(entry.entry_id)

#     return unload_ok


# async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
#     """Unload a config entry."""
#     print(f"hass.data: {hass.data}")
#     print(f"entry id: {entry.entry_id}")
#     print(f"hass domain data: {hass.data[DOMAIN][entry.entry_id]}")
#     component: EntityComponent = hass.data[DOMAIN]
#     return await component.async_unload_entry(entry)

# async def async_remove_entry(hass, entry) -> None:
#     """Handle removal of an entry."""
