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
    RWS_DAYS_LEFT_NOTIFY,
    TIME_CHANGE_COUNT,
    DATA_BACKUP_PATH,
)
from .utils import decrypt_message, to_thread
from .robonomics import Robonomics, check_subscription_left_days
from .ipfs import get_ipfs_data, add_to_ipfs, write_data_to_file
from .get_states import get_and_send_data
from .manage_users import change_password, manage_users
from .backup_control import restore_from_backup, create_secure_backup, unpack_backup, check_backup_change

async def init_integration(hass: HomeAssistant, data_config_path: str,) -> None:
    sub_admin_acc = Account(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
    await check_subscription_left_days(hass)
    if TWIN_ID not in hass.data[DOMAIN]:
        try:
            with open(f"{data_config_path}/config", "r") as f:
                current_config = json.load(f)
                _LOGGER.debug(f"Current twin id is {current_config['twin_id']}")
                hass.data[DOMAIN][TWIN_ID] = current_config["twin_id"]
        except Exception as e:
            _LOGGER.debug(f"Can't load config: {e}")
            last_telemetry_hash = await hass.data[DOMAIN][ROBONOMICS].get_last_telemetry_hash()
            if last_telemetry_hash is not None:
                hass.data[DOMAIN][HANDLE_LAUNCH] = True
                await get_ipfs_data(hass, last_telemetry_hash, sub_admin_acc.get_address(), 0, launch=False, telemetry=True)
                while hass.data[DOMAIN][HANDLE_LAUNCH]:
                    await asyncio.sleep(0.5)
                    pass
                await asyncio.sleep(0.5)
                if TWIN_ID not in hass.data[DOMAIN]:
                    hass.data[DOMAIN][TWIN_ID] = await hass.data[DOMAIN][ROBONOMICS].create_digital_twin()
                    _LOGGER.debug(f"New twin id is {hass.data[DOMAIN][TWIN_ID]}")
                else:
                    _LOGGER.debug(f"Got twin id from telemetry: {hass.data[DOMAIN][TWIN_ID]}")
            else:
                hass.data[DOMAIN][TWIN_ID] = await hass.data[DOMAIN][ROBONOMICS].create_digital_twin()
                _LOGGER.debug(f"New twin id is {hass.data[DOMAIN][TWIN_ID]}")

    #Checking rws devices to user list correlation
    try:
        start_devices_list = hass.data[DOMAIN][ROBONOMICS].get_devices_list()
        _LOGGER.debug(f"Start devices list is {start_devices_list}")
        hass.async_create_task(manage_users(hass, ('0', start_devices_list)))
    except Exception as e:
        print(f"Exception in fist check devices {e}")
    
    await check_backup_change(hass)
    await asyncio.sleep(60)
    await get_and_send_data(hass)

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
    data_backup_path = f"{os.path.expanduser('~')}/{DATA_BACKUP_PATH}"
    if not os.path.isdir(data_backup_path):
        os.mkdir(data_backup_path)

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

    hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0
    async def handle_time_changed(event):
        try:
            time_change_count_in_day = 24*60/(hass.data[DOMAIN][CONF_SENDING_TIMEOUT].seconds/60)
            hass.data[DOMAIN][TIME_CHANGE_COUNT] += 1
            if hass.data[DOMAIN][TIME_CHANGE_COUNT] >= time_change_count_in_day:
                hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0
                await check_subscription_left_days(hass)
            _LOGGER.debug(f"Time changed: {event}")
            await get_and_send_data(hass)
        except Exception as e:
            _LOGGER.error(f"Exception in handle_time_changed: {e}")
    
    hass.data[DOMAIN][HANDLE_TIME_CHANGE] = handle_time_changed

    async def handle_save_backup(call):
        if os.path.isdir(data_backup_path):
            shutil.rmtree(data_backup_path)
            os.mkdir(data_backup_path)
        else:
            os.mkdir(data_backup_path)
        backup_path = await create_secure_backup(hass, Path(hass.config.path()), Path(data_backup_path), admin_keypair=sub_admin_acc.keypair)
        ipfs_hash = await add_to_ipfs(hass, backup_path, pinata=hass.data[DOMAIN][PINATA])
        _LOGGER.debug(f"Backup created on {backup_path} with hash {ipfs_hash}")
        await hass.data[DOMAIN][ROBONOMICS].set_backup_topic(
            ipfs_hash, hass.data[DOMAIN][TWIN_ID]
        )

    async def handle_restore_from_backup(call):
        try:
            config_path = Path(hass.config.path())
            backup_encrypted_path = call.data.get("backup_path")
            hass.states.async_set(f"{DOMAIN}.backup", "Restoring")
            if backup_encrypted_path is None:
                hass.data[DOMAIN][HANDLE_LAUNCH] = True
                _LOGGER.debug("Start looking for backup ipfs hash")
                ipfs_backup_hash = await hass.data[DOMAIN][ROBONOMICS].get_backup_hash(hass.data[DOMAIN][TWIN_ID])
                await get_ipfs_data(hass, ipfs_backup_hash, sub_admin_acc.get_address(), 0, launch=False)
            else:
                backup_path = await unpack_backup(hass, backup_encrypted_path, sub_admin_acc.keypair)
                await restore_from_backup(hass, config_path)
                _LOGGER.debug(f"Config restored, restarting...")
        except Exception as e:
            _LOGGER.error(f"Exception in restore from backup service call: {e}")

    hass.services.async_register(DOMAIN, "save_backup_to_robonomics", handle_save_backup)
    hass.services.async_register(DOMAIN, "restore_from_robonomics_backup", handle_restore_from_backup)

    #hass.bus.async_listen("state_changed", handle_state_changed)
    hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(hass, hass.data[DOMAIN][HANDLE_TIME_CHANGE], hass.data[DOMAIN][CONF_SENDING_TIMEOUT])
    hass.data[DOMAIN][ROBONOMICS].subscribe()

    asyncio.ensure_future(init_integration(hass, data_config_path))
    
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
