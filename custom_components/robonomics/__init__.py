"""
Entry point for integration.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import timedelta
from platform import platform

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.event import async_track_time_interval, TrackStates, async_track_state_change
from homeassistant.helpers.typing import ConfigType
from pinatapy import PinataPy
from robonomicsinterface import Account
from substrateinterface import KeypairType
from homeassistant.components.switch.const import DOMAIN as SWITCH_DOMAIN

_LOGGER = logging.getLogger(__name__)

from .const import (
    CONF_ADMIN_SEED,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
    CONF_IPFS_GATEWAY_PORT,
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_SENDING_TIMEOUT,
    CONF_SUB_OWNER_ADDRESS,
    CREATE_BACKUP_SERVICE,
    DATA_PATH,
    DOMAIN,
    HANDLE_IPFS_REQUEST,
    HANDLE_TIME_CHANGE,
    PINATA,
    PLATFORMS,
    RESTORE_BACKUP_SERVICE,
    ROBONOMICS,
    SAVE_VIDEO_SERVICE,
    TIME_CHANGE_COUNT,
    TIME_CHANGE_UNSUB,
    TWIN_ID,
    GETTING_STATES_QUEUE,
    GETTING_STATES,
    IPFS_CONFIG_PATH,
    IPFS_DAEMON_OK,
    IPFS_STATUS_ENTITY,
    IPFS_DAEMON_STATUS_STATE_CHANGE,
)
from .get_states import get_and_send_data
from .ipfs import create_folders, wait_ipfs_daemon, delete_folder_from_local_node, handle_ipfs_status_change
from .manage_users import manage_users
from .robonomics import Robonomics, get_or_create_twin_id
from .services import restore_from_backup_service_call, save_backup_service_call, save_video


async def init_integration(hass: HomeAssistant) -> None:
    """Compare rws devices with users from Home Assistant

    :param hass: HomeAssistant instance
    """

    try:
        await asyncio.sleep(60)
        track_states = TrackStates(False, set(), SWITCH_DOMAIN)
        # hass.data[DOMAIN][STATE_CHANGE_UNSUB] = async_track_state_change_filtered(
        #     hass, track_states, hass.data[DOMAIN][HANDLE_STATE_CHANGE]
        # )
        start_devices_list = await hass.data[DOMAIN][ROBONOMICS].get_devices_list()
        _LOGGER.debug(f"Start devices list is {start_devices_list}")
        hass.async_create_task(manage_users(hass, ("0", start_devices_list)))
    except Exception as e:
        _LOGGER.error(f"Exception in fist check devices {e}")

    await get_and_send_data(hass)


async def update_listener(hass: HomeAssistant, entry: ConfigEntry):
    """Handle options update. It's called when config updates.

    :param hass: HomeAssistant instance
    :param entry: Data from config
    """
    try:
        _LOGGER.debug("Reconfigure Robonomics Integration")
        _LOGGER.debug(f"HASS.data before: {hass.data[DOMAIN]}")
        _LOGGER.debug(f"entry options before: {entry.options}")
        if CONF_IPFS_GATEWAY in entry.options:
            hass.data[DOMAIN][CONF_IPFS_GATEWAY] = entry.options[CONF_IPFS_GATEWAY]
        hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = entry.options[CONF_IPFS_GATEWAY_AUTH]
        hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT] = entry.options[CONF_IPFS_GATEWAY_PORT]
        hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(minutes=entry.options[CONF_SENDING_TIMEOUT])
        if (CONF_PINATA_PUB in entry.options) and (CONF_PINATA_SECRET in entry.options):
            hass.data[DOMAIN][PINATA] = PinataPy(entry.options[CONF_PINATA_PUB], entry.options[CONF_PINATA_SECRET])
            _LOGGER.debug("Use Pinata to pin files")
        else:
            hass.data[DOMAIN][PINATA] = None
            _LOGGER.debug("Use local node to pin files")
        hass.data[DOMAIN][TIME_CHANGE_UNSUB]()
        hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(
            hass,
            hass.data[DOMAIN][HANDLE_TIME_CHANGE],
            hass.data[DOMAIN][CONF_SENDING_TIMEOUT],
        )
        _LOGGER.debug(f"HASS.data after: {hass.data[DOMAIN]}")
    except Exception as e:
        _LOGGER.error(f"Exception in update_listener: {e}")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Robonomics Integration from a config entry.
    It calls every time integration uploading and after config flow during initial
    setup.

    :param hass: HomeAssistant instance
    :param entry: Data from config

    :return: True after succesfull setting up

    """

    hass.data.setdefault(DOMAIN, {})
    _LOGGER.debug(f"Robonomics user control starting set up")
    conf = entry.data
    if CONF_IPFS_GATEWAY in conf:
        hass.data[DOMAIN][CONF_IPFS_GATEWAY] = conf[CONF_IPFS_GATEWAY]
    hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = conf[CONF_IPFS_GATEWAY_AUTH]
    hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT] = conf[CONF_IPFS_GATEWAY_PORT]
    hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(minutes=conf[CONF_SENDING_TIMEOUT])
    _LOGGER.debug(f"Sending interval: {conf[CONF_SENDING_TIMEOUT]} minutes")
    hass.data[DOMAIN][CONF_ADMIN_SEED] = conf[CONF_ADMIN_SEED]
    hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS] = conf[CONF_SUB_OWNER_ADDRESS]
    hass.data[DOMAIN][GETTING_STATES_QUEUE] = 0
    hass.data[DOMAIN][GETTING_STATES] = False
    hass.data[DOMAIN][IPFS_DAEMON_OK] = True

    sub_admin_acc = Account(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
    _LOGGER.debug(f"sub admin: {sub_admin_acc.get_address()}")
    _LOGGER.debug(f"sub owner: {hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS]}")
    hass.data[DOMAIN][ROBONOMICS]: Robonomics = Robonomics(
        hass,
        hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS],
        hass.data[DOMAIN][CONF_ADMIN_SEED],
    )
    if (CONF_PINATA_PUB in conf) and (CONF_PINATA_SECRET in conf):
        hass.data[DOMAIN][CONF_PINATA_PUB] = conf[CONF_PINATA_PUB]
        hass.data[DOMAIN][CONF_PINATA_SECRET] = conf[CONF_PINATA_SECRET]
        hass.data[DOMAIN][PINATA] = PinataPy(hass.data[DOMAIN][CONF_PINATA_PUB], hass.data[DOMAIN][CONF_PINATA_SECRET])
        _LOGGER.debug("Use Pinata to pin files")
    else:
        hass.data[DOMAIN][PINATA] = None
        _LOGGER.debug("Use local node to pin files")
    data_path = f"{os.path.expanduser('~')}/{DATA_PATH}"
    if os.path.isdir(data_path):
        shutil.rmtree(data_path)

    await wait_ipfs_daemon(hass)
    try:
        await create_folders(hass)
    except Exception as e:
        _LOGGER.error(f"Exception in create ipfs folders: {e}")
        await wait_ipfs_daemon(hass)
    hass.states.async_set(f"{DOMAIN}.{IPFS_STATUS_ENTITY}", "OK")

    hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = False
    entry.async_on_unload(entry.add_update_listener(update_listener))

    hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0

    async def handle_time_changed(event):
        """Callback for time' changing subscription.
        It calls every timeout from config to get and send telemtry.

        :param event: Current date & time
        """

        try:
            if not hass.data[DOMAIN][ROBONOMICS].is_subscription_alive():
                await hass.data[DOMAIN][ROBONOMICS].resubscribe()
            if TWIN_ID not in hass.data[DOMAIN]:
                _LOGGER.debug("There is no twin id. Looking for one...")
                await get_or_create_twin_id(hass)
            time_change_count_in_day = 24 * 60 / (hass.data[DOMAIN][CONF_SENDING_TIMEOUT].seconds / 60)
            hass.data[DOMAIN][TIME_CHANGE_COUNT] += 1
            if hass.data[DOMAIN][TIME_CHANGE_COUNT] >= time_change_count_in_day:
                hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0
                await hass.data[DOMAIN][ROBONOMICS].check_subscription_left_days()
            _LOGGER.debug(f"Time changed: {event}")
            await get_and_send_data(hass)
        except Exception as e:
            _LOGGER.error(f"Exception in handle_time_changed: {e}")

    hass.data[DOMAIN][HANDLE_TIME_CHANGE] = handle_time_changed

    async def ipfs_daemon_state_changed(changed_entity: str, old_state, new_state):
        _LOGGER.debug(f"IPFS Status entity changed state from {old_state} to {new_state}")
        if old_state.state != new_state.state:
            await handle_ipfs_status_change(hass, new_state.state == "OK")

    hass.data[DOMAIN][IPFS_DAEMON_STATUS_STATE_CHANGE] = async_track_state_change(
        hass, f"{DOMAIN}.{IPFS_STATUS_ENTITY}", ipfs_daemon_state_changed
    )

    async def handle_save_backup(call: ServiceCall) -> None:
        """Callback for save_backup_to_robonomics service.
        It creates secure backup, adds to IPFS and updates
        the Digital Twin topic.
        """

        if TWIN_ID not in hass.data[DOMAIN]:
            _LOGGER.debug("There is no twin id. Looking for one...")
            await get_or_create_twin_id(hass)
        await save_backup_service_call(hass, call, sub_admin_acc)

    async def handle_restore_from_backup(call: ServiceCall) -> None:
        """Callback for restore_from_robonomics_backup service.
        It restores configuration file from backup.
        """

        if TWIN_ID not in hass.data[DOMAIN]:
            _LOGGER.debug("There is no twin id. Looking for one...")
            await get_or_create_twin_id(hass)
        await restore_from_backup_service_call(hass, call, sub_admin_acc)

    async def handle_save_video(call: ServiceCall) -> None:
        """Callback for save_video_to_robonomics service"""
        if "entity_id" in call.data:
            target = {"entity_id": call.data["entity_id"]}
        elif "device_id" in call.data:
            target = {"device_id": call.data["device_id"]}
        if "duration" in call.data:
            duration = call.data["duration"]
        else:
            duration = 10
        path = call.data["path"]
        if TWIN_ID not in hass.data[DOMAIN]:
            _LOGGER.debug("There is no twin id. Looking for one...")
            await get_or_create_twin_id(hass)
        await save_video(hass, target, path, duration, sub_admin_acc)

    hass.services.async_register(DOMAIN, SAVE_VIDEO_SERVICE, handle_save_video)
    hass.services.async_register(DOMAIN, CREATE_BACKUP_SERVICE, handle_save_backup)
    hass.services.async_register(DOMAIN, RESTORE_BACKUP_SERVICE, handle_restore_from_backup)

    hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(
        hass,
        hass.data[DOMAIN][HANDLE_TIME_CHANGE],
        hass.data[DOMAIN][CONF_SENDING_TIMEOUT],
    )

    await hass.data[DOMAIN][ROBONOMICS].subscribe()
    await hass.data[DOMAIN][ROBONOMICS].check_subscription_left_days()
    if TWIN_ID not in hass.data[DOMAIN]:
        await get_or_create_twin_id(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    asyncio.ensure_future(init_integration(hass))

    # hass.config_entries.async_setup_platforms(entry, PLATFORMS)
    _LOGGER.debug(f"Robonomics user control successfuly set up")
    return True


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    _LOGGER.debug(f"setup data: {config.get(DOMAIN)}")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.
    It calls during integration's removing.

    :param hass: HomeAssistant instance
    :param entry: Data from config

    :return: True when integration is unloaded
    """

    hass.data[DOMAIN][TIME_CHANGE_UNSUB]()
    hass.data[DOMAIN][ROBONOMICS].subscriber.cancel()
    await delete_folder_from_local_node(hass, IPFS_CONFIG_PATH)
    hass.data.pop(DOMAIN)
    await asyncio.gather(
        *(
            hass.config_entries.async_forward_entry_unload(entry, component)
            for component in PLATFORMS
        )
    )
    _LOGGER.debug(f"Robonomics integration was unloaded")
    return True
            
