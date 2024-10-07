""""
Entry point for integration.
"""

from __future__ import annotations

import asyncio
import logging
import os
import json
import shutil
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, Event, CoreState, callback
from homeassistant.const import MATCH_ALL, EVENT_HOMEASSISTANT_STARTED
from homeassistant.helpers.event import (
    async_track_time_interval,
    async_track_state_change_event,
    async_track_state_change,
)
from homeassistant.helpers.typing import ConfigType
from pinatapy import PinataPy

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
    IPFS_STATUS,
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
    LIBP2P_UNSUB,
    IPFS_STATUS_ENTITY,
    IPFS_DAEMON_STATUS_STATE_CHANGE,
    HANDLE_LIBP2P_STATE_CHANGED,
    WAIT_IPFS_DAEMON,
    LIBP2P,
    HANDLE_TIME_CHANGE_LIBP2P,
    TIME_CHANGE_LIBP2P_UNSUB,
    CONTROLLER_ADDRESS,
    CONF_CONTROLLER_TYPE,
    TELEMETRY_SENDER,
    CONF_NETWORK,
)
from .ipfs import (
    create_folders,
    wait_ipfs_daemon,
    delete_folder_from_local_node,
    handle_ipfs_status_change,
)
from .manage_users import UserManager
from .robonomics import Robonomics, get_or_create_twin_id
from .services import (
    restore_from_backup_service_call,
    save_backup_service_call,
    save_video,
)
from .libp2p import LibP2P
from .telemetry_helpers import Telemetry
from .hass_helpers import HassStatesHelper


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
        hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = entry.options[
            CONF_IPFS_GATEWAY_AUTH
        ]
        hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT] = entry.options[
            CONF_IPFS_GATEWAY_PORT
        ]
        hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(
            minutes=entry.options[CONF_SENDING_TIMEOUT]
        )
        if (CONF_PINATA_PUB in entry.options) and (CONF_PINATA_SECRET in entry.options):
            hass.data[DOMAIN][PINATA] = PinataPy(
                entry.options[CONF_PINATA_PUB], entry.options[CONF_PINATA_SECRET]
            )
            _LOGGER.debug("Use Pinata to pin files")
        else:
            hass.data[DOMAIN][PINATA] = None
            _LOGGER.debug("Use local node to pin files")
        hass.data[DOMAIN][TELEMETRY_SENDER].setup(hass.data[DOMAIN][CONF_SENDING_TIMEOUT])
        hass.data[DOMAIN][TIME_CHANGE_UNSUB]()
        hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(
            hass,
            hass.data[DOMAIN][HANDLE_TIME_CHANGE],
            hass.data[DOMAIN][CONF_SENDING_TIMEOUT],
        )
        hass.data[DOMAIN][TIME_CHANGE_LIBP2P_UNSUB]()
        hass.data[DOMAIN][TIME_CHANGE_LIBP2P_UNSUB] = async_track_time_interval(
            hass,
            hass.data[DOMAIN][HANDLE_TIME_CHANGE_LIBP2P],
            timedelta(seconds=1),
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
    lock = asyncio.Lock()
    libp2p_message_queue = []
    hass.data.setdefault(DOMAIN, {})

    async def init_integration(_: Event = None) -> None:
        """Compare rws devices with users from Home Assistant

        :param hass: HomeAssistant instance
        """
        _LOGGER.debug(f"hass state: {hass.state}")
        start_devices_list = await hass.data[DOMAIN][ROBONOMICS].get_devices_list()
        _LOGGER.debug(f"Start devices list is {start_devices_list}")
        if DOMAIN not in hass.data:
            return
        try:
            states = await HassStatesHelper(hass).get_states(with_history=False)
            msg = hass.data[DOMAIN][ROBONOMICS].encrypt_for_devices(json.dumps(states))
            await hass.data[DOMAIN][LIBP2P].send_states_to_websocket(msg)
        except Exception as e:
            _LOGGER.error(f"Exception in first send libp2p states {e}")
        try:
            hass.create_task(UserManager(hass).update_users(start_devices_list))
            _LOGGER.debug("Start track state change")
            hass.data[DOMAIN][LIBP2P_UNSUB] = async_track_state_change(
                hass, MATCH_ALL, hass.data[DOMAIN][HANDLE_LIBP2P_STATE_CHANGED]
            )
        except Exception as e:
            _LOGGER.error(f"Exception in first check devices {e}")
        await hass.data[DOMAIN][TELEMETRY_SENDER].send()

        # await get_and_send_data(hass)

    _LOGGER.debug("Robonomics user control starting set up")
    conf = entry.data
    if CONF_IPFS_GATEWAY in conf:
        hass.data[DOMAIN][CONF_IPFS_GATEWAY] = conf[CONF_IPFS_GATEWAY]
    hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = conf[CONF_IPFS_GATEWAY_AUTH]
    hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT] = conf[CONF_IPFS_GATEWAY_PORT]
    hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(
        minutes=conf[CONF_SENDING_TIMEOUT]
    )
    _LOGGER.debug(f"Sending interval: {conf[CONF_SENDING_TIMEOUT]} minutes")
    hass.data[DOMAIN][CONF_ADMIN_SEED] = conf[CONF_ADMIN_SEED]
    hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS] = conf[CONF_SUB_OWNER_ADDRESS]
    hass.data[DOMAIN][GETTING_STATES_QUEUE] = 0
    hass.data[DOMAIN][GETTING_STATES] = False
    hass.data[DOMAIN][IPFS_DAEMON_OK] = True
    hass.data[DOMAIN][WAIT_IPFS_DAEMON] = False

    hass.data[DOMAIN][ROBONOMICS] = Robonomics(
        hass,
        hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS],
        hass.data[DOMAIN][CONF_ADMIN_SEED],
        conf.get(CONF_CONTROLLER_TYPE),
        conf.get(CONF_NETWORK)
    )
    hass.data[DOMAIN][TELEMETRY_SENDER] = Telemetry(hass)
    hass.data[DOMAIN][TELEMETRY_SENDER].setup(hass.data[DOMAIN][CONF_SENDING_TIMEOUT])
    controller_account = hass.data[DOMAIN][ROBONOMICS].controller_account

    hass.data[DOMAIN][CONTROLLER_ADDRESS] = hass.data[DOMAIN][
        ROBONOMICS
    ].controller_address
    _LOGGER.debug(f"Controller: {hass.data[DOMAIN][CONTROLLER_ADDRESS]}")
    _LOGGER.debug(f"Owner: {hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS]}")
    await hass.data[DOMAIN][ROBONOMICS].check_subscription_left_days()
    if (CONF_PINATA_PUB in conf) and (CONF_PINATA_SECRET in conf):
        hass.data[DOMAIN][CONF_PINATA_PUB] = conf[CONF_PINATA_PUB]
        hass.data[DOMAIN][CONF_PINATA_SECRET] = conf[CONF_PINATA_SECRET]
        hass.data[DOMAIN][PINATA] = PinataPy(
            hass.data[DOMAIN][CONF_PINATA_PUB], hass.data[DOMAIN][CONF_PINATA_SECRET]
        )
        _LOGGER.debug("Use Pinata to pin files")
    else:
        hass.data[DOMAIN][PINATA] = None
        _LOGGER.debug("Use local node to pin files")
    hass.data[DOMAIN][IPFS_STATUS] = "OK"
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    data_path = f"{os.path.expanduser('~')}/{DATA_PATH}"
    if os.path.isdir(data_path):
        shutil.rmtree(data_path)

    await wait_ipfs_daemon(hass, timeout = 30)
    try:
        await create_folders(hass)
    except Exception as e:
        _LOGGER.error(f"Exception in create ipfs folders: {e}")
        await wait_ipfs_daemon(hass, timeout = 30)
    hass.states.async_set(
        f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
    )

    hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = False
    entry.async_on_unload(entry.add_update_listener(update_listener))

    hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0

    @callback
    def handle_time_changed_callback(event):
        hass.loop.create_task(handle_time_changed(event))

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
            time_change_count_in_day = (
                24 * 60 / (hass.data[DOMAIN][CONF_SENDING_TIMEOUT].seconds / 60)
            )
            hass.data[DOMAIN][TIME_CHANGE_COUNT] += 1
            if hass.data[DOMAIN][TIME_CHANGE_COUNT] >= time_change_count_in_day:
                hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0
                await hass.data[DOMAIN][ROBONOMICS].check_subscription_left_days()
            _LOGGER.debug(f"Time changed: {event}")
            # await get_and_send_data(hass)
        except Exception as e:
            _LOGGER.error(f"Exception in handle_time_changed: {e}")

    hass.data[DOMAIN][HANDLE_TIME_CHANGE] = handle_time_changed_callback

    @callback
    def libp2p_state_changed(changed_entity: str, old_state, new_state):
        if LIBP2P not in hass.data[DOMAIN]:
            return
        if old_state is None or new_state is None:
            return
        if old_state.state == new_state.state:
            return
        hass.loop.create_task(add_libp2p_states_to_queue(old_state, new_state))

    async def add_libp2p_states_to_queue(old_state, new_state):
        """Callback for state changing listener.
        It calls every timeout from config to get and send telemtry.
        """
        try:
            states = await HassStatesHelper(hass).get_states(with_history=False)
            msg = hass.data[DOMAIN][ROBONOMICS].encrypt_for_devices(json.dumps(states))
            async with lock:
                if len(libp2p_message_queue) == 0:
                    libp2p_message_queue.append(msg)
                else:
                    libp2p_message_queue[0] = msg
        except Exception as e:
            _LOGGER.error(f"Exception in libp2p_state_changed: {e}")

    hass.data[DOMAIN][HANDLE_LIBP2P_STATE_CHANGED] = libp2p_state_changed

    @callback
    def libp2p_time_changed(event):
        hass.loop.create_task(libp2p_send_states_from_queue())

    async def libp2p_send_states_from_queue():
        if len(libp2p_message_queue) > 0:
            async with lock:
                last_message = libp2p_message_queue[0]
                libp2p_message_queue.pop(0)
            await hass.data[DOMAIN][LIBP2P].send_states_to_websocket(last_message)

    hass.data[DOMAIN][HANDLE_TIME_CHANGE_LIBP2P] = libp2p_time_changed

    @callback
    def ipfs_daemon_state_changed(event: Event):
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        _LOGGER.debug(
            f"IPFS Status entity changed state from {old_state} to {new_state}"
        )
        if old_state.state != new_state.state:
            hass.loop.create_task(
                handle_ipfs_status_change(hass, new_state.state == "OK")
            )

    hass.data[DOMAIN][IPFS_DAEMON_STATUS_STATE_CHANGE] = async_track_state_change_event(
        hass, f"sensor.{IPFS_STATUS_ENTITY}", ipfs_daemon_state_changed
    )

    async def handle_save_backup(call: ServiceCall) -> None:
        """Callback for save_backup_to_robonomics service.
        It creates secure backup, adds to IPFS and updates
        the Digital Twin topic.
        """

        if TWIN_ID not in hass.data[DOMAIN]:
            _LOGGER.debug("There is no twin id. Looking for one...")
            await get_or_create_twin_id(hass)
        await save_backup_service_call(hass, call, controller_account)

    async def handle_restore_from_backup(call: ServiceCall) -> None:
        """Callback for restore_from_robonomics_backup service.
        It restores configuration file from backup.
        """

        if TWIN_ID not in hass.data[DOMAIN]:
            _LOGGER.debug("There is no twin id. Looking for one...")
            await get_or_create_twin_id(hass)
        await restore_from_backup_service_call(hass, call, controller_account)

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
        await save_video(hass, target, path, duration, controller_account)

    hass.services.async_register(DOMAIN, SAVE_VIDEO_SERVICE, handle_save_video)
    hass.services.async_register(DOMAIN, CREATE_BACKUP_SERVICE, handle_save_backup)
    hass.services.async_register(
        DOMAIN, RESTORE_BACKUP_SERVICE, handle_restore_from_backup
    )

    hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(
        hass,
        hass.data[DOMAIN][HANDLE_TIME_CHANGE],
        hass.data[DOMAIN][CONF_SENDING_TIMEOUT],
    )

    hass.data[DOMAIN][TIME_CHANGE_LIBP2P_UNSUB] = async_track_time_interval(
        hass,
        hass.data[DOMAIN][HANDLE_TIME_CHANGE_LIBP2P],
        timedelta(seconds=1),
    )

    await hass.data[DOMAIN][ROBONOMICS].subscribe()
    hass.data[DOMAIN][LIBP2P] = LibP2P(hass)
    await hass.data[DOMAIN][LIBP2P].connect_to_websocket()
    if TWIN_ID not in hass.data[DOMAIN]:
        await get_or_create_twin_id(hass)

    asyncio.ensure_future(hass.data[DOMAIN][ROBONOMICS].pin_dapp_to_local_node())
    if hass.state == CoreState.running:
        asyncio.ensure_future(init_integration())
    else:
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, init_integration)

    _LOGGER.debug(
        f"Robonomics user control successfuly set up, hass state: {hass.state}"
    )
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

    hass.data[DOMAIN][TELEMETRY_SENDER].unload()
    hass.data[DOMAIN][TIME_CHANGE_UNSUB]()
    hass.data[DOMAIN][TIME_CHANGE_LIBP2P_UNSUB]()
    await hass.data[DOMAIN][LIBP2P].close_connection()
    if LIBP2P_UNSUB in hass.data[DOMAIN]:
        hass.data[DOMAIN][LIBP2P_UNSUB]()
    hass.data[DOMAIN][ROBONOMICS].subscriber.cancel()
    await delete_folder_from_local_node(hass, IPFS_CONFIG_PATH)
    hass.data.pop(DOMAIN)
    await asyncio.gather(
        *(
            hass.config_entries.async_forward_entry_unload(entry, component)
            for component in PLATFORMS
        )
    )
    _LOGGER.debug("Robonomics integration was unloaded")
    return True
