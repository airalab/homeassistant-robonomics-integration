"""
Script for getting and sending data from Robonomics Integration.
Method `get_and_send_data` is imported to `__init__.py` to collect data with the configurated 
timeout and send it to Robonomics Network.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
import time
import json
import typing as tp
from copy import deepcopy
from datetime import datetime, timedelta

import homeassistant.util.dt as dt_util
from homeassistant.components.lovelace.const import DOMAIN as LOVELACE_DOMAIN
from homeassistant.components.recorder import get_instance, history
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.service import async_get_all_descriptions
from robonomicsinterface import Account
from substrateinterface import KeypairType

_LOGGER = logging.getLogger(__name__)

from .const import (
    CONF_ADMIN_SEED,
    CONFIG_ENCRYPTED_PREFIX,
    CONFIG_PREFIX,
    DOMAIN,
    IPFS_CONFIG_PATH,
    IPFS_HASH_CONFIG,
    ROBONOMICS,
    TWIN_ID,
    DELETE_ATTRIBUTES,
    IPFS_MEDIA_PATH,
    CONF_SENDING_TIMEOUT,
    GETTING_STATES,
    GETTING_STATES_QUEUE,
    PEER_ID_LOCAL,
    LIBP2P_MULTIADDRESS,
)
from .utils import (
    encrypt_for_devices,
    get_hash,
    delete_temp_file,
    format_libp2p_node_multiaddress,
    write_data_to_temp_file,
    write_file_data,
)
from .ipfs import (
    add_config_to_ipfs,
    add_telemetry_to_ipfs,
    add_media_to_ipfs,
    check_if_hash_in_folder,
    get_last_file_hash,
    read_ipfs_local_file,
)


async def get_and_send_data(hass: HomeAssistant):
    """Collect data from all entities within 24hrs and send its hash to Robonomics Datalog.

    :param hass: HomeAssistant instance
    """

    if TWIN_ID not in hass.data[DOMAIN]:
        _LOGGER.debug("Trying to send data before creating twin id")
        return
    _LOGGER.debug(
        f"Get states request, another getting states: {hass.data[DOMAIN][GETTING_STATES]}"
    )
    if hass.data[DOMAIN][GETTING_STATES]:
        _LOGGER.debug("Another states are sending. Wait...")
        hass.data[DOMAIN][GETTING_STATES_QUEUE] += 1
        on_queue = hass.data[DOMAIN][GETTING_STATES_QUEUE]
        while hass.data[DOMAIN][GETTING_STATES]:
            await asyncio.sleep(5)
            if on_queue > 3:
                _LOGGER.debug(
                    "Another states are sending too long. Start getting states..."
                )
                break
            if on_queue < hass.data[DOMAIN][GETTING_STATES_QUEUE]:
                _LOGGER.debug("Stop waiting to send states")
                return
        hass.data[DOMAIN][GETTING_STATES] = True
        hass.data[DOMAIN][GETTING_STATES_QUEUE] = 0
        await asyncio.sleep(10)
    else:
        hass.data[DOMAIN][GETTING_STATES] = True
        hass.data[DOMAIN][GETTING_STATES_QUEUE] = 0

    try:
        sender_acc = Account(
            seed=hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
        )
        sender_kp = sender_acc.keypair
    except Exception as e:
        _LOGGER.error(f"Exception in create keypair during get and send data: {e}")
    try:
        await _get_dashboard_and_services(hass)
        data = await _get_states(hass)
        data = json.dumps(data)
        _LOGGER.debug("Got states to send datalog")
        devices_list_with_admin = hass.data[DOMAIN][ROBONOMICS].devices_list.copy()
        devices_list_with_admin.append(sender_acc.get_address())
        encrypted_data = encrypt_for_devices(
            str(data), sender_kp, devices_list_with_admin
        )
        await asyncio.sleep(2)
        filename = await hass.async_add_executor_job(write_data_to_temp_file, encrypted_data)
        ipfs_hash = await add_telemetry_to_ipfs(hass, filename)
        delete_temp_file(filename)
        await hass.data[DOMAIN][ROBONOMICS].send_datalog_states(ipfs_hash)
        hass.data[DOMAIN][GETTING_STATES] = False
    except Exception as e:
        _LOGGER.error(f"Exception in get_and_send_data: {e}")


async def get_states_libp2p(hass: HomeAssistant) -> str:
    states_json = await _get_states(hass, False)
    states_string = json.dumps(states_json)
    sender_acc = Account(
        seed=hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
    )
    sender_kp = sender_acc.keypair
    devices_list_with_admin = hass.data[DOMAIN][ROBONOMICS].devices_list.copy()
    devices_list_with_admin.append(sender_acc.get_address())
    encrypted_string = encrypt_for_devices(
        states_string, sender_kp, devices_list_with_admin
    )
    return encrypted_string


def _state_changes_during_period(
    hass: HomeAssistant,
    start: datetime.datetime,
    end: datetime.datetime,
    entity_id: str,
) -> list[State]:
    """Save states of the given entity within 24hrs.

    :param hass: HomeAssistant instance
    :param start: Begin of the period
    :param end: End of the period
    :param entity_id: Id for entity from HomeAssistant

    :return: List of State within 24hrs
    """

    return history.state_changes_during_period(
        hass,
        start,
        end,
        entity_id,
        include_start_time_state=True,
        no_attributes=True,
    ).get(entity_id, [])


async def _get_state_history(
    hass: HomeAssistant, entity_id: str
) -> tp.List[tp.Tuple[str, str]]:
    """Get 24 hours history for the given entity.

    :param hass: HomeAssistant instance
    :param entity_id: Id for entity from HomeAssistant

    :return: List of states with date for the given entity in the last 24hrs
    """

    start = dt_util.utcnow() - timedelta(hours=24)
    end = dt_util.utcnow()
    instance = get_instance(hass)
    states = await instance.async_add_executor_job(
        _state_changes_during_period,
        hass,
        start,
        end,
        entity_id,
    )
    states = states[1:]
    list_states = []
    for state in states:
        list_states.append({"state": state.state, "date": str(state.last_changed)})
    return list_states


async def _get_dashboard_and_services(hass: HomeAssistant) -> None:
    """Getting dashboard's configuration and list of services. If it was changed,
    set new topic in Digital Twin with IPFS hash of new dashboard's configuration.

    :param hass: HomeAssistant instance
    """

    _LOGGER.debug("Start getting info about dashboard and services")
    entity_registry = er.async_get(hass)
    try:
        descriptions = json.loads(json.dumps(await async_get_all_descriptions(hass)))
    except Exception as e:
        _LOGGER.error(f"Exception in getting descriptions: {e}")
    try:
        services_list = {}
        for entity in entity_registry.entities:
            entity_data = entity_registry.async_get(entity)
            platform = entity_data.entity_id.split(".")[0]
            if platform not in services_list and platform in descriptions:
                services_list[platform] = descriptions[platform]
    except Exception as e:
        _LOGGER.error(f"Exception in get services list: {e}")
    try:
        dashboard = hass.data[LOVELACE_DOMAIN]["dashboards"].get(None)
        config_dashboard_real = await dashboard.async_load(False)
        config_dashboard = deepcopy(config_dashboard_real)
    except Exception as e:
        _LOGGER.warning(f"Exception in get dashboard: {e}")
        config_dashboard = None
    if config_dashboard is not None:
        # _LOGGER.debug(f"Config dashboard: {config_dashboard}")
        for view in config_dashboard.get("views", []):
            for card in view["cards"]:
                if "image" in card:
                    _LOGGER.debug(f"Image in config: {card['image']}")
                    image_path = card["image"]
                    if image_path[:6] == "/local":
                        image_path = image_path.replace("/local/", "")
                        filename = f"{hass.config.path()}/www/{image_path}"
                        ipfs_hash_media = await get_hash(filename)
                        card["image"] = ipfs_hash_media
                        if not await check_if_hash_in_folder(
                            hass, ipfs_hash_media, IPFS_MEDIA_PATH
                        ):
                            await add_media_to_ipfs(hass, filename)
    peer_id = hass.data[DOMAIN].get(PEER_ID_LOCAL, "")
    local_libp2p_multiaddress = format_libp2p_node_multiaddress(peer_id)
    libp2p_multiaddress = hass.data[DOMAIN].get(LIBP2P_MULTIADDRESS, []).copy()
    libp2p_multiaddress.append(local_libp2p_multiaddress)
    last_config, _ = await get_last_file_hash(hass, IPFS_CONFIG_PATH, CONFIG_PREFIX)
    last_config_encrypted, _ = await get_last_file_hash(hass, IPFS_CONFIG_PATH, CONFIG_ENCRYPTED_PREFIX)
    current_config = await read_ipfs_local_file(hass, last_config, IPFS_CONFIG_PATH)
    current_config_encrypted = await read_ipfs_local_file(hass, last_config_encrypted, IPFS_CONFIG_PATH)
    if current_config_encrypted is None:
        current_config_devices = []
    else:
        current_config_devices = list(current_config_encrypted.keys())
        current_config_devices.remove("data")
        current_config_devices.sort()
    new_config_devices = hass.data[DOMAIN][
        ROBONOMICS
    ].devices_list.copy()
    sender_acc = Account(
        seed=hass.data[DOMAIN][CONF_ADMIN_SEED],
        crypto_type=KeypairType.ED25519,
    )
    new_config_devices.append(sender_acc.get_address())
    new_config_devices.sort()
    if current_config is None:
        current_config = {}
    try:
        new_config = {
            "services": services_list,
            "dashboard": config_dashboard,
            "twin_id": hass.data[DOMAIN][TWIN_ID],
            "sending_timeout": hass.data[DOMAIN][CONF_SENDING_TIMEOUT].seconds,
            "peer_id": peer_id,
            "libp2p_multiaddress": libp2p_multiaddress,
        }
        if current_config != new_config or IPFS_HASH_CONFIG not in hass.data[DOMAIN] or current_config_devices != new_config_devices:
            if current_config != new_config or current_config_devices != new_config_devices:
                _LOGGER.debug(f"Config was changed: {current_config != new_config}, devices was changed: {current_config_devices != new_config_devices}")
                dirname = tempfile.gettempdir()
                config_filename = f"{dirname}/config-{time.time()}"
                await hass.async_add_executor_job(write_file_data, config_filename, json.dumps(new_config))
                sender_kp = sender_acc.keypair
                encrypted_data = encrypt_for_devices(
                    json.dumps(new_config), sender_kp, new_config_devices
                )
                filename = await hass.async_add_executor_job(write_data_to_temp_file, encrypted_data, True)
                _LOGGER.debug(f"Filename: {filename}")
                hass.data[DOMAIN][IPFS_HASH_CONFIG] = await add_config_to_ipfs(
                    hass, config_filename, filename
                )
                delete_temp_file(config_filename)
                delete_temp_file(filename)
            else:
                _LOGGER.debug("Config wasn't changed")
                _, last_config_hash = await get_last_file_hash(
                    hass, IPFS_CONFIG_PATH, CONFIG_ENCRYPTED_PREFIX
                )
                hass.data[DOMAIN][IPFS_HASH_CONFIG] = last_config_hash
            _LOGGER.debug(
                f"New config IPFS hash: {hass.data[DOMAIN][IPFS_HASH_CONFIG]}"
            )
            await hass.data[DOMAIN][ROBONOMICS].set_config_topic(
                hass.data[DOMAIN][IPFS_HASH_CONFIG], hass.data[DOMAIN][TWIN_ID]
            )
        else:
            await hass.data[DOMAIN][ROBONOMICS].set_config_topic(
                hass.data[DOMAIN][IPFS_HASH_CONFIG], hass.data[DOMAIN][TWIN_ID]
            )
    except Exception as e:
        _LOGGER.error(f"Exception in change config: {e}")


async def _get_states(hass: HomeAssistant, with_history: bool = True) -> tp.Dict[
    str,
    tp.Dict[str, tp.Union[str, tp.Dict[str, tp.Dict[str, tp.Union[str, float]]]]],
]:
    """Get info about all entities within 24hrs

    :param hass: HomeAssistant instance

    :return: Dict with the history within 24hrs
    """

    registry = dr.async_get(hass)
    entity_registry = er.async_get(hass)
    devices_data = {}
    entities_data = {}
    all_data = {}

    for entity in entity_registry.entities:
        entity_data = entity_registry.async_get(entity)
        entity_state = hass.states.get(entity)
        if entity_state is not None:
            units = str(entity_state.attributes.get("unit_of_measurement", "None"))
            entity_attributes = {}
            for attr in entity_state.attributes:
                if attr not in DELETE_ATTRIBUTES:
                    # if attr == "supported_color_modes":
                    #     color_modes = []
                    #     for color_mode in entity_state.attributes[attr]:
                    #         color_modes.append(color_mode.)
                    if isinstance(entity_state.attributes[attr], int) or isinstance(
                        entity_state.attributes[attr], dict
                    ):
                        entity_attributes[attr] = entity_state.attributes[attr]
                    else:
                        entity_attributes[attr] = str(entity_state.attributes[attr])
            entity_info = {
                "units": units,
                "state": str(entity_state.state),
                "attributes": entity_attributes,
            }
            if with_history:
                history = await _get_state_history(hass, entity_data.entity_id)
                entity_info["history"] = history
            if entity_data.device_id is not None:
                if entity_data.device_id not in devices_data:
                    device = registry.async_get(entity_data.device_id)
                    if device is not None:
                        device_name = (
                            str(device.name_by_user)
                            if device.name_by_user is not None
                            else str(device.name)
                        )
                        devices_data[entity_data.device_id] = {
                            "name": device_name,
                            "entities": [entity_data.entity_id],
                            "config_entries": list(device.config_entries),
                            "manufacturer": device.manufacturer,
                            "model": device.model,
                            "via_device": device.via_device_id,
                            "connections": list(device.connections),
                            "suggested_area": device.suggested_area,
                            "area_id": device.area_id,
                        }
                else:
                    devices_data[entity_data.device_id]["entities"].append(
                        entity_data.entity_id
                    )
            entities_data[entity_data.entity_id] = entity_info

    all_data["devices"] = devices_data
    all_data["entities"] = entities_data
    if TWIN_ID in hass.data[DOMAIN]:
        all_data["twin_id"] = hass.data[DOMAIN][TWIN_ID]
    else:
        all_data["twin_id"] = -1
    return all_data
