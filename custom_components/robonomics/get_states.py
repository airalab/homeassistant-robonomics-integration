from __future__ import annotations
from platform import platform

from homeassistant.core import HomeAssistant
from homeassistant.components.recorder import get_instance, history
from homeassistant.components.lovelace.const import DOMAIN as LOVELACE_DOMAIN
from homeassistant.helpers.service import async_get_all_descriptions

from substrateinterface import Keypair, KeypairType
import asyncio
import logging
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from robonomicsinterface import Account
import typing as tp
import time
import os
from datetime import timedelta, datetime

_LOGGER = logging.getLogger(__name__)

from .const import (
    CONF_ADMIN_SEED,
    DOMAIN,
    ROBONOMICS,
    PINATA,
    CONF_ENERGY_SENSORS,
    DATA_CONFIG_PATH,
    DATA_PATH,
    IPFS_HASH_CONFIG,
    TWIN_ID,
)
from .utils import encrypt_message
from .robonomics import Robonomics
from .ipfs import add_to_ipfs, write_data_to_file
import json


def state_changes_during_period(
    hass: HomeAssistant, start: datetime.datetime, end: datetime.datetime, entity_id: str
) -> list[State]:
    return history.state_changes_during_period(
            hass,
            start,
            end,
            entity_id,
            include_start_time_state=True,
            no_attributes=True,
        ).get(entity_id, [])

async def get_state_history(hass: HomeAssistant, entity_id: str) -> tp.List[tp.Tuple[str, str]]:
    """ 
    Get 24 hours history for given entity
    """
    start = datetime.now() - timedelta(hours=24)
    end = datetime.now()
    instance = get_instance(hass)
    states = await instance.async_add_executor_job(
        state_changes_during_period,
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

async def get_dashboard_and_services(hass: HomeAssistant) -> None:
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
            platform = entity_data.entity_id.split('.')[0]
            if platform not in services_list and platform in descriptions:
                services_list[platform] = descriptions[platform]
        dashboard = hass.data[LOVELACE_DOMAIN]['dashboards'].get(None)
        config_dashboard = await dashboard.async_load(False)
    except Exception as e:
        _LOGGER.error(f"Exception in get services and dashboard: {e}")
    data_config_path = f"{os.path.expanduser('~')}/{DATA_CONFIG_PATH}"
    try:
        with open(f"{data_config_path}/config", "r") as f:
            current_config = json.load(f)
    except Exception as e:
        _LOGGER.error(f"Exception in json load config: {e}")
        current_config = {}
    try:
        new_config = {"services": services_list, "dashboard": config_dashboard, "twin_id": hass.data[DOMAIN][TWIN_ID]}
        if current_config != new_config or IPFS_HASH_CONFIG not in hass.data[DOMAIN]:
            if current_config != new_config:
                _LOGGER.debug("Config was changed")
                with open(f"{data_config_path}/config", "w") as f:
                    json.dump(new_config, f)
                sender_acc = Account(seed=hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
                sender_kp = sender_acc.keypair
                encrypted_data = encrypt_message(str(new_config), sender_kp, sender_kp.public_key)
            else:
                with open(f"{data_config_path}/config_encrypted") as f:
                    encrypted_data = f.read()
            filename = write_data_to_file(encrypted_data, data_config_path, config=True)
            _LOGGER.debug(f"Filename: {filename}")
            hass.data[DOMAIN][IPFS_HASH_CONFIG] = await add_to_ipfs(hass,
                                                                    filename, 
                                                                    pinata=hass.data[DOMAIN][PINATA])
            _LOGGER.debug(f"New config IPFS hash: {hass.data[DOMAIN][IPFS_HASH_CONFIG]}")
            await hass.data[DOMAIN][ROBONOMICS].set_config_topic(hass.data[DOMAIN][IPFS_HASH_CONFIG], hass.data[DOMAIN][TWIN_ID])
    except Exception as e:
        _LOGGER.error(f"Exception in change config: {e}")

async def get_states(hass: HomeAssistant) -> tp.Dict[
    str,
    tp.Dict[str, tp.Union[str, tp.Dict[str, tp.Dict[str, tp.Union[str, float]]]]],
]:
    """
    Get info about all entities with 24 hours history
    """ 
    await get_dashboard_and_services(hass)
    registry = dr.async_get(hass)
    entity_registry = er.async_get(hass)
    devices_data = {}
    data = {}

    for entity in entity_registry.entities:
        entity_data = entity_registry.async_get(entity)
        if entity_data.device_id != None:
            entity_state = hass.states.get(entity)
            if entity_state != None:
                try:
                    units = str(entity_state.attributes.get("unit_of_measurement"))
                except:
                    units = "None"
                history = await get_state_history(hass, entity_data.entity_id)
                entity_info = {
                    "units": units,
                    "state": str(entity_state.state),
                    "history": history
                }
                if entity_data.device_id not in devices_data:
                    device = registry.async_get(entity_data.device_id)
                    device_name = (
                        str(device.name_by_user)
                        if device.name_by_user != None
                        else str(device.name)
                    )
                    devices_data[entity_data.device_id] = {
                        "name": device_name,
                        "entities": {entity_data.entity_id: entity_info},
                    }
                else:
                    devices_data[entity_data.device_id]["entities"][
                        entity_data.entity_id
                    ] = entity_info
    devices_data['twin_id'] = hass.data[DOMAIN][TWIN_ID]
    return devices_data

def clear_files():
    data_path = f"{os.path.expanduser('~')}/{DATA_PATH}"
    files = os.listdir(data_path)
    for datafile in files:
        if datafile[:4] == 'data':
            os.remove(f"{data_path}/{datafile}")

async def get_and_send_data(hass: HomeAssistant):
    try:
        clear_files()
        sender_acc = Account(seed=hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
        sender_kp = sender_acc.keypair
    except Exception as e:
        _LOGGER.error(f"Exception in create keypair during get and senf data: {e}")
    try:
        data_path = f"{os.path.expanduser('~')}/{DATA_PATH}"
        data = await get_states(hass)
        data = json.dumps(data)
        # with open('/home/homeassistant/ha_test_data', 'w') as f:
        #     f.write(data)
        _LOGGER.debug(f"Got states to send datalog")
        encrypted_data = encrypt_message(str(data), sender_kp, sender_kp.public_key)
        await asyncio.sleep(2)
        filename = write_data_to_file(encrypted_data, data_path)
        ipfs_hash = await add_to_ipfs(hass, filename, pinata=hass.data[DOMAIN][PINATA])
        await hass.data[DOMAIN][ROBONOMICS].send_datalog_states(ipfs_hash)
    except Exception as e:
        _LOGGER.error(f"Exception in get_and_send_data: {e}")