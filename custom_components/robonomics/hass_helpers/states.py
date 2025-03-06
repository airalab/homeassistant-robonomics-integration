from datetime import timedelta
import logging

import homeassistant.util.dt as dt_util
from homeassistant.components.recorder import get_instance, history
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from ..const import (
    DOMAIN,
    TWIN_ID,
    DELETE_ATTRIBUTES,
)

_LOGGER = logging.getLogger(__name__)

class HassStatesHelper:
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._devices_registry = None
        self._entity_registry = None
        self._entities_data: dict = {}
        self._devices_data: dict = {}
        
    async def get_states(self, with_history: bool = True) -> dict:
        self._devices_registry = dr.async_get(self._hass)
        self._entity_registry = er.async_get(self._hass)
        for entity_id in self._entity_registry.entities:
            # _LOGGER.debug(f"Entity: {entity_id}")
            entity_state = self._hass.states.get(entity_id)
            if entity_state is not None:
                entity_info = self._create_entity_info(entity_state)
                if with_history:
                    entity_info["history"] = await self._get_state_history(entity_id)
                self._update_devices_data(entity_id)
                self._entities_data[entity_id] = entity_info
        return self._format_final_data()

    def _create_entity_info(self, entity_state: State) -> dict:
        units = str(entity_state.attributes.get("unit_of_measurement", "None"))
        attributes = self._get_attributes(entity_state)
        entity_info = {
                "units": units,
                "state": str(entity_state.state),
                "attributes": attributes,
            }
        return entity_info

    def _get_attributes(self, entity_state: State) -> dict:
        entity_attributes = {}
        for attr in entity_state.attributes:
            if attr not in DELETE_ATTRIBUTES:
                if isinstance(entity_state.attributes[attr], int) or isinstance(
                    entity_state.attributes[attr], dict
                ):
                    entity_attributes[attr] = entity_state.attributes[attr]
                else:
                    entity_attributes[attr] = str(entity_state.attributes[attr])
        return entity_attributes

    async def _get_state_history(self, entity_id: str) -> list:
        instance = get_instance(self._hass)
        states = await instance.async_add_executor_job(
            self._state_changes_during_period,
            entity_id,
        )
        states = states[1:]
        list_states = []
        for state in states:
            list_states.append({"state": state.state, "date": str(state.last_changed)})
        return list_states

    def _state_changes_during_period(self, entity_id: str,) -> list[State]:
        return history.state_changes_during_period(
            hass = self._hass,
            start_time = dt_util.utcnow() - timedelta(hours=24),
            end_time = dt_util.utcnow(),
            entity_id = entity_id,
            include_start_time_state = True,
            no_attributes = True,
        ).get(entity_id, [])

    def _update_devices_data(self, entity_id: str) -> None:
        entity_data = self._entity_registry.async_get(entity_id)
        if entity_data.device_id is not None:
            if entity_data.device_id not in self._devices_data:
                device = self._devices_registry.async_get(entity_data.device_id)
                if device is not None:
                    device_info = self._create_device_info(device, entity_id)
                    self._devices_data[entity_data.device_id] = device_info
            else:
                self._devices_data[entity_data.device_id]["entities"].append(entity_id)


    def _create_device_info(self, device: dr.DeviceEntry, entity_id: str) -> dict:
        device_name = self._get_device_name(device)
        device_info = {
            "name": device_name,
            "entities": [entity_id],
            "config_entries": list(device.config_entries.copy()),
            "manufacturer": device.manufacturer,
            "model": device.model,
            "via_device": device.via_device_id,
            "connections": list(device.connections.copy()),
            "suggested_area": device.suggested_area,
            "area_id": device.area_id,
        }
        return device_info

    def _get_device_name(self, device: dr.DeviceEntry) -> str:
        if device.name_by_user is not None:
            return str(device.name_by_user)
        else:
            return str(device.name)

    def _format_final_data(self) -> dict:
        all_data = {}
        all_data["devices"] = self._devices_data
        all_data["entities"] = self._entities_data
        if TWIN_ID in self._hass.data[DOMAIN]:
            all_data["twin_id"] = self._hass.data[DOMAIN][TWIN_ID]
        else:
            all_data["twin_id"] = -1
        return all_data