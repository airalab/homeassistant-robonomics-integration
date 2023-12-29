"""This file contains classes for `sensor` entity that shows IPFS daemon status"""

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up backup buttons"""
    sensor = [IPFSStatusSensor(hass)]
    async_add_entities(sensor)


class IPFSStatusSensor(SensorEntity):
    _attr_name = "IPFS Daemon Status"
    _attr_unique_id = "ipfs_status"

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_press(self) -> None:
        await self.hass.services.async_call(DOMAIN, CREATE_BACKUP_SERVICE)
