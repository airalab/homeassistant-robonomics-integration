"""This file contains classes for `sensor` entity that shows IPFS daemon status"""

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, IPFS_STATUS, IPFS_STATUS_ENTITY, SUBSCRIPTION_LEFT_DAYS


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up backup buttons"""
    sensors = [IPFSStatusSensor(hass), SubscriptionLeftDaysSensor(hass)]
    async_add_entities(sensors)


class IPFSStatusSensor(SensorEntity):
    _attr_name = "IPFS Daemon Status"
    _attr_unique_id = IPFS_STATUS_ENTITY

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__()
        self.hass = hass

    @property
    def state(self):
        return self.hass.data[DOMAIN][IPFS_STATUS]

class SubscriptionLeftDaysSensor(SensorEntity):
    _attr_name = "RWS Subscription Left Days"
    _attr_unique_id = SUBSCRIPTION_LEFT_DAYS

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__()
        self.hass = hass

    @property
    def state(self):
        return self.hass.data[DOMAIN][SUBSCRIPTION_LEFT_DAYS]