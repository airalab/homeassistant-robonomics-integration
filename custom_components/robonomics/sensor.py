"""This file contains classes for `sensor` entity that shows IPFS daemon status"""

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_SUB_OWNER_ADDRESS,
    CONTROLLER_ADDRESS,
    DOMAIN,
    IPFS_STATUS,
    SUBSCRIPTION_LEFT_DAYS,
)

IPFS_STATUS_ENTITY_UNIQUE_ID = "ipfs_status_entity"
SUBSCRIPTION_LEFT_DAYS_ENTITY_UNIQUE_ID = "subscription_left_days_entity"
CONTROLLER_ADDRESS_ENTITY_UNIQUE_ID = "controller_address_entity"
OWNER_ADDRESS_ENTITY_UNIQUE_ID = "owner_address_entity"


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up backup buttons"""
    sensors = [
        IPFSStatusSensor(hass),
        SubscriptionLeftDaysSensor(hass),
        ControllerAddressSensor(hass),
        OwnerAddressSensor(hass),
    ]
    async_add_entities(sensors)


class IPFSStatusSensor(SensorEntity):
    _attr_name = "IPFS Daemon Status"
    _attr_unique_id = IPFS_STATUS_ENTITY_UNIQUE_ID
    # _attr_should_poll = False

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__()
        self.hass = hass

    @property
    def icon(self):
        if self.hass.data[DOMAIN][IPFS_STATUS] == "OK":
            return "mdi:hand-okay"
        else:
            return "mdi:hand-saw"

    @property
    def state(self):
        return self.hass.data[DOMAIN][IPFS_STATUS]


class SubscriptionLeftDaysSensor(SensorEntity):
    _attr_name = "RWS Subscription Left Days"
    _attr_unique_id = SUBSCRIPTION_LEFT_DAYS_ENTITY_UNIQUE_ID

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__()
        self.hass = hass

    @property
    def icon(self):
        return "mdi:calendar-today"

    @property
    def state(self):
        return self.hass.data[DOMAIN][SUBSCRIPTION_LEFT_DAYS]


class ControllerAddressSensor(SensorEntity):
    _attr_name = "Controller Address"
    _attr_unique_id = CONTROLLER_ADDRESS_ENTITY_UNIQUE_ID

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__()
        self.hass = hass

    @property
    def icon(self):
        return "mdi:gamepad-square"

    @property
    def state(self):
        return self.hass.data[DOMAIN][CONTROLLER_ADDRESS]


class OwnerAddressSensor(SensorEntity):
    _attr_name = "Owner Address"
    _attr_unique_id = OWNER_ADDRESS_ENTITY_UNIQUE_ID

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__()
        self.hass = hass

    @property
    def icon(self):
        return "mdi:home-group"

    @property
    def state(self):
        return self.hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS]
