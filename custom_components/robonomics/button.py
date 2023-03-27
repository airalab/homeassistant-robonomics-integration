from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CREATE_BACKUP_SERVICE, DOMAIN, RESTORE_BACKUP_SERVICE


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up backup buttons"""
    buttons = [CreateBackupButton(hass), RestoreBackupButton(hass)]
    async_add_entities(buttons)


class CreateBackupButton(ButtonEntity):
    _attr_name = "Create Backup"
    _attr_unique_id = "create_backup"

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_press(self) -> None:
        await self.hass.services.async_call(DOMAIN, CREATE_BACKUP_SERVICE)


class RestoreBackupButton(ButtonEntity):
    _attr_name = "Restore from Backup"
    _attr_unique_id = "restore_backup"

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def async_press(self) -> None:
        await self.hass.services.async_call(DOMAIN, RESTORE_BACKUP_SERVICE)
