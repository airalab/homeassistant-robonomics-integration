"""Backup platform for the Google Drive integration."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Coroutine
import logging
from typing import Any

from google_drive_api.exceptions import GoogleDriveApiError

from homeassistant.components.backup import AgentBackup, BackupAgent, BackupAgentError
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import ChunkAsyncStreamIterator
from homeassistant.util import slugify

from .const import DOMAIN
from . import DATA_BACKUP_AGENT_LISTENERS

_LOGGER = logging.getLogger(__name__)


async def async_get_backup_agents(
    hass: HomeAssistant,
    **kwargs: Any,
) -> list[BackupAgent]:
    """Return a list of backup agents."""
    entries = hass.config_entries.async_loaded_entries(DOMAIN)
    return [RobonomicsBackupAgent()]


@callback
def async_register_backup_agents_listener(
    hass: HomeAssistant,
    *,
    listener: Callable[[], None],
    **kwargs: Any,
) -> Callable[[], None]:
    """Register a listener to be called when agents are added or removed.

    :return: A function to unregister the listener.
    """
    hass.data.setdefault(DATA_BACKUP_AGENT_LISTENERS, []).append(listener)

    @callback
    def remove_listener() -> None:
        """Remove the listener."""
        hass.data[DATA_BACKUP_AGENT_LISTENERS].remove(listener)
        if not hass.data[DATA_BACKUP_AGENT_LISTENERS]:
            del hass.data[DATA_BACKUP_AGENT_LISTENERS]

    return remove_listener


class RobonomicsBackupAgent(BackupAgent):
    """Google Drive backup agent."""

    domain = DOMAIN
    name = "Robonomics Backup-Agent"
    unique_id = "robonomics"

    def __init__(self) -> None:
        """Initialize the cloud backup sync agent."""
        super().__init__()
        self.backup_names = {}

    async def async_upload_backup(
        self,
        *,
        open_stream: Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]]],
        backup: AgentBackup,
        **kwargs: Any,
    ) -> None:
        """Upload a backup.

        :param open_stream: A function returning an async iterator that yields bytes.
        :param backup: Metadata about the backup that should be uploaded.
        """
        try:
            _LOGGER.debug("Uploading backup_id: %s", backup.backup_id)
            _LOGGER.debug("Uploading backup: %s", backup.as_dict())
            self.backup_names[backup.backup_id] = backup.as_dict()
        except (GoogleDriveApiError, HomeAssistantError, TimeoutError) as err:
            raise BackupAgentError(f"Failed to upload backup: {err}") from err

    async def async_list_backups(self, **kwargs: Any) -> list[AgentBackup]:
        """List backups."""
        try:
            backups = []
            for backup in self.backup_names.values():
                _LOGGER.debug("Listing backup: %s", backup)
                backups.append(AgentBackup.from_dict(backup))
            return backups
        except (GoogleDriveApiError, HomeAssistantError, TimeoutError) as err:
            raise BackupAgentError(f"Failed to list backups: {err}") from err

    async def async_get_backup(
        self,
        backup_id: str,
        **kwargs: Any,
    ) -> AgentBackup | None:
        """Return a backup."""
        backups = await self.async_list_backups()
        for backup in backups:
            if backup.backup_id == backup_id:
                return backup
        return None

    async def async_download_backup(
        self,
        backup_id: str,
        **kwargs: Any,
    ) -> AsyncIterator[bytes]:
        """Download a backup file.

        :param backup_id: The ID of the backup that was returned in async_list_backups.
        :return: An async iterator that yields bytes.
        """
        _LOGGER.debug("Downloading backup_id: %s", backup_id)
        raise BackupAgentError("Backup not found")

    async def async_delete_backup(
        self,
        backup_id: str,
        **kwargs: Any,
    ) -> None:
        """Delete a backup file.

        :param backup_id: The ID of the backup that was returned in async_list_backups.
        """
        _LOGGER.debug("Deleting backup_id: %s", backup_id)
        try:
            self.backup_names.pop(backup_id, None)
        except (GoogleDriveApiError, HomeAssistantError, TimeoutError) as err:
            raise BackupAgentError(f"Failed to delete backup: {err}") from err
