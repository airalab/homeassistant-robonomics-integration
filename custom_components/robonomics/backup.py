"""Backup platform for the Google Drive integration."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Coroutine
import logging
from typing import Any

from homeassistant.components.backup import AgentBackup, BackupAgent, BackupAgentError
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import ChunkAsyncStreamIterator
from homeassistant.util import slugify
import json

from .const import DOMAIN, ROBONOMICS, TWIN_ID, CONF_PINATA_PUB, CONF_PINATA_SECRET
from . import DATA_BACKUP_AGENT_LISTENERS
from .ipfs_helpers.add_gateways import PinataGateway
from .ipfs_helpers.get_data import GetIPFSData
from .robonomics import Robonomics

_LOGGER = logging.getLogger(__name__)


async def async_get_backup_agents(
    hass: HomeAssistant,
    **kwargs: Any,
) -> list[BackupAgent]:
    """Return a list of backup agents."""
    if hass.data[DOMAIN].get(CONF_PINATA_PUB) and hass.data[DOMAIN].get(CONF_PINATA_SECRET):
        return [RobonomicsBackupAgent(hass)]
    else:
        return []


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

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the cloud backup sync agent."""
        super().__init__()
        self.cached_backups_meta: dict | None = None
        self.last_backup_meta_hash: str | None = None
        self.hass = hass
        self.robonomics: Robonomics = self.hass.data[DOMAIN][ROBONOMICS]

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
            backup_ipfs_hash, _ = await PinataGateway(self.hass).add_from_stream(open_stream, backup.name.replace(" ", "_"))
            _LOGGER.debug("Backup IPFS hash: %s", backup_ipfs_hash)
            old_backup_meta = await self._get_backups_meta()
            _LOGGER.debug("Old backup meta: %s", old_backup_meta)
            old_backup_meta[backup.backup_id] = {"meta": backup.as_dict(), "ipfs_hash": backup_ipfs_hash}
            _LOGGER.debug("New backup meta: %s", old_backup_meta)
            await self._set_new_backup_meta(old_backup_meta)
        except (HomeAssistantError, TimeoutError) as err:
            raise BackupAgentError(f"Failed to upload backup: {err}") from err

    async def async_list_backups(self, **kwargs: Any) -> list[AgentBackup]:
        """List backups."""
        try:
            _LOGGER.debug("Listing backups")
            backups = []
            backups_meta = await self._get_backups_meta()
            for backup in backups_meta.values():
                _LOGGER.debug("Listing backup: %s", backup)
                backups.append(AgentBackup.from_dict(backup["meta"]))
            return backups
        except (HomeAssistantError, TimeoutError) as err:
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
        backup_hash = self.cached_backups_meta.get(backup_id, {}).get("ipfs_hash")
        if backup_hash is None:
            raise BackupAgentError(f"Backup with ID {backup_id} not found.")
        return await GetIPFSData(self.hass, backup_hash).get_file_data_stream()

    async def async_delete_backup(
        self,
        backup_id: str,
        **kwargs: Any,
    ) -> None:
        """Delete a backup file.

        :param backup_id: The ID of the backup that was returned in async_list_backups.
        """
        _LOGGER.debug("Deleting backup_id: %s", backup_id)
        backups_meta = await self._get_backups_meta()
        try:
            backup_data = backups_meta.pop(backup_id, None)
            if backup_data is not None:
                backup_ipfs_hash = backup_data["ipfs_hash"]
                _LOGGER.debug("Deleting backup IPFS hash: %s", backup_ipfs_hash)
                await PinataGateway(self.hass).remove(backup_ipfs_hash)
                await self._set_new_backup_meta(backups_meta)
        except (HomeAssistantError, TimeoutError) as err:
            raise BackupAgentError(f"Failed to delete backup: {err}") from err

    async def _get_backups_meta(self) -> dict:
        """Get backups meta from IPFS."""
        if self.cached_backups_meta is not None:
            return self.cached_backups_meta
        backup_meta_hash = await self.robonomics.get_backup_hash(self.hass.data[DOMAIN][TWIN_ID])
        _LOGGER.debug(f"Backup meta hash: {backup_meta_hash}")
        self.last_backup_meta_hash = backup_meta_hash
        if backup_meta_hash is None:
            return {}
        try:
            backups_meta = await GetIPFSData(self.hass, backup_meta_hash).get_file_data()
            backups_meta = json.loads(backups_meta)
            self.cached_backups_meta = backups_meta
        except Exception as e:
            _LOGGER.error(f"Error getting backups meta: {e}")
            return {}
        return backups_meta

    async def _set_new_backup_meta(self, new_backup_meta: dict) -> None:
        """Set new backup meta."""
        self.cached_backups_meta = new_backup_meta
        if new_backup_meta == {}:
            await PinataGateway(self.hass).remove(self.last_backup_meta_hash)
            await self.robonomics.remove_backup_topic(self.hass.data[DOMAIN][TWIN_ID])
            self.last_backup_meta_hash = None
            return
        new_ipfs_hash = await PinataGateway(self.hass).add_json(new_backup_meta)
        _LOGGER.debug(f"New backup meta IPFS hash: {new_ipfs_hash}")
        await PinataGateway(self.hass).remove(self.last_backup_meta_hash)
        self.last_backup_meta_hash = new_ipfs_hash
        if self.last_backup_meta_hash is not None:
            await self.robonomics.set_backup_topic(
                self.last_backup_meta_hash, self.hass.data[DOMAIN][TWIN_ID]
            )
