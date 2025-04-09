"""Provides the CustomGateway class for interacting with IPFS nodes.

The CustomGateway class allows adding and removing files from IPFS nodes
with optional authentication and pinning support.
"""

from contextlib import asynccontextmanager
import logging
from aiofile import AIOFile

import aioipfs
from robonomicsinterface.utils import web_3_auth

from homeassistant.core import HomeAssistant

from ...const import (
    CONF_ADMIN_SEED,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
    CONF_IPFS_GATEWAY_PORT,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

class CustomGateway:
    """Handles interactions with IPFS nodes, including adding and removing files."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the CustomGateway with Home Assistant instance.

        Args:
            hass (HomeAssistant): The Home Assistant instance.

        """
        self.hass = hass
        self.url = self._format_url(hass.data[DOMAIN][CONF_IPFS_GATEWAY])
        self.port = hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT]
        if hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH]:
            self.seed = hass.data[DOMAIN][CONF_ADMIN_SEED]
        else:
            self.seed = None

    async def add(self, filename: str, pin: bool, last_file_hash: str | None = None) -> tuple[str | None, int | None]:
        """Add a file to the IPFS node.

        Args:
            filename (str): The name of the file to add.
            pin (bool): Should save previous pin or not.
            last_file_hash (str | None): The hash of the last file to unpin if needed.

        Returns:
            tuple[str | None, int | None]: The IPFS hash and file size of the added file, or None if unsuccessful.

        """
        if not pin and last_file_hash is not None:
            await self._remove(last_file_hash)
        return await self._add(filename)

    async def _add(self, filename: str) -> tuple[str | None, int | None]:
        ipfs_hash = None
        ipfs_file_size = None
        try:
            async with self._create_client() as client, AIOFile(filename, 'rb') as afp:
                content = await afp.read()
                added = await client.add_bytes(content)
                ipfs_hash = added["Hash"]
                ipfs_file_size = int(added["Size"])
                _LOGGER.debug("File %s was added to custom gateway with cid: %s", filename, ipfs_hash)
        except Exception as e:
            _LOGGER.warning(f"Exception in adding file to custom gateway: {e}")
            return None, None
        return ipfs_hash, ipfs_file_size

    async def _remove(self, ipfs_hash: str) -> None:
        try:
            async with self._create_client() as client:
                await client.pin.rm(ipfs_hash)
        except Exception as e:
            _LOGGER.warning(f"Exception in removing pin from custom gateway: {e}")
            return None

    @asynccontextmanager
    async def _create_client(self):
        if self.seed:
            usr, pwd = web_3_auth(self.seed)
            async with aioipfs.AsyncIPFS(maddr=f"/dns4/{self.url}/tcp/{self.port}/https", auth=aioipfs.BasicAuth(usr, pwd)) as client:
                yield client
        else:
            async with aioipfs.AsyncIPFS(maddr=f"/dns4/{self.url}/tcp/{self.port}/https") as client:
                yield client

    def _format_url(self, url: str) -> str:
        if "https://" in url:
            url = url[8:]
        if url[-1] == "/":
            url = url[:-1]
        return url

