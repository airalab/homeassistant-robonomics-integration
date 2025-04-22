"""Provides the LocalGateway class for interacting with IPFS local node.

The LocalGateway class allows adding and removing files from IPFS local node.
"""

import logging

from aiofile import AIOFile
import aioipfs

from homeassistant.core import HomeAssistant

from ..decorators import catch_ipfs_errors_async
from ..utils import IPFSLocalUtils

_LOGGER = logging.getLogger(__name__)

class LocalGateway:
    """Class for interacting with the IPFS local node.

    Provides methods to add, pin, and remove files from the IPFS local node.
    """

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the LocalGateway with a HomeAssistant instance.

        Args:
            hass (HomeAssistant): The HomeAssistant instance.

        """
        self.hass = hass

    @catch_ipfs_errors_async("Exception in add to local node")
    async def add(self, filename: str, path: str, pin: bool, last_file_name: str | None = None) -> tuple[str | None, int | None]:
        """Add a file to the IPFS local node.

        Args:
            filename (str): The name of the file to add.
            path (str): The path where the file should be added in MFS.
            pin (bool): Whether to save previous pin or not.
            last_file_name (str | None): The name of the last file to remove, if applicable.

        Returns:
            tuple[str | None, int | None]: The IPFS hash and file size of the added file.

        """
        async with aioipfs.AsyncIPFS() as client:
            if not pin and last_file_name is not None:
                await self._remove(f"{path}/{last_file_name}", client)
            ipfs_hash, ipfs_file_size = await self._pin(filename, client)
            filename = filename.split("/")[-1]
            await self._add_to_mfs(f"{path}/{filename}", ipfs_hash, client)
        return ipfs_hash, ipfs_file_size

    async def _pin(self, filename: str, client: aioipfs.AsyncIPFS) -> tuple[str | None, int | None]:
        async with AIOFile(filename, 'rb') as afp:
            content = await afp.read()
            added = await client.add_bytes(content)
            ipfs_hash = added["Hash"]
            ipfs_file_size = int(added["Size"])
            _LOGGER.debug("File %s was added to local node with cid: %s", filename, ipfs_hash)
            return ipfs_hash, ipfs_file_size

    async def _add_to_mfs(self, filepath: str, ipfs_hash: str, client: aioipfs.AsyncIPFS) -> None:
        await client.files.cp(f"/ipfs/{ipfs_hash}", filepath)

    async def _remove(self, filepath: str, client: aioipfs.AsyncIPFS) -> None:
        is_dir = await IPFSLocalUtils(self.hass).ipfs_path_is_dir(filepath, client=client)
        await client.files.rm(filepath, recursive=is_dir)
        _LOGGER.debug("File %s was unpinned", filepath)


