import logging

import aioipfs

from homeassistant.core import HomeAssistant

from .decorators import catch_ipfs_errors_async, ensure_client, set_timeout

_LOGGER = logging.getLogger(__name__)

class IPFSLocalUtils:
    """Utility class for interacting with the IPFS local node."""

    def __init__(self, hass: HomeAssistant):
        self.hass = hass

    @ensure_client
    async def remove_pin(self, ipfs_hash: str | None = None, path: str | None = None, client: aioipfs.AsyncIPFS = None) -> bool:
        """Remove a pin from the IPFS local node if exists.

        Args:
            ipfs_hash (str | None): The IPFS hash of the file to unpin.
            path (str | None): The path of the file in the IPFS file system.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            bool: True if the pin was successfully removed, False otherwise.

        """
        if (ipfs_hash is None) and (path is None):
            _LOGGER.error("Can't remove pin without path and name")
            return False
        _LOGGER.debug(f"Start removing pin with hash: {ipfs_hash} or path: {path}")
        if path is not None:
            if await self.ipfs_file_exists(path, client=client):
                ipfs_file_stat = await client.files.stat(path)
                ipfs_hash = ipfs_file_stat.get("Hash")
                recursive = await self.ipfs_path_is_dir(path, client=client)
                await client.files.rm(path, recursive=recursive)
                _LOGGER.debug(f"Removed {path} from ipfs")
            else:
                _LOGGER.debug(f"Path {path} does not exist")
                return False
        if ipfs_hash is not None:
            if await self.hash_pinned(ipfs_hash, client=client):
                await client.pin.rm(ipfs_hash)
                _LOGGER.debug(f"Removed pin {ipfs_hash} from local node")
            else:
                _LOGGER.debug(f"Hash {ipfs_hash} is not pinned in local node")
                return False
        return True

    @catch_ipfs_errors_async("Exception in pin by hash")
    @ensure_client
    @set_timeout(40)
    async def pin_by_hash(
        self, ipfs_hash: str, path: str | None = None, client: aioipfs.AsyncIPFS = None
    ) -> bool:
        """Pin a file to the IPFS local node by its hash.

        Args:
            ipfs_hash (str): The IPFS hash of the file to pin.
            path (str | None): The optional path in the IPFS file system to pin the file to.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            bool: True if the file was successfully pinned, False otherwise.

        """
        _LOGGER.debug(f"Start pinning hash {ipfs_hash} to local node")
        try:
            if path is not None:
                await client.files.cp(f"/ipfs/{ipfs_hash}", path)
            await client.pin.add(ipfs_hash)
            _LOGGER.debug(
                f"Hash {ipfs_hash} was pinned to local node with path: {path}"
            )
            return True
        except TimeoutError:
            _LOGGER.debug(f"Can't pin hash {ipfs_hash} to local node by timeout")
            return False

    @catch_ipfs_errors_async("Exception in check if file exists")
    @ensure_client
    async def ipfs_file_exists(self, filename_with_path: str, client: aioipfs.AsyncIPFS = None) -> bool:
        """Check if a file exists in the IPFS file system.

        Args:
            filename_with_path (str): The full path of the file in the IPFS file system.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            bool: True if the file exists, False otherwise.

        """
        try:
            await client.files.stat(filename_with_path)
        except aioipfs.exceptions.APIError:
            return False
        else:
            return True

    @catch_ipfs_errors_async("Exception in check if ipfs path is dir")
    @ensure_client
    async def ipfs_path_is_dir(self, filename_with_path: str, client: aioipfs.AsyncIPFS = None) -> bool:
        """Check if the given path in MFS is a directory.

        Args:
            filename_with_path (str): The full path in the IPFS file system.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            bool: True if the path is a directory, False otherwise.

        """
        if await self.ipfs_file_exists(filename_with_path, client=client):
            path_stat = await client.files.stat(filename_with_path)
            path_type = path_stat.get("Type")
            return path_type == "directory"
        return False

    @catch_ipfs_errors_async("Exception in check if hash pinned")
    @ensure_client
    async def hash_pinned(self, ipfs_hash: str, client: aioipfs.AsyncIPFS = None) -> bool:
        """Check if a given IPFS hash is pinned in the local node.

        Args:
            ipfs_hash (str): The IPFS hash to check.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            bool: True if the hash is pinned, False otherwise.

        """
        pins = await client.pin.ls()
        pinned_hashes = list(pins["Keys"].keys())
        return ipfs_hash in pinned_hashes

    @catch_ipfs_errors_async("Exception in get ipfs files list")
    @ensure_client
    async def get_files_list(self, path: str = "/", client: aioipfs.AsyncIPFS = None) -> list[str]:
        """Retrieve a list of file names in the specified MFS path.

        Args:
            path (str): The directory path in the IPFS file system. Defaults to "/".
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            list[str]: A list of file names in the specified directory.

        """
        files_list_res = await client.files.ls(path)
        files_list = files_list_res.get("Entries", []) if files_list_res.get("Entries", []) is not None else []
        return [item["Name"] for item in files_list]

    @catch_ipfs_errors_async("Exception in get_last_file_hash:")
    @ensure_client
    async def get_last_file_hash(
        self, path: str, prefix: str | None = None, client: aioipfs.AsyncIPFS = None
    ) -> tuple[str, str]:
        """Retrieve the last file and its hash from a specified path in the IPFS file system.

        Args:
            path (str): The directory path in the IPFS file system.
            prefix (str | None): An optional prefix to filter files by name.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            tuple[str, str]: A tuple containing the last file name and its hash.

        """
        _LOGGER.debug(f"Getting last file hash from {path} with prefix {prefix}")
        last_file = None
        last_hash = None
        filenames = await self.get_files_list(path, client=client)
        if len(filenames) > 0:
            if prefix is not None:
                for filename in filenames:
                    if filename[: len(prefix)] == prefix:
                        last_file = filename
                        last_file_stat = await client.files.stat(f"{path}/{last_file}")
                        last_hash = last_file_stat.get("Hash")
            else:
                last_file = filenames[-1]
                last_file_stat = await client.files.stat(f"{path}/{last_file}")
                last_hash = last_file_stat.get("Hash")
        _LOGGER.debug(f"Last {path} file {last_file}, with hash {last_hash}")
        return last_file, last_hash

    @catch_ipfs_errors_async("Exception in check_if_hash_in_folder:")
    @ensure_client
    async def check_if_hash_in_folder(self, ipfs_hash: str, folder: str, client: aioipfs.AsyncIPFS = None) -> bool:
        """Check if a specific IPFS hash exists in a given folder.

        Args:
            ipfs_hash (str): The IPFS hash to search for.
            folder (str): The folder path in the MFS to search within.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            bool: True if the hash is found in the folder, False otherwise.

        """
        list_files = await self.get_files_list(folder, client=client)
        for fileinfo in list_files:
            stat = await client.files.stat(f"{folder}/{fileinfo['Name']}")
            if ipfs_hash == stat["Hash"]:
                return True
        return False

    @catch_ipfs_errors_async("Exception in get_folder_hash:")
    @ensure_client
    async def get_folder_hash(self, ipfs_folder: str, client: aioipfs.AsyncIPFS = None) -> str | None:
        """Retrieve the hash of a folder in the MFS.

        Args:
            ipfs_folder (str): The folder path in the IPFS file system.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            str | None: The hash of the folder, or None if not found.

        """
        res = await client.files.stat(ipfs_folder)
        return res.get("Hash")

    @catch_ipfs_errors_async("Exception in get_folder_hash:")
    @ensure_client
    async def delete_folder(self, dirname: str, client: aioipfs.AsyncIPFS = None) -> None:
        """Delete a folder from the IPFS file system.

        Args:
            dirname (str): The directory name to delete.
            client (aioipfs.AsyncIPFS | None): The IPFS client instance.

        Returns:
            None

        """
        _LOGGER.debug(f"Start deleting ipfs folder {dirname}")
        folder_names = await self.get_files_list("/", client=client)
        if dirname[1:] in folder_names:
            await client.files.rm(dirname, recursive=True)
            _LOGGER.debug(f"Ipfs folder {dirname} was deleted")
