from ..gateway import Gateway, PinArgs, UnpinArgs
from homeassistant.core import HomeAssistant
import typing as tp
import logging
import asyncio
import json
from .service import Service
from ....const import DOMAIN, WAIT_IPFS_DAEMON, IPFS_STATUS, IPFS_STATUS_ENTITY
from ....utils import path_is_dir
from .utils import is_ipfs_path_dir, format_files_list

_LOGGER = logging.getLogger(__name__)

class Local(Gateway):

    def __init__(self, hass: HomeAssistant, websession) -> None:
        self.hass = hass
        super().__init__(self.hass, [], websession)
    
    async def pin(self, args: PinArgs) -> tp.Optional[str]:
        file_name: str = args.file_name
        path: str = args.path
        _LOGGER.debug(f"Start adding {file_name} to local node")
        is_path_dir = await self.hass.async_add_executor_job(path_is_dir, file_name)
        result = await self.hass.async_add_executor_job(Service.add, file_name, is_path_dir)
        if isinstance(result, list):
            for res in result:
                if "/" not in res["Name"]:
                    result = res
                    break
        ipfs_hash: tp.Optional[str] = result["Hash"]
        _LOGGER.debug(f"File {file_name} was added to local node with cid: {ipfs_hash}")
        file_name = file_name.split("/")[-1]
        await self.hass.async_add_executor_job(Service.copy_mfs, ipfs_hash, path, file_name)
        return ipfs_hash

    async def unpin(self, args: UnpinArgs) -> None:
        last_file_name: tp.Optional[str] = args.last_file_name
        path: str = args.path
        if last_file_name is not None:
            file_with_path = f"{path}/{last_file_name}"
            file_info = self.async_add_executor_job(Service.stat_file, path, last_file_name)
            is_dir = is_ipfs_path_dir(file_info)
            await self.hass.async_add_executor_job(Service.remove_file, file_with_path, is_dir)
            _LOGGER.debug(f"File {last_file_name} with was unpinned")
    
    def create_tasks_for_get(self, ipfs_hash: str, is_directory: bool = False):
        tasks = []
        tasks.append(Service.get_from_local_node_by_hash(ipfs_hash))

    async def wait_ipfs_daemon(self):
        if self.hass.data[DOMAIN][WAIT_IPFS_DAEMON]:
            return
        self.hass.data[DOMAIN][WAIT_IPFS_DAEMON] = True
        _LOGGER.debug("Wait for IPFS local node connection...")
        connected = await self.hass.async_add_executor_job(Service.check_connection, self.hass)
        while not connected:
            await asyncio.sleep(10)
            connected = await self.hass.async_add_executor_job(Service.check_connection, self.hass)
        self.hass.data[DOMAIN][IPFS_STATUS] = "OK"
        self.hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", self.hass.data[DOMAIN][IPFS_STATUS]
        )
        self.hass.data[DOMAIN][WAIT_IPFS_DAEMON] = False
        
    async def read_file(self, file_name: str, path: str) -> tp.Union[str, dict]:
        data = None
        filename_with_path = f"{path}/{file_name}"
        file_info = await self.hass.async_add_executor_job(Service.stat_file, path, file_name)
        if file_info is None:
            _LOGGER.debug(f"File {filename_with_path} does not exist")
        else:
            data = await self.hass.async_add_executor_job(Service.read_file, filename_with_path)
            try:
                data_json = json.loads(data)
                return data_json
            except Exception as e:
                _LOGGER.debug(f"Data is not json: {e}")
                data = data.decode("utf-8")
        return data


    async def get_last_file_hash(self, path: str, prefix: tp.Optional[str] = None):
        last_file = None
        last_hash = None
        files_list = await self.hass.async_add_executor_job(Service.ls, path)
        file_names_list = format_files_list(files_list)
        if len(file_names_list) > 0:
            if prefix is not None:
                for filename in file_names_list:
                    if filename[: len(prefix)] == prefix:
                        last_file = filename
                        file_info = await self.hass.async_add_executor_job(Service.stat_file, path, last_file)
                        last_hash = file_info["Hash"]
                    else:
                        last_file = file_names_list[-1]
                        file_info = await self.hass.async_add_executor_job(Service.stat_file, path, last_file)
                        last_hash = file_info["Hash"]
                _LOGGER.debug(f"Last {path} file {last_file}, with hash {last_hash}")
        return last_file, last_hash


    async def pin_by_hash(self, ipfs_hash: str, path: tp.Optional[str]) -> bool: 
        if path is not None:
            await self.hass.async_add_executor_job(Service.copy_mfs, ipfs_hash, path)
            result = await self.hass.async_add_executor_job(Service.pin_hash, ipfs_hash)
            if "Pins" in result:
                _LOGGER.debug(
                    f"Hash {ipfs_hash} was pinned to local node with path: {path}"
                )
                return True
            else:
                _LOGGER.debug(f"Can't pin hash {ipfs_hash} to local node by timeout")
                return False

    async def read_ipfs_local_file(self, file_name: str, path: str) -> tp.Union[str, dict]:
        _LOGGER.debug(f"Read data from local file: {path}/{file_name}")
        file_info = await self.hass.async_add_executor_job(Service.stat_file, path, file_name)
        if file_info is None:
            _LOGGER.debug(f"File {path}/{file_name} does not exist")
            data = None
        else:
            filename_with_path = f"{path}/{file_name}"
            data = await self.hass.async_add_executor_job(Service.read_file, filename_with_path)
            try:
                json_data = json.loads(data)
                return json_data
            except Exception as e:
                _LOGGER.debug(f"Data is not json: {e}")
                data = data.decode("utf-8")
        return data