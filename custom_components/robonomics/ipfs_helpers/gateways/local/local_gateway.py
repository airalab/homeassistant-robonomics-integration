from ..gateway import Gateway, PinArgs, UnpinArgs
from homeassistant.core import HomeAssistant
import typing as tp
import logging
import ipfshttpclient2
import time
import asyncio
import json
from ....const import DOMAIN, WAIT_IPFS_DAEMON, IPFS_STATUS, IPFS_STATUS_ENTITY
from ...decorators import catch_ipfs_errors
from ....utils import path_is_dir

_LOGGER = logging.getLogger(__name__)

class Local(Gateway):

    def __init__(self, hass: HomeAssistant, websession) -> None:
        self.hass = hass
        super().__init__(self.hass, [], websession)
    
    async def pin(self, args: PinArgs) -> tp.Optional[str]:
        file_name: str = args.file_name
        path: str = args.path
        _LOGGER.debug(f"Start adding {file_name} to local node")
        is_path_dir = self.hass.async_add_executor_job(path_is_dir, file_name)
        result = self.hass.async_add_executor_job(self._add, file_name, is_path_dir)
        if isinstance(result, list):
            for res in result:
                if "/" not in res["Name"]:
                    result = res
                    break
        ipfs_hash: tp.Optional[str] = result["Hash"]
        _LOGGER.debug(f"File {file_name} was added to local node with cid: {ipfs_hash}")
        file_name = file_name.split("/")[-1]
        self.hass.async_add_executor_job(self._copy_mfs, file_name, ipfs_hash, path)
        return ipfs_hash

    def unpin(self, args: UnpinArgs) -> None:
        last_file_name: tp.Optional[str] = args.last_file_name
        path: str = args.path
        if last_file_name is not None:
            file_with_path = f"{path}/{last_file_name}"
            is_dir = self.hass.async_add_executor_job(self._path_is_dir, file_with_path)
            self.hass.async_add_executor_job(self._remove_file, file_with_path, is_dir)
            _LOGGER.debug(f"File {last_file_name} with was unpinned")

    async def wait_ipfs_daemon(self):
        if self.hass.data[DOMAIN][WAIT_IPFS_DAEMON]:
            return
        self.hass.data[DOMAIN][WAIT_IPFS_DAEMON] = True
        _LOGGER.debug("Wait for IPFS local node connection...")
        connected = await self.hass.async_add_executor_job(self._check_connection)
        while not connected:
            await asyncio.sleep(10)
            connected = await self.hass.async_add_executor_job(self._check_connection)
        self.hass.data[DOMAIN][IPFS_STATUS] = "OK"
        self.hass.states.async_set(
            f"sensor.{IPFS_STATUS_ENTITY}", self.hass.data[DOMAIN][IPFS_STATUS]
        )
        self.hass.data[DOMAIN][WAIT_IPFS_DAEMON] = False
        

    @catch_ipfs_errors("Exception in reading ipfs local file")
    async def read_file(self, file_name: str, path: str) -> tp.Union[str, dict]:
        data = None
        filename_with_path = f"{path}/{file_name}"
        if not self.hass.async_add_executor_job(self._is_file_exists, filename_with_path):
            _LOGGER.debug(f"File {filename_with_path} does not exist")
        else:
            data = self.hass.async_add_executor_job(self._read_file, filename_with_path)
            try:
                data_json = json.loads(data)
                return data_json
            except Exception as e:
                _LOGGER.debug(f"Data is not json: {e}")
                data = data.decode("utf-8")
        return data


    def get_last_file_hash():
        pass

    def pin_by_hash(self):
        pass

    def read_ipfs_local_file():
        pass

    async def create_tasks_for_get(self):
        tasks = []
        tasks.append(self._get_from_local_node_by_hash())

    
    def _add(self, file_name, is_path_dir: bool):
        with ipfshttpclient2.connect() as client:
            result = client.add(file_name, pin=False, recursive=is_path_dir)
        return result
    
    def _copy_mfs(self, file_name: str, ipfs_hash: str, path: str) -> None:
        with ipfshttpclient2.connect() as client:
            client.files.cp(f"/ipfs/{ipfs_hash}", f"{path}/{file_name}")

    
    @catch_ipfs_errors("Exception in check if ipfs path is dir")
    def _path_is_dir(self, filename_with_path: str) -> bool:
        if self._is_file_exists(client, filename_with_path):
            with ipfshttpclient2.connect() as client:
                path_type = client.files.stat(filename_with_path)["Type"]
                is_dir = path_type == "directory"
        else:
            is_dir = False
        return is_dir
    
    @catch_ipfs_errors("Exception in check if file exists")
    def _is_file_exists(self, filename_with_path: str) -> bool:
        with ipfshttpclient2.connect() as client:
            try:
                client.files.stat(filename_with_path)
                file_exists = True
            except ipfshttpclient2.exceptions.ErrorResponse:
                file_exists = False
        return file_exists
    
    def _remove_file(self, file_with_path: str, is_dir: bool) -> None:
        with ipfshttpclient2.connect() as client:
            client.files.rm(file_with_path, recursive=is_dir)
    
    @catch_ipfs_errors("Exception in get from local node by hash")
    def _get_from_local_node_by_hash(self) -> tp.Optional[str]:
        with ipfshttpclient2.connect() as client:
            res = client.cat(self.ipfs_hash)
            res_str = res.decode()
            _LOGGER.debug(f"Got data {self.ipfs_hash} from local gateway")
        return res_str


    def _check_connection(self) -> bool:
        """Check connection to IPFS local node

        :return: Connected or not
        """
        try:
            with ipfshttpclient2.connect() as client:
                test_hash = client.add_str("Test string")
                _LOGGER.debug(f"Added test string to the local node: {test_hash}")
                time.sleep(0.5)
                files_info = client.files.ls("/")["Entries"]
                if files_info is not None:
                    files = [fileinfo["Name"] for fileinfo in files_info]
                    if "test_file" in files:
                        client.files.rm("/test_file")
                        _LOGGER.debug("Deleted test string from the local node MFS")
                    time.sleep(0.5)
                client.files.cp(f"/ipfs/{test_hash}", "/test_file")
                _LOGGER.debug("Added test string to the local node MFS")
                time.sleep(0.5)
                client.files.rm("/test_file")
                _LOGGER.debug("Deleted test string from the local node MFS")
                time.sleep(0.5)
                res = client.pin.rm(test_hash)
                _LOGGER.debug(f"Unpinned test string from local node with res: {res}")
                time.sleep(0.5)
            _LOGGER.debug("Connected to IPFS local node")
            return True
        
        except ipfshttpclient2.exceptions.ConnectionError:
            self.hass.data[DOMAIN][IPFS_STATUS] = "Error"
            self.hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", self.hass.data[DOMAIN][IPFS_STATUS]
            )
            _LOGGER.debug("Can't connect to IPFS")
            return False
        except Exception as e:
            self.hass.data[DOMAIN][IPFS_STATUS] = "Error"
            self.hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", self.hass.data[DOMAIN][IPFS_STATUS]
            )
            _LOGGER.error(f"Unexpected error in check ipfs connection: {e}")
            return False

    def _read_file(self, filename_with_path: str) -> str:
        with ipfshttpclient2.connect() as client:
            return client.files.read(filename_with_path)