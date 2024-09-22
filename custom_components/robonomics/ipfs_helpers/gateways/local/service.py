import ipfshttpclient2
import typing as tp
import time
import logging
from homeassistant.core import HomeAssistant
from ...decorators import catch_ipfs_errors
from ....const import DOMAIN, IPFS_STATUS, IPFS_STATUS_ENTITY

_LOGGER = logging.getLogger(__name__)

class Service:

    @staticmethod
    @catch_ipfs_errors("Exception in adding file to local node")
    def add(file_name: str, is_dir: bool) -> dict:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                result = client.add(file_name, pin=False, recursive=is_dir)
            return result
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in add")
    
    @staticmethod
    @catch_ipfs_errors("Exception in copy file in mfs")
    def copy_mfs(ipfs_hash: str, path: str, file_name: str = None) -> None:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                if file_name is not None:
                    client.files.cp(f"/ipfs/{ipfs_hash}", f"{path}/{file_name}")
                else:
                    client.files.cp(f"/ipfs/{ipfs_hash}", fpath)
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in copy_mfs")

    @staticmethod
    @catch_ipfs_errors("Exception in stat file")
    def stat_file(path: str, file_name: str) -> tp.Optional[dict]:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                try:
                    file_info = client.files.stat(f"{path}/{file_name}")
                except ipfshttpclient2.exceptions.ErrorResponse:
                    file_info = None
            return file_info
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in stat_file")
    
    @staticmethod
    @catch_ipfs_errors("Exception in removing ipfs local file")
    def remove_file(file_with_path: str, is_dir: bool) -> None:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                client.files.rm(file_with_path, recursive=is_dir) 
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in remove_file")

    @staticmethod
    @catch_ipfs_errors("Exception in get from local node by hash")
    def get_from_local_node_by_hash(ipfs_hash: str) -> tp.Optional[str]:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                res = client.cat(ipfs_hash)
                res_str = res.decode()
                _LOGGER.debug(f"Got data {ipfs_hash} from local gateway")
            return res_str
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in get_from_local_node_by_hash")

    @staticmethod
    @catch_ipfs_errors("Exception in reading ipfs local file")
    def read_file(filename_with_path: str) -> str:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                return client.files.read(filename_with_path)
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in read_file")

    @staticmethod
    @catch_ipfs_errors("Exception in ls")
    def ls(path: str = "/") -> tp.List[str]:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                return client.files.ls(path)
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in ls")

    @staticmethod
    @catch_ipfs_errors("Exception in ls")
    def pin_hash(ipfs_hash: str) -> dict:
        try:
            with ipfshttpclient2.connect(timeout=40) as client:
                return client.pin.add(ipfs_hash)
        except ipfshttpclient2.exceptions.TimeoutError:
            _LOGGER.debug("IPFS Local Gateway: Timeout in pin_hash")   

    
    @staticmethod
    def check_connection(hass: HomeAssistant) -> bool:
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
            hass.data[DOMAIN][IPFS_STATUS] = "Error"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
            _LOGGER.debug("Can't connect to IPFS")
            return False
        except Exception as e:
            hass.data[DOMAIN][IPFS_STATUS] = "Error"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
            _LOGGER.error(f"Unexpected error in check ipfs connection: {e}")
            return False