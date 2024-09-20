from ..gateway import Gateway, PinArgs, UnpinArgs
from homeassistant.core import HomeAssistant
import typing as tp
import logging
import ipfshttpclient2
from ....const import IPFS_GATEWAY, MORALIS_GATEWAY, DOMAIN
from ...decorators import catch_ipfs_errors
from ....utils import path_is_dir

_LOGGER = logging.getLogger(__name__)

class Local(Gateway):

    def __init__(self, hass: HomeAssistant, websession) -> None:
        self.hass = hass
        super().__init__(self.hass, [self.hass.data[DOMAIN][IPFS_GATEWAY], self.hass.data[DOMAIN][MORALIS_GATEWAY]], websession)
    
    def pin(self, args: PinArgs) -> tp.Optional[str]:
        file_name: str = args.file_name
        path: str = args.path
        _LOGGER.debug(f"Start adding {file_name} to local node")
        with ipfshttpclient2.connect() as client:
            result = client.add(file_name, pin=False, recursive=path_is_dir(file_name))
            if isinstance(result, list):
                for res in result:
                    if "/" not in res["Name"]:
                        result = res
                        break
            ipfs_hash: tp.Optional[str] = result["Hash"]
            _LOGGER.debug(f"File {file_name} was added to local node with cid: {ipfs_hash}")
            filename = filename.split("/")[-1]
            client.files.cp(f"/ipfs/{ipfs_hash}", f"{path}/{file_name}")
        return ipfs_hash
    
    @catch_ipfs_errors("Exception in check if ipfs path is dir")
    def _path_is_dir(self, client, filename_with_path: str) -> bool:
        if self._ipfs_file_exists(client, filename_with_path):
            path_type = client.files.stat(filename_with_path)["Type"]
            return path_type == "directory"
        else:
            return False
    
    @catch_ipfs_errors("Exception in check if file exists")
    def _ipfs_file_exists(self, client, filename_with_path: str) -> bool:
        try:
            client.files.stat(filename_with_path)
            return True
        except ipfshttpclient2.exceptions.ErrorResponse:
            return False
