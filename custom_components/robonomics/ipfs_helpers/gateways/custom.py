from .gateway import Gateway
from homeassistant.core import HomeAssistant
import typing as tp
import logging
from robonomicsinterface.utils import web_3_auth
import ipfshttpclient2
from ...const import CONF_IPFS_GATEWAY, DOMAIN, CONF_IPFS_GATEWAY_PORT

_LOGGER = logging.getLogger(__name__)

class Custom(Gateway):

    def __init__(self, hass: HomeAssistant, websession, seed: tp.Optional[str] = None) -> None:
        self.hass = hass
        self.port = hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT]
        self.seed = seed
        super().__init__(self.hass, self.hass.data[DOMAIN][CONF_IPFS_GATEWAY], websession)
    
    def add(self, filename: str, pin: bool, last_file_hash: str, file_size: tp.Optional[int] = None)-> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
        url = self._format_url_for_add_request()
        address = self._format_address_for_add_request(url)
        _LOGGER.debug(f"Start adding {filename} to {url}, pin: {pin}, auth: {bool(self.seed)}")
        if self.seed is not None:
            try:
                usr, pwd = web_3_auth(self.seed)
            except Exception as e:
                 _LOGGER.warning(f"Can't authorize to custom gateway: {e}. Trying to use gateway {url} without authorization.")
                 self.seed = None
        try:
            if not pin:
                try:
                    if self.seed is not None:
                        self._unpin_with_authorization(address, usr, pwd)
                    else:
                        self._unpin(address, last_file_hash)
                except Exception as e:
                    _LOGGER.warning(f"Can't unpin from custom gateway: {e}")

            if self.seed is not None:
                ipfs_hash, ipfs_file_size = self._pin_with_authorization(address, usr, pwd, filename)
            else:
                ipfs_hash, ipfs_file_size = self._pin(address, filename)

        except Exception as e:
            _LOGGER.error(f"Exception in pinning to custom gateway: {e}")
            ipfs_hash = None
            ipfs_file_size = None
            return ipfs_hash, ipfs_file_size
        
        return ipfs_hash, ipfs_file_size

    def _format_url_for_add_request(self):
        if "https://" in self.hass.data[DOMAIN][CONF_IPFS_GATEWAY]:
            url = self.hass.data[DOMAIN][CONF_IPFS_GATEWAY][8:]
        if self.hass.data[DOMAIN][CONF_IPFS_GATEWAY][-1] == "/":
            url = self.hass.data[DOMAIN][CONF_IPFS_GATEWAY][:-1]
        return url
    
    def _format_address_for_add_request(self, url: str) -> str:
        return f"/dns4/{url}/tcp/{self.port}/https"

    def _unpin_with_authorization(self, address: str, usr: str, pwd: str, last_file_hash: str) -> None:
        with ipfshttpclient2.connect(addr=address, auth=(usr, pwd)) as client:
            client.pin.rm(last_file_hash)
            _LOGGER.debug(f"Hash {last_file_hash} was unpinned from {address} with authorization")
    
    def _unpin(self, address: str, last_file_hash: str) -> None:
        with ipfshttpclient2.connect(addr=address) as client:
            client.pin.rm(last_file_hash)
            _LOGGER.debug(f"Hash {last_file_hash} was unpinned from {address}")
    
    def _pin_with_authorization(self, address: str, usr: str, pwd: str, filename: str) -> tp.Tuple[str, int]:
        with ipfshttpclient2.connect(addr=address, auth=(usr, pwd)) as client:
            result = client.add(filename)
            ipfs_hash, ipfs_file_size = self._parse_result(result)
            _LOGGER.debug(
                f"File {filename} was added to {address} with cid: {ipfs_hash}"
            )
            return ipfs_hash, ipfs_file_size
    
    def _pin(self, address: str, filename: str) -> tp.Tuple[str, int]:
        with ipfshttpclient2.connect(addr=address) as client:
            result = client.add(filename)
            ipfs_hash, ipfs_file_size = self._parse_result(result)
            _LOGGER.debug(
                f"File {filename} was added to {address} with cid: {ipfs_hash}"
            )
            return ipfs_hash, ipfs_file_size
    
    def _parse_result(self, result) -> tp.Tuple[str, int]:
        if isinstance(result, list):
                result = result[-1]
        ipfs_hash: tp.Optional[str] = result["Hash"]
        ipfs_file_size: tp.Optional[int] = int(result["Size"])
        return ipfs_hash, ipfs_file_size