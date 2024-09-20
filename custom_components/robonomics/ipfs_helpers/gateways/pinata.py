from .gateway import Gateway
from homeassistant.core import HomeAssistant
from pinatapy import PinataPy
import typing as tp
import logging
from ...const import PINATA_GATEWAY, DOMAIN

_LOGGER = logging.getLogger(__name__)

class Pinata(Gateway):

    def __init__(self, hass: HomeAssistant, pinata_pub: str, pinata_secret: str, websession) -> None:
        self.pinata_pub = pinata_pub
        self.pinata_secret = pinata_secret
        self.hass = hass
        super().__init__(self.hass, self.hass.data[DOMAIN][PINATA_GATEWAY], websession)
    
    def add(self, filename: str, pin: bool, last_file_hash: str, file_size: tp.Optional[int] = None)-> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
        """Add file to Pinata service

        :param filename: file with data
        :param pin: should save previous pin or not
        :param last_file_hash: hash of file, which should be unpinned(if needed)

        :return: IPFS hash of the file and file size in IPFS
        """
        _LOGGER.debug(f"Start adding {filename} to Pinata, pin: {pin}")
        pinata_py = PinataPy(self.pinata_pub, self.pinata_secret)
        if not pin:
            try:
                self.pinata_py.remove_pin_from_ipfs(last_file_hash)
            except Exception as e:
                _LOGGER.warning(f"Exception in unpinning file from Pinata: {e}")
        try:
            res = None
            res = pinata_py.pin_file_to_ipfs(filename, save_absolute_paths=False)
            ipfs_hash: tp.Optional[str] = res["IpfsHash"]
            ipfs_file_size: tp.Optional[int] = int(res["PinSize"])
            _LOGGER.debug(f"File {filename} was added to Pinata with cid: {ipfs_hash}")
        except Exception as e:
            _LOGGER.error(f"Exception in pinata pin: {e}, pinata response: {res}")
            ipfs_hash = None
            ipfs_file_size = None
            return ipfs_hash, ipfs_file_size
        return ipfs_hash, ipfs_file_size
        
    

        

