from .gateway import Gateway
from homeassistant.core import HomeAssistant
import typing as tp
import logging
from ...const import IPFS_GATEWAY, MORALIS_GATEWAY, DOMAIN

_LOGGER = logging.getLogger(__name__)

class Public(Gateway):

    def __init__(self, hass: HomeAssistant, websession) -> None:
        self.hass = hass
        super().__init__(self.hass, [self.hass.data[DOMAIN][IPFS_GATEWAY], self.hass.data[DOMAIN][MORALIS_GATEWAY]], websession)
    
    def add(self, filename: str, pin: bool, last_file_hash: tp.Optional[str] = None, file_size: tp.Optional[int] = None) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
        """No add method for public gateways"""
        pass