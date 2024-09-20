from .gateway import Gateway, PinArgs, UnpinArgs
from homeassistant.core import HomeAssistant
import typing as tp
import logging
from ...const import IPFS_GATEWAY, MORALIS_GATEWAY, DOMAIN

_LOGGER = logging.getLogger(__name__)

class Public(Gateway):

    def __init__(self, hass: HomeAssistant, websession) -> None:
        self.hass = hass
        super().__init__(self.hass, [IPFS_GATEWAY, MORALIS_GATEWAY], websession)
    
    def pin(self, args: PinArgs) -> tp.Optional[str]:
        """No pin method for public gateways"""
        pass

    def unpin(self, args: UnpinArgs) -> None:
        """No unpin method for public gateways"""
        pass
