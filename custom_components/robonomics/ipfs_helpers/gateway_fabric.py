from ..const import CONF_PINATA_PUB, CONF_PINATA_SECRET, CONF_IPFS_GATEWAY, CONF_IPFS_GATEWAY_AUTH, CONF_IPFS_GATEWAY_PORT
from homeassistant.core import HomeAssistant 

class GatewayFabric:

    @staticmethod
    def get_gateways(hass: HomeAssistant, params: dict):
        gateways = []
        if CONF_PINATA_PUB in params:
            pass
