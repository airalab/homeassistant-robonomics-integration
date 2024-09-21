from .gateway import Gateway, PinArgs, UnpinArgs
from homeassistant.core import HomeAssistant
from ..decorators import catch_ipfs_errors
from crustinterface import Mainnet
from substrateinterface import KeypairType
import typing as tp
import logging
from ...const import CRUST_GATEWAY_1, CRUST_GATEWAY_2, DOMAIN, CONF_ADMIN_SEED

_LOGGER = logging.getLogger(__name__)

class Crust(Gateway):
    def __init__(self, hass: HomeAssistant, websession) -> None:
        self.hass = hass
        super().__init__(hass, [CRUST_GATEWAY_1, CRUST_GATEWAY_2], websession)
    
    async def pin(self, args: PinArgs) -> tp.Optional[str]:
        file_name: str = args.file_name
        file_size: int = args.file_size
        mainnet = self._setup_and_check_crust(file_size)
        if mainnet is not None:
            try:
                _LOGGER.debug(f"Start adding {file_name} to crust with size {file_size}")
                file_stored = self.hass.async_add_executor_job(self._store_file, file_name, file_size)
                _LOGGER.debug(f"file stored in Crust. Extrinsic data is  {file_stored}")
            except Exception as e:
                _LOGGER.debug(f"error while uploading file to crust - {e}")
                return None
            return file_stored
    
    def unpin(self, args: UnpinArgs) -> None:
        """No unpin method for crust gateway"""
        pass

    def _setup_and_check_crust(self, file_size: int) -> tp.Optional[Mainnet]:
        seed: str = self.hass.data[DOMAIN][CONF_ADMIN_SEED]
        mainnet = Mainnet(seed=seed, crypto_type=KeypairType.ED25519)
        try:
            # Check balance
            balance = mainnet.get_balance()
            _LOGGER.debug(f"Actual balance in crust network - {balance}")

            # Check price in Main net. Price in pCRUs
            price = mainnet.get_appx_store_price(file_size)
            _LOGGER.debug(f"approximate cost to store the file - {price}")

        except Exception as e:
            _LOGGER.debug(f"error while get account balance - {e}")
            return None

        if price >= balance:
            _LOGGER.warning("Not enough account balance to store the file in Crust Network")
            return None
    
    def _store_file(self, mainnet: Mainnet, file_name: str, file_size: int) -> tp.Tuple[str, str]:
        return mainnet.store_file(file_name, file_size)