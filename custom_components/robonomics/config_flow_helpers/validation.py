import typing as tp
import ipfshttpclient2

from robonomicsinterface import RWS, Account
from substrateinterface import KeypairType
from substrateinterface.utils.ss58 import is_valid_ss58_address

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from ..exceptions import (
    CantConnectToIPFS,
    ControllerNotInDevices,
    InvalidSubAdminSeed,
    InvalidSubOwnerAddress,
    NoSubscription,
    InvalidConfigPassword,
    InvalidConfigFormat,
)
from ..const import (
    CONF_ADMIN_SEED,
    CONF_SUB_OWNER_ADDRESS,
    CONF_NETWORK,
    CONF_KUSAMA,
    CONF_POLKADOT,
    ROBONOMICS_WSS_POLKADOT,
    ROBONOMICS_WSS_KUSAMA,
)

class ConfigValidator:
    def __init__(self, hass: HomeAssistant, data: tp.Dict) -> None:
        self.data: tp.Dict = data
        self.hass: HomeAssistant = hass

    @staticmethod
    def get_error_key(exception: HomeAssistantError) -> str:
        if isinstance(exception, InvalidConfigPassword):
            return "wrong_password"
        if isinstance(exception, InvalidSubAdminSeed):
            return "invalid_sub_admin_seed"
        if isinstance(exception, InvalidSubOwnerAddress):
            return "invalid_sub_owner_address"
        if isinstance(exception, NoSubscription):
            return "has_no_subscription"
        if isinstance(exception, ControllerNotInDevices):
            return "is_not_in_devices"
        if isinstance(exception, CantConnectToIPFS):
            return "can_connect_to_ipfs"
        if isinstance(exception, InvalidConfigFormat):
            return "wrong_config_format"
        return "unknown"

    @staticmethod
    def get_raw_seed_from_config(config_seed: str) -> str:
        """Extract and return the raw seed from the provided configuration seed.

        :param config_seed: The seed string from the configuration.
        :return: The raw seed in hexadecimal format.
        """
        if config_seed.startswith("0x"):
            return config_seed
        if " " in config_seed:
            acc = Account(config_seed, crypto_type=KeypairType.ED25519)
            return f"0x{acc.keypair.private_key.hex()}"
        else:
            return f"0x{config_seed}"

    async def validate(self) -> str | None:
        """Validate input from Config Flow.

        :return: None if the input is correct, othervese raise an exception
        """

        if self.data[CONF_ADMIN_SEED] is None:
            raise InvalidConfigPassword
        if not self.hass.async_add_executor_job(self._is_ipfs_local_connected):
            raise CantConnectToIPFS
        if not self._is_valid_sub_admin_seed():
            raise InvalidSubAdminSeed
        if not self._is_valid_sub_owner_address():
            raise InvalidSubOwnerAddress
        if not await self._has_sub_owner_subscription():
            raise NoSubscription
        if not await self._is_sub_admin_in_subscription():
            raise ControllerNotInDevices


    def _is_ipfs_local_connected(self) -> bool:
        try:
            ipfshttpclient2.connect()
            return True
        except ipfshttpclient2.exceptions.ConnectionError:
            return False


    async def _has_sub_owner_subscription(self) -> bool:
        rws = RWS(Account(remote_ws = self._get_network_ws()))
        return await self.hass.async_add_executor_job(rws.get_ledger, self.data[CONF_SUB_OWNER_ADDRESS])


    async def _is_sub_admin_in_subscription(self) -> None:
        rws = RWS(Account(self.data[CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519, remote_ws = self._get_network_ws()))
        return await self.hass.async_add_executor_job(rws.is_in_sub, self.data[CONF_SUB_OWNER_ADDRESS])


    def _is_valid_sub_admin_seed(self) -> None:
        try:
            Account(self.data[CONF_ADMIN_SEED])
            return True
        except Exception as e:
            return False


    def _is_valid_sub_owner_address(self) -> None:
        return is_valid_ss58_address(self.data[CONF_SUB_OWNER_ADDRESS], valid_ss58_format=32)

    def _get_network_ws(self) -> str:
        if self.data[CONF_NETWORK] == CONF_KUSAMA:
            return ROBONOMICS_WSS_KUSAMA[0]
        elif self.data[CONF_NETWORK] == CONF_POLKADOT:
            return ROBONOMICS_WSS_POLKADOT[0]