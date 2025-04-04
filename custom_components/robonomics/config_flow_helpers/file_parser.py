import json
import logging
from nacl.exceptions import CryptoError

from substrateinterface import Keypair

from homeassistant.core import HomeAssistant
from homeassistant.components.file_upload import process_uploaded_file

from ..const import (
    CONF_ADMIN_SEED,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
    CONF_IPFS_GATEWAY_PORT,
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_SENDING_TIMEOUT,
    CONF_SUB_OWNER_ADDRESS,
    CONF_CONTROLLER_TYPE,
    CONF_NETWORK
)
from ..exceptions import (
    InvalidConfigPassword,
    InvalidConfigFormat,
)

_LOGGER = logging.getLogger(__name__)

class ConfigFileParser:
    def __init__(self, hass: HomeAssistant, config_file_id: str, password: str) -> None:
        self.hass: HomeAssistant = hass
        self.file_id: str = config_file_id
        self.password: str = password
        self.config: dict = {}

    async def parse(self) -> dict:
        """Parse the uploaded configuration file, decrypt sensitive data, and populate the configuration dictionary.

        Returns:
            dict: The parsed and processed configuration data.

        Raises:
            InvalidConfigFormat: If the file data is not in the expected format.
            InvalidConfigPassword: If the decryption of sensitive data fails.

        """
        file_data = await self.hass.async_add_executor_job(self._load_file_data)
        if not file_data:
            raise InvalidConfigFormat
        if "controller" in file_data and "owner" in file_data:
            if file_data["controller"]["private"]:
                if not self._decrypt_controller(file_data["controller"]["private"]):
                    raise InvalidConfigPassword
            self.config[CONF_SUB_OWNER_ADDRESS] = file_data["owner"]
        elif "encoded" in file_data:
            if not self._decrypt_controller(file_data):
                raise InvalidConfigPassword
            return self.config
        self._fill_gateways_fields(file_data)
        self.config[CONF_SENDING_TIMEOUT] = int(file_data["datalog"]["interval"]) if file_data["datalog"]["interval"] else 10
        self.config[CONF_NETWORK] = file_data["network"] if file_data["network"] else "polkadot"
        _LOGGER.debug(f"Config: {self.config}")
        return self.config


    def _load_file_data(self) -> dict | None:
        with process_uploaded_file(self.hass, self.file_id) as f:
            config_file_data = f.read_text(encoding="utf-8")
        try:
            return json.loads(config_file_data)
        except Exception as e:
            _LOGGER.error(f"Exception in parsing config file: {e}")

    def _decrypt_controller(self, controller_encrypted: dict | str) -> bool:
        """Decrypt controller info from config file. Fill CONF_ADMIN_SEED and CONF_CONTROLLER_TYPE fields in self.config."""

        if isinstance(controller_encrypted, str):
            controller_encrypted_json = json.loads(controller_encrypted)
        else:
            controller_encrypted_json = controller_encrypted
        try:
            controller_kp = Keypair.create_from_encrypted_json(
                controller_encrypted_json, self.password
            )
        except CryptoError:
            return False
        self.config[CONF_ADMIN_SEED] = f"0x{controller_kp.private_key.hex()}"
        self.config[CONF_CONTROLLER_TYPE] = controller_kp.crypto_type
        return True

    def _fill_gateways_fields(self, file_data: dict) -> None:
        """Fill IPFS and Pinata fields in self.config."""
        if file_data["pinata"]["public"] and file_data["pinata"]["private"]:
            self.config[CONF_PINATA_PUB] = file_data["pinata"]["public"]
            self.config[CONF_PINATA_SECRET] = file_data["pinata"]["private"]
        if file_data["ipfs"]["url"]:
            self.config[CONF_IPFS_GATEWAY] = file_data["ipfs"]["url"]
        self.config[CONF_IPFS_GATEWAY_PORT] = file_data["ipfs"]["port"] if file_data["ipfs"]["port"] else 443
        self.config[CONF_IPFS_GATEWAY_AUTH] = True
