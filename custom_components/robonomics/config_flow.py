"""Config flow for Robonomics Control integration. It is service module for HomeAssistant, 
which sets in `manifest.json`. This module allows to setup the integration from the web interface.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from nacl.exceptions import CryptoError
import json

import homeassistant.helpers.config_validation as cv
import ipfshttpclient2
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from robonomicsinterface import RWS, Account
from substrateinterface import KeypairType, Keypair
from substrateinterface.utils.ss58 import is_valid_ss58_address
from homeassistant.helpers.selector import FileSelector, FileSelectorConfig, TextSelector, TextSelectorConfig, TextSelectorType
from homeassistant.components.file_upload import process_uploaded_file

from .const import (
    CONF_ADMIN_SEED,
    CONF_CUSTOM_GATEWAY_USE,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
    CONF_IPFS_GATEWAY_PORT,
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_PINATA_USE,
    CONF_SENDING_TIMEOUT,
    CONF_SUB_OWNER_ADDRESS,
    CONF_WARN_ACCOUNT_MANAGMENT,
    CONF_WARN_DATA_SENDING,
    CONF_PASSWORD,
    CONF_CONFIG_FILE,
    CONF_CONTROLLER_TYPE,
    DOMAIN,
    CRYPTO_TYPE,
)
from .exceptions import (
    CantConnectToIPFS,
    ControllerNotInDevices,
    InvalidSubAdminSeed,
    InvalidSubOwnerAddress,
    NoSubscription,
    InvalidConfigPassword,
    WrongControllerType,
)
from .utils import to_thread

_LOGGER = logging.getLogger(__name__)


STEP_USER_DATA_SCHEMA_FIELDS = {}
PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
STEP_USER_DATA_SCHEMA_FIELDS[CONF_CONFIG_FILE] = FileSelector(FileSelectorConfig(accept=".json,application/json"))
STEP_USER_DATA_SCHEMA_FIELDS[CONF_PASSWORD] = PASSWORD_SELECTOR
STEP_USER_DATA_SCHEMA = vol.Schema(STEP_USER_DATA_SCHEMA_FIELDS)

STEP_WARN_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_WARN_DATA_SENDING): bool,
        vol.Required(CONF_WARN_ACCOUNT_MANAGMENT): bool,
    }
)


@to_thread
def _is_ipfs_local_connected() -> bool:
    """Check if IPFS local node is running and integration can connect

    :return: True if integration can connect to the node, false otherwise
    """

    try:
        ipfshttpclient2.connect()
        return True
    except ipfshttpclient2.exceptions.ConnectionError:
        return False


async def _has_sub_owner_subscription(hass: HomeAssistant, sub_owner_address: str) -> bool:
    """Check if controller account is in subscription devices

    :param sub_owner_address: Subscription owner address

    :return: True if ledger is not None, false otherwise
    """

    rws = RWS(Account())
    res = await hass.async_add_executor_job(rws.get_ledger, sub_owner_address)
    # res = asyncio.run_coroutine_threadsafe(rws.get_ledger(sub_owner_address), hass).result()
    if res is None:
        return False
    else:
        return True


async def _is_sub_admin_in_subscription(hass: HomeAssistant, controller_seed: str, sub_owner_address: str) -> bool:
    """Check if controller account is in subscription devices

    :param sub_admin_seed: Controller's seed
    :param sub_owner_address: Subscription owner address

    :return: True if controller account is in subscription devices, false otherwise
    """

    rws = RWS(Account(controller_seed, crypto_type=CRYPTO_TYPE))
    res = await hass.async_add_executor_job(rws.is_in_sub, sub_owner_address)
    # res = rws.is_in_sub(sub_owner_address)
    return res


def _is_valid_sub_admin_seed(sub_admin_seed: str) -> Optional[ValueError]:
    """Check if provided controller seed is valid

    :param sub_admin_seed: Controller's seed
    """

    try:
        Account(sub_admin_seed)
    except Exception as e:
        return e


def _is_valid_sub_owner_address(sub_owner_address: str) -> bool:
    """Check if provided subscription owner address is valid

    :param sub_owner_address: Subscription owner address

    :return: True if address is valid, false otherwise
    """

    return is_valid_ss58_address(sub_owner_address, valid_ss58_format=32)

def _is_valid_controller_type(controller_type: int) -> bool:
    return controller_type == KeypairType.SR25519


async def _validate_config(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    :param hass: HomeAssistant instance
    :param data: dict with the keys from STEP_USER_DATA_SCHEMA and values provided by the user
    """

    if not _is_valid_controller_type(data[CONF_CONTROLLER_TYPE]):
        raise WrongControllerType
    if data[CONF_ADMIN_SEED] is None:
        raise InvalidConfigPassword
    if await hass.async_add_executor_job(
        _is_valid_sub_admin_seed, data[CONF_ADMIN_SEED]
    ):
        raise InvalidSubAdminSeed
    if not _is_valid_sub_owner_address(data[CONF_SUB_OWNER_ADDRESS]):
        raise InvalidSubOwnerAddress
    if not await _has_sub_owner_subscription(hass, data[CONF_SUB_OWNER_ADDRESS]):
        raise NoSubscription
    if not await _is_sub_admin_in_subscription(
        hass, data[CONF_ADMIN_SEED], data[CONF_SUB_OWNER_ADDRESS]
    ):
        raise ControllerNotInDevices
    if not await _is_ipfs_local_connected():
        raise CantConnectToIPFS

    return {"title": "Robonomics"}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Robonomics Control."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> OptionsFlowHandler:
        """Get the options flow for this handler."""

        return OptionsFlowHandler(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step of the configuration. Contains user's warnings.

        :param user_input: Dict with the keys from STEP_WARN_DATA_SCHEMA and values provided by user

        :return: Service functions from HomeAssistant
        """

        errors = {}
        device_unique_id = "robonomics"
        await self.async_set_unique_id(device_unique_id)
        self._abort_if_unique_id_configured()
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_WARN_DATA_SCHEMA
            )
        else:
            if [x for x in user_input if not user_input[x]]:
                errors["base"] = "warnings"
                return self.async_show_form(
                    step_id="user", data_schema=STEP_WARN_DATA_SCHEMA, errors=errors
                )
            return await self.async_step_conf()

    async def async_step_conf(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the second step of the configuration. Contains fields to provide credentials.

        :param: user_input: Dict with the keys from STEP_USER_DATA_SCHEMA and values provided by user

        :return: Service functions from HomeAssistant
        """

        self.updated_config = {}
        if user_input is None:
            return self.async_show_form(
                step_id="conf", data_schema=STEP_USER_DATA_SCHEMA
            )
        _LOGGER.debug(f"User data: {user_input}")
        config = self._parse_config_file(user_input[CONF_CONFIG_FILE], user_input[CONF_PASSWORD])

        errors = {}
        try:
            info = await _validate_config(self.hass, config)
            config.pop(CONF_CONTROLLER_TYPE)
        except WrongControllerType:
            errors["base"] = "wrong_controller_type"
        except InvalidSubAdminSeed:
            errors["base"] = "invalid_sub_admin_seed"
        except InvalidSubOwnerAddress:
            errors["base"] = "invalid_sub_owner_address"
        except NoSubscription:
            errors["base"] = "has_no_subscription"
        except ControllerNotInDevices:
            errors["base"] = "is_not_in_devices"
        except CantConnectToIPFS:
            errors["base"] = "can_connect_to_ipfs"
        except InvalidConfigPassword:
            errors["base"] = "wrong_password"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"
        else:
            return self.async_create_entry(title=info["title"], data=config)

        return self.async_show_form(
            step_id="conf", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    def _parse_config_file(self, config_file_id: str, password: str) -> dict:
        with process_uploaded_file(self.hass, config_file_id) as f:
            config_file_data = f.read_text(encoding="utf-8")
        config_file_data = json.loads(config_file_data)
        config = {}
        try:
            controller_kp = Keypair.create_from_encrypted_json(json.loads(config_file_data.get("controllerkey")), password)
            config[CONF_ADMIN_SEED] = f"0x{controller_kp.private_key.hex()}"
            config[CONF_CONTROLLER_TYPE] = controller_kp.crypto_type
        except CryptoError:
            config[CONF_ADMIN_SEED] = None
            config[CONF_CONTROLLER_TYPE] = None
        config[CONF_SUB_OWNER_ADDRESS] = config_file_data.get("owner")
        if config_file_data.get("pinatapublic") and config_file_data.get("pinataprivate"):
            config[CONF_PINATA_PUB] = config_file_data.get("pinatapublic")
            config[CONF_PINATA_SECRET] = config_file_data.get("pinataprivate")
        if config_file_data.get("ipfsurl"):
            config[CONF_IPFS_GATEWAY] = config_file_data.get("ipfsurl")
        config[CONF_IPFS_GATEWAY_PORT] = config_file_data.get("ipfsport") or 443
        config[CONF_IPFS_GATEWAY_AUTH] = True
        config[CONF_SENDING_TIMEOUT] = config_file_data.get("datalogtimeout")
        _LOGGER.debug(f"Config: {config}")
        return config

class OptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialise options flow. THis class contains methods to manage config after it was initialised."""

        self.config_entry = config_entry
        _LOGGER.debug(config_entry.data)
        self.updated_config = self.config_entry.data.copy()
        _LOGGER.debug(f"Updated config: {self.updated_config}")

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage Timeout and Pinata and Custom IPFS gateways.

        :param user_input: Dict with the keys from OPTIONS_DATA_SCHEMA and values provided by user

        :return: Service functions from HomeAssistant
        """

        if user_input is not None:
            _LOGGER.debug(f"User input: {user_input}")
            if not user_input[CONF_PINATA_USE]:
                user_input.pop(CONF_PINATA_PUB, None)
                user_input.pop(CONF_PINATA_SECRET, None)
                self.updated_config.pop(CONF_PINATA_PUB, None)
                self.updated_config.pop(CONF_PINATA_SECRET, None)
            if not user_input[CONF_CUSTOM_GATEWAY_USE]:
                user_input.pop(CONF_IPFS_GATEWAY, None)
                self.updated_config.pop(CONF_IPFS_GATEWAY, None)
            del user_input[CONF_PINATA_USE]
            del user_input[CONF_CUSTOM_GATEWAY_USE]

            self.updated_config.update(user_input)

            self.hass.config_entries.async_update_entry(
                self.config_entry, data=self.updated_config
            )
            return self.async_create_entry(title="", data=user_input)

        if CONF_PINATA_PUB in self.config_entry.data:
            pinata_pub = self.config_entry.data[CONF_PINATA_PUB]
            pinata_secret = self.config_entry.data[CONF_PINATA_SECRET]
            if CONF_IPFS_GATEWAY in self.config_entry.data:
                custom_ipfs_gateway = self.config_entry.data[CONF_IPFS_GATEWAY]
                custom_ipfs_port = self.config_entry.data[CONF_IPFS_GATEWAY_PORT]
                custom_ipfs_gateway_auth = self.config_entry.data[
                    CONF_IPFS_GATEWAY_AUTH
                ]
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(
                            CONF_SENDING_TIMEOUT,
                            default=self.config_entry.data[CONF_SENDING_TIMEOUT],
                        ): int,
                        vol.Required(CONF_PINATA_USE, default=True): bool,
                        vol.Optional(CONF_PINATA_PUB, default=pinata_pub): str,
                        vol.Optional(CONF_PINATA_SECRET, default=pinata_secret): str,
                        vol.Required(CONF_CUSTOM_GATEWAY_USE, default=True): bool,
                        vol.Optional(
                            CONF_IPFS_GATEWAY, default=custom_ipfs_gateway
                        ): str,
                        vol.Required(
                            CONF_IPFS_GATEWAY_PORT, default=custom_ipfs_port
                        ): int,
                        vol.Required(
                            CONF_IPFS_GATEWAY_AUTH, default=custom_ipfs_gateway_auth
                        ): bool,
                    }
                )
            else:
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(
                            CONF_SENDING_TIMEOUT,
                            default=self.config_entry.data[CONF_SENDING_TIMEOUT],
                        ): int,
                        vol.Required(CONF_PINATA_USE, default=True): bool,
                        vol.Optional(CONF_PINATA_PUB, default=pinata_pub): str,
                        vol.Optional(CONF_PINATA_SECRET, default=pinata_secret): str,
                        vol.Required(CONF_CUSTOM_GATEWAY_USE, default=False): bool,
                        vol.Optional(CONF_IPFS_GATEWAY): str,
                        vol.Required(CONF_IPFS_GATEWAY_PORT, default=443): int,
                        vol.Required(CONF_IPFS_GATEWAY_AUTH, default=False): bool,
                    }
                )
        else:
            if CONF_IPFS_GATEWAY in self.config_entry.data:
                custom_ipfs_gateway = self.config_entry.data[CONF_IPFS_GATEWAY]
                custom_ipfs_port = self.config_entry.data[CONF_IPFS_GATEWAY_PORT]
                custom_ipfs_gateway_auth = self.config_entry.data[
                    CONF_IPFS_GATEWAY_AUTH
                ]
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(
                            CONF_SENDING_TIMEOUT,
                            default=self.config_entry.data[CONF_SENDING_TIMEOUT],
                        ): int,
                        vol.Required(CONF_PINATA_USE, default=False): bool,
                        vol.Optional(CONF_PINATA_PUB): str,
                        vol.Optional(CONF_PINATA_SECRET): str,
                        vol.Required(CONF_CUSTOM_GATEWAY_USE, default=True): bool,
                        vol.Optional(
                            CONF_IPFS_GATEWAY, default=custom_ipfs_gateway
                        ): str,
                        vol.Required(
                            CONF_IPFS_GATEWAY_PORT, default=custom_ipfs_port
                        ): int,
                        vol.Required(
                            CONF_IPFS_GATEWAY_AUTH, default=custom_ipfs_gateway_auth
                        ): bool,
                    }
                )
            else:
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(
                            CONF_SENDING_TIMEOUT,
                            default=self.config_entry.data[CONF_SENDING_TIMEOUT],
                        ): int,
                        vol.Required(CONF_PINATA_USE, default=False): bool,
                        vol.Optional(CONF_PINATA_PUB): str,
                        vol.Optional(CONF_PINATA_SECRET): str,
                        vol.Required(CONF_CUSTOM_GATEWAY_USE, default=False): bool,
                        vol.Optional(CONF_IPFS_GATEWAY): str,
                        vol.Required(CONF_IPFS_GATEWAY_PORT, default=443): int,
                        vol.Required(CONF_IPFS_GATEWAY_AUTH, default=False): bool,
                    }
                )

        return self.async_show_form(
            step_id="init",
            data_schema=OPTIONS_DATA_SCHEMA,
            last_step=False,
        )
