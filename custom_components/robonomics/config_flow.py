"""Config flow for Robonomics Control integration. It is service module for HomeAssistant,
which sets in `manifest.json`. This module allows to setup the integration from the web interface.
"""

from __future__ import annotations

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
from homeassistant.helpers.selector import (
    FileSelector,
    FileSelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)
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
    CONF_NETWORK,
    CONF_KUSAMA,
    CONF_POLKADOT,
    DOMAIN,
)
from .config_flow_helpers import ConfigFileParser, ConfigValidator
from .utils import to_thread

_LOGGER = logging.getLogger(__name__)


STEP_USER_DATA_SCHEMA_FIELDS = {}
PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CONFIG_FILE): FileSelector(
            FileSelectorConfig(accept=".json,application/json")
        ),
        vol.Required(CONF_PASSWORD): PASSWORD_SELECTOR,
    }
)

NETWORK_SELECTOR = SelectSelector(
    SelectSelectorConfig(
        options=[CONF_KUSAMA, CONF_POLKADOT],
        mode=SelectSelectorMode.DROPDOWN,
        translation_key="network",
    )
)

STEP_MANUAL_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ADMIN_SEED): str,
        vol.Required(CONF_SUB_OWNER_ADDRESS): str,
        vol.Required(CONF_NETWORK, default=CONF_POLKADOT): NETWORK_SELECTOR,
    }
)

STEP_WARN_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_WARN_DATA_SENDING): bool,
        vol.Required(CONF_WARN_ACCOUNT_MANAGMENT): bool,
    }
)


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

        self.config = {}
        if user_input is None:
            return self.async_show_form(
                step_id="conf", data_schema=STEP_USER_DATA_SCHEMA
            )
        _LOGGER.debug(f"User data: {user_input}")
        errors = {}
        if CONF_CONFIG_FILE in user_input:
            try:
                self.config = await ConfigFileParser(self.hass, user_input[CONF_CONFIG_FILE], user_input[CONF_PASSWORD]).parse()
            except Exception as e:
                _LOGGER.error(f"Exception in file parse: {e}")
                errors["base"] = ConfigValidator.get_error_key(e)
                return self.async_show_form(
                    step_id="conf", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
                )
            if not CONF_ADMIN_SEED in self.config or not CONF_SUB_OWNER_ADDRESS in self.config or not CONF_NETWORK in self.config:
                return await self.async_step_manual()

            try:
                await ConfigValidator(self.hass, self.config).validate()
            except Exception as e:
                _LOGGER.error(f"Exception in validation: {e}")
                errors["base"] = ConfigValidator.get_error_key(e)
            else:
                return self.async_create_entry(title="Robonomics", data=self.config)
        else:
            errors["base"] = "file_not_found"

        return self.async_show_form(
            step_id="conf", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is None:
            return self.async_show_form(
                step_id="manual", data_schema=STEP_MANUAL_DATA_SCHEMA
            )
        errors = {}
        _LOGGER.debug(f"User data: {user_input}")
        self.config[CONF_SUB_OWNER_ADDRESS] = user_input[CONF_SUB_OWNER_ADDRESS]
        self.config[CONF_NETWORK] = user_input[CONF_NETWORK]
        try:
            self.config[CONF_ADMIN_SEED] = ConfigValidator.get_raw_seed_from_config(user_input[CONF_ADMIN_SEED])
        except Exception as e:
            _LOGGER.error(f"Exception in seed parsing: {e}")
            return self.async_show_form(
                step_id="manual", data_schema=STEP_MANUAL_DATA_SCHEMA, errors={"base": "invalid_sub_admin_seed"}
            )
        try:
            await ConfigValidator(self.hass, self.config).validate()
        except Exception as e:
            errors["base"] = ConfigValidator.get_error_key(e)
        else:
            return self.async_create_entry(title="Robonomics", data=self.config)

        return self.async_show_form(
            step_id="manual", data_schema=STEP_MANUAL_DATA_SCHEMA, errors=errors
        )


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
