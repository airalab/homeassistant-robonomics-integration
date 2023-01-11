"""Config flow for Robonomics Control integration."""
from __future__ import annotations
from robonomicsinterface import Account
from substrateinterface.utils.ss58 import is_valid_ss58_address

import logging
from typing import Any, Optional

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from .exceptions import InvalidSubAdminSeed, InvalidSubOwnerAddress
import homeassistant.helpers.config_validation as cv

from .const import (
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_SUB_OWNER_ADDRESS,
    CONF_ADMIN_SEED,
    DOMAIN,
    CONF_SENDING_TIMEOUT,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ADMIN_SEED): str,
        vol.Required(CONF_SUB_OWNER_ADDRESS): str,
        vol.Required(CONF_SENDING_TIMEOUT, default=10): int,
        vol.Optional(CONF_IPFS_GATEWAY): str,
        vol.Required(CONF_IPFS_GATEWAY_AUTH, default=False): bool,
        vol.Optional(CONF_PINATA_PUB): str,
        vol.Optional(CONF_PINATA_SECRET): str,
    }
)


def is_valid_sub_admin_seed(sub_admin_seed: str) -> Optional[ValueError]:
    try:
        Account(sub_admin_seed)
    except Exception as e:
        return e

def is_valid_sub_owner_address(sub_owner_address: str) -> Optional[ValueError]:
    return is_valid_ss58_address(sub_owner_address, valid_ss58_format=32)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    if await hass.async_add_executor_job(is_valid_sub_admin_seed, data[CONF_ADMIN_SEED]):
        raise InvalidSubAdminSeed
    if not is_valid_ss58_address(data[CONF_SUB_OWNER_ADDRESS], valid_ss58_format=32):
        raise InvalidSubOwnerAddress

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
        """Handle the initial step."""
        self.updated_config = {}
        device_unique_id = "robonomics"
        await self.async_set_unique_id(device_unique_id)
        self._abort_if_unique_id_configured()
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_USER_DATA_SCHEMA
            )

        errors = {}

        try:
            info = await validate_input(self.hass, user_input)
        except CannotConnect:
            errors["base"] = "cannot_connect"
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except InvalidSubAdminSeed:
            errors["base"] = "invalid_sub_admin_seed"
        except InvalidSubOwnerAddress:
            errors["base"] = "invalid_sub_owner_address"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"
        else:
            return self.async_create_entry(title=info["title"], data=user_input)
        
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )


class OptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        _LOGGER.debug(config_entry.data)
        self.updated_config = self.config_entry.data.copy()

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Manage the options.
        """
        if user_input is not None:
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
                custom_ipfs_gateway_auth = self.config_entry.data[CONF_IPFS_GATEWAY_AUTH]
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(CONF_SENDING_TIMEOUT, default=self.config_entry.data[CONF_SENDING_TIMEOUT]): int,
                        vol.Optional(CONF_PINATA_PUB, default=pinata_pub): str,
                        vol.Optional(CONF_PINATA_SECRET, default=pinata_secret): str,
                        vol.Optional(CONF_IPFS_GATEWAY, default=custom_ipfs_gateway): str,
                        vol.Required(CONF_IPFS_GATEWAY_AUTH, default=custom_ipfs_gateway_auth): bool,
                    }
                )
            else:
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(CONF_SENDING_TIMEOUT, default=self.config_entry.data[CONF_SENDING_TIMEOUT]): int,
                        vol.Optional(CONF_PINATA_PUB, default=pinata_pub): str,
                        vol.Optional(CONF_PINATA_SECRET, default=pinata_secret): str,
                        vol.Optional(CONF_IPFS_GATEWAY): str,
                        vol.Required(CONF_IPFS_GATEWAY_AUTH, default=False): bool,
                    }
                )
        else:
            if CONF_IPFS_GATEWAY in self.config_entry.data:
                custom_ipfs_gateway = self.config_entry.data[CONF_IPFS_GATEWAY]
                custom_ipfs_gateway_auth = self.config_entry.data[CONF_IPFS_GATEWAY_AUTH]
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(CONF_SENDING_TIMEOUT, default=self.config_entry.data[CONF_SENDING_TIMEOUT]): int,
                        vol.Optional(CONF_PINATA_PUB): str,
                        vol.Optional(CONF_PINATA_SECRET): str,
                        vol.Optional(CONF_IPFS_GATEWAY, default=custom_ipfs_gateway): str,
                        vol.Required(CONF_IPFS_GATEWAY_AUTH, default=custom_ipfs_gateway_auth): bool,
                    }
                )
            else:
                OPTIONS_DATA_SCHEMA = vol.Schema(
                    {
                        vol.Required(CONF_SENDING_TIMEOUT, default=self.config_entry.data[CONF_SENDING_TIMEOUT]): int,
                        vol.Optional(CONF_PINATA_PUB): str,
                        vol.Optional(CONF_PINATA_SECRET): str,
                        vol.Optional(CONF_IPFS_GATEWAY): str,
                        vol.Required(CONF_IPFS_GATEWAY_AUTH, default=False): bool,
                    }
                )

        return self.async_show_form(
            step_id="init",
            data_schema=OPTIONS_DATA_SCHEMA,
            last_step=False,
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
