"""Config flow for Robonomics Control integration."""
from __future__ import annotations
from robonomicsinterface import Account

import logging
from typing import Any, Optional

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from .exceptions import InvalidSubAdminSeed, InvalidSubOwnerSeed

from .const import (
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_SUB_OWNER_ED,
    CONF_SUB_OWNER_SEED,
    CONF_USER_ED,
    CONF_USER_SEED,
    DOMAIN,
    CONF_SENDING_TIMEOUT
)

_LOGGER = logging.getLogger(__name__)

# TODO adjust the data schema to the data that you need
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USER_SEED): str,
        vol.Required(CONF_USER_ED): bool,
        vol.Required(CONF_SUB_OWNER_SEED): str,
        vol.Required(CONF_SUB_OWNER_ED): bool,
        vol.Required(CONF_SENDING_TIMEOUT, default=10): int,
        vol.Optional(CONF_PINATA_PUB): str,
        vol.Optional(CONF_PINATA_SECRET): str,
    }
)


def is_valid_sub_admin_seed(sub_admin_seed: str) -> Optional[ValueError]:
    try:
        account = Account(sub_admin_seed)
    except Exception as e:
        return e

def is_valid_sub_owner_seed(sub_owner_seed: str) -> Optional[ValueError]:
    try:
        account = Account(sub_owner_seed)
    except Exception as e:
        return e


# class PlaceholderHub:
#     """Placeholder class to make tests pass.

#     TODO Remove this placeholder class and replace with things from your PyPI package.
#     """

#     def __init__(self, host: str) -> None:
#         """Initialize."""
#         self.host = host

#     async def authenticate(self, username: str, password: str) -> bool:
#         """Test if we can authenticate with the host."""
#         return True


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    # TODO validate the data can be used to set up a connection.

    # If your PyPI package is not built with async, pass your methods
    # to the executor:
    if await hass.async_add_executor_job(is_valid_sub_admin_seed, data[CONF_USER_SEED]):
        raise InvalidSubAdminSeed
    if await hass.async_add_executor_job(is_valid_sub_owner_seed, data[CONF_SUB_OWNER_SEED]):
        raise InvalidSubOwnerSeed

    return {"title": "Robonomics"}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Robonomics Control."""

    VERSION = 1
    
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
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
        except InvalidSubOwnerSeed:
            errors["base"] = "invalid_sub_owner_seed"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"
        else:
            return self.async_create_entry(title=info["title"], data=user_input)

        # return self.async_create_entry(title=info["title"], data=user_input)
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
