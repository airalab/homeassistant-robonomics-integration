"""Adds config flow for Robonomics control."""
from copy import deepcopy
import logging
from typing import Any, Dict, Optional

from homeassistant import config_entries, core
from homeassistant.const import CONF_ACCESS_TOKEN, CONF_NAME, CONF_PATH, CONF_URL
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_registry import (
    async_entries_for_config_entry,
    async_get_registry,
)
import voluptuous as vol
from homeassistant import data_entry_flow
from .const import CONF_REPOS, DOMAIN

_LOGGER = logging.getLogger(__name__)

class RoboConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    async def async_step_user(self, user_input):
        if user_input is not None:
            self.data = user_input
            return self.async_create_entry(title="Robonomics Control", data=self.data)

        return self.async_show_form(
            step_id="user", data_schema=vol.Schema({vol.Required("seed"): str})
        )