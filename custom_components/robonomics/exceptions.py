"""Custom exceptions for the Robonomics integration."""
from homeassistant.exceptions import HomeAssistantError


class InvalidSubAdminSeed(HomeAssistantError):
    """Given sub admin seed is not correct"""


class InvalidSubOwnerAddress(HomeAssistantError):
    """Given subscription owner address is not correct"""
