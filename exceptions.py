"""Custom exceptions for the Robonomics integration."""
from homeassistant.exceptions import HomeAssistantError

class InvalidSubAdminSeed(HomeAssistantError):
    """Given sub admin seed is not correct """

class InvalidSubOwnerSeed(HomeAssistantError):
    """Given subscription owner seed is not correct """