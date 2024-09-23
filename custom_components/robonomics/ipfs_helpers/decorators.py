from __future__ import annotations

import functools
import logging
import typing as tp

from homeassistant.core import HomeAssistant

from ..const import DOMAIN, IPFS_STATUS, IPFS_STATUS_ENTITY

_LOGGER = logging.getLogger(__name__)


def catch_ipfs_errors(error_message: str = ""):
    def catch_ipfs_errors_decorator(func: tp.Callable):
        @functools.wraps(func)
        def wrapper(obj, *args, **kwargs):
            if isinstance(obj, HomeAssistant):
                hass = obj
            else:
                hass = obj.hass
            try:
                res = func(obj, *args, **kwargs)
                hass.data[DOMAIN][IPFS_STATUS] = "OK"
                hass.states.async_set(
                    f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
                )
                return res
            except Exception as e:
                _LOGGER.error(f"{error_message}: {e}")
                hass.data[DOMAIN][IPFS_STATUS] = "Error"
                hass.states.async_set(
                    f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
                )

        return wrapper

    return catch_ipfs_errors_decorator
