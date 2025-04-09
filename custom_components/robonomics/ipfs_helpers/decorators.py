from __future__ import annotations

import typing as tp
import logging
import functools
import aioipfs
import async_timeout

from homeassistant.core import HomeAssistant

from ..const import (
    DOMAIN,
    IPFS_STATUS,
    IPFS_STATUS_ENTITY,
)

_LOGGER = logging.getLogger(__name__)

def ensure_client(func: tp.Callable):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        client = kwargs.get("client")
        if client is not None:
            return await func(*args, **kwargs)

        async with aioipfs.AsyncIPFS() as temp_client:
            kwargs["client"] = temp_client
            return await func(*args, **kwargs)

    return wrapper

def set_timeout(timeout: int):
    def set_timeout_decorator(func: tp.Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            async with async_timeout.timeout(timeout):
                return await func(*args, **kwargs)

        return wrapper

    return set_timeout_decorator

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

def catch_ipfs_errors_async(error_message: str = ""):
    def catch_ipfs_errors_decorator(func: tp.Callable):
        @functools.wraps(func)
        async def wrapper(obj, *args, **kwargs):
            if isinstance(obj, HomeAssistant):
                hass = obj
            else:
                hass = obj.hass
            try:
                res = await func(obj, *args, **kwargs)
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