from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.core import HomeAssistant
from collections.abc import AsyncIterator, Callable, Coroutine
import logging
from aiohttp import FormData
import aiofiles
import typing as tp
from pathlib import Path

from ...const import DOMAIN, CONF_PINATA_PUB, CONF_PINATA_SECRET

_LOGGER = logging.getLogger(__name__)

class PinataGateway:
    """Pinata Gateway class."""

    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._pinata_host: str = "https://api.pinata.cloud/"
        self._auth_headers: dict = {
            "pinata_api_key": hass.data[DOMAIN].get(CONF_PINATA_PUB),
            "pinata_secret_api_key": hass.data[DOMAIN].get(CONF_PINATA_SECRET),
        }
        self._session = async_create_clientsession(self._hass, auto_cleanup=False)

    async def add(self, filename: str, pin: bool, last_file_hash: str | None = None) -> tuple[str | None, int | None]:
        """Add a file to the IPFS node using Pinata."""
        ipfs_hash = None
        ipfs_file_size = None
        if not pin and last_file_hash is not None:
            await self._remove(last_file_hash)
        try:
            _LOGGER.debug("Start add file to Pinata: %s", filename)
            async with aiofiles.open(filename, "rb") as f:
                file_data = await f.read()
            form = FormData()
            form.add_field(
                name="file",
                value=file_data,
                filename=filename.split("/")[-1],
                content_type="application/octet-stream",
            )
            res_json = await self._post("pinning/pinFileToIPFS", form_data=form)
            ipfs_hash = res_json.get("IpfsHash")
            ipfs_file_size = res_json.get("PinSize")
            _LOGGER.debug("Response from Pinata: %s", res_json)

        except Exception as e:
            _LOGGER.error("Error adding file to Pinata: %s", e)
            return None, None
        finally:
            self._session.detach()

        return ipfs_hash, ipfs_file_size

    async def add_from_stream(self, open_stream: Callable[[], Coroutine[tp.Any, tp.Any, AsyncIterator[bytes]]], filename: str) -> tuple[str | None, int | None]:
        """Add a file to the IPFS node using Pinata."""
        ipfs_hash = None
        ipfs_file_size = None
        try:
            _LOGGER.debug("Start add file stream to Pinata")
            stream = await open_stream()
            form = FormData()
            form.add_field(
                name="file",
                value=stream,
                filename=filename,
                content_type="application/octet-stream",
            )
            res_json = await self._post("pinning/pinFileToIPFS", form_data=form)
            ipfs_hash = res_json.get("IpfsHash")
            ipfs_file_size = res_json.get("PinSize")
            _LOGGER.debug("Response from Pinata: %s", res_json)

        except Exception as e:
            _LOGGER.error("Error adding file to Pinata: %s", e)
            return None, None
        finally:
            self._session.detach()

        return ipfs_hash, ipfs_file_size

    async def add_json(self, json_data: dict) -> str | None:
        """Add JSON data to the IPFS node using Pinata."""
        try:
            _LOGGER.debug("Start add JSON to Pinata: %s", json_data)
            res_json = await self._post("pinning/pinJSONToIPFS", json_data=json_data)
            ipfs_hash = res_json.get("IpfsHash")
            _LOGGER.debug("Response from Pinata: %s", res_json)
        except Exception as e:
            _LOGGER.error("Error adding JSON to Pinata: %s", e)
            return None
        finally:
            self._session.detach()

        return ipfs_hash

    async def remove(self, ipfs_hash: str) -> bool:
        """Remove a file from the IPFS node using Pinata."""
        try:
            return await self._remove(ipfs_hash)
        except Exception as e:
            _LOGGER.error("Error removing file from Pinata: %s", e)
        finally:
            self._session.detach()

    async def _remove(self, ipfs_hash: str) -> bool:
        _LOGGER.debug("Start remove file from Pinata with hash: %s", ipfs_hash)
        url = self._pinata_host + "pinning/unpin/" + ipfs_hash
        headers = {"Content-Type": "application/json"}
        headers.update(self._auth_headers)
        res = await self._session.delete(
            url,
            headers=headers,
            data={},
        )
        res_text = await res.text()
        _LOGGER.debug("Response from Pinata delete request: %s", res_text)
        return res_text == "OK"

    async def _post(self, method: str, form_data: FormData | None = None, json_data: dict | None = None) -> dict | None:
        """Post a request to the Pinata API."""
        url = self._pinata_host + method
        if form_data:
            res = await self._session.post(url, headers=self._auth_headers, data=form_data)
        elif json_data:
            res = await self._session.post(url, headers=self._auth_headers, json=json_data)
        else:
            _LOGGER.error("No form data or JSON data provided to Pinata POST request")
            return None
        return await res.json()
