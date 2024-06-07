from __future__ import annotations

import asyncio
import logging
import typing as tp

import ipfshttpclient2
from aiohttp import ClientResponse
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
import tarfile
from io import BytesIO

from ..const import (
    CONF_IPFS_GATEWAY,
    DOMAIN,
    IPFS_GATEWAY,
    MAX_NUMBER_OF_REQUESTS,
    MORALIS_GATEWAY,
    PINATA_GATEWAY,
    CRUST_GATEWAY_1,
    CRUST_GATEWAY_2,
)
from ..utils import to_thread, delete_temp_dir_if_exists
from .decorators import catch_ipfs_errors

_LOGGER = logging.getLogger(__name__)


class GetIPFSData:
    def __init__(
        self,
        hass: HomeAssistant,
        ipfs_hash: str,
        number_of_requests: int = MAX_NUMBER_OF_REQUESTS,
    ):
        self.hass = hass
        self.websession = async_create_clientsession(hass)
        self.request_number = 0
        self.handle_ipfs_request = True
        self.ipfs_hash = ipfs_hash
        self.gateways = self._get_gateways_list()
        self.max_number_of_requests = number_of_requests

    async def get_file_data(self) -> tp.Optional[str]:
        res = await self._get_ipfs_data(is_directory=False)
        result_text = None
        if res is not None:
            if isinstance(res, str):
                result_text = res
            elif isinstance(res, ClientResponse):
                result_text = await res.text()
            else:
                _LOGGER.error(
                    f"Unexpected result from get ipfs data with type {type(res)}"
                )
        return result_text

    async def get_directory_to_given_path(
        self, dir_with_path: str
    ) -> tp.Optional[bool]:
        delete_temp_dir_if_exists(dir_with_path)
        res = await self._get_ipfs_data(is_directory=True)
        if res is not None:
            await self._extract_archive(res, dir_with_path)
            return True
        else:
            return False

    def _get_gateways_list(self) -> tp.List[str]:
        gateways = [
            IPFS_GATEWAY,
            MORALIS_GATEWAY,
            PINATA_GATEWAY,
            CRUST_GATEWAY_1,
            CRUST_GATEWAY_2,
        ]
        if CONF_IPFS_GATEWAY in self.hass.data[DOMAIN]:
            gateways.append(self.hass.data[DOMAIN][CONF_IPFS_GATEWAY])
        return gateways

    async def _get_ipfs_data(self, is_directory: bool) -> tp.Optional[ClientResponse]:
        if self.request_number >= self.max_number_of_requests:
            return None
        try:
            tasks = self._create_tasks(is_directory)
            for task in asyncio.as_completed(tasks):
                res = await task
                if res:
                    return res
            else:
                if self.handle_ipfs_request:
                    self.request_number += 1
                    res = await self._get_ipfs_data(is_directory)
                    return res
        except Exception as e:
            _LOGGER.error(f"Exception in get ipfs: {e}")
            if self.handle_ipfs_request:
                self.request_number += 1
                res = await self._get_ipfs_data(is_directory)
                return res

    def _create_tasks(self, is_directory: bool) -> tp.List[tp.Coroutine]:
        tasks = []
        if not is_directory:
            tasks.append(self._get_from_local_node_by_hash())
        for gateway in self.gateways:
            url = self._format_gateway_url(gateway)
            tasks.append(self._get_request(url, is_directory))
        if CONF_IPFS_GATEWAY in self.hass.data[DOMAIN]:
            custom_gateway = self.hass.data[DOMAIN][CONF_IPFS_GATEWAY]
            if custom_gateway is not None:
                url = self._format_gateway_url(custom_gateway)
                tasks.append(self._get_request(url, is_directory))
        return tasks

    def _format_gateway_url(self, gateway_url: str) -> str:
        if gateway_url[-1] != "/":
            gateway_url += "/"
        if gateway_url[-5:] != "ipfs/":
            gateway_url += "ipfs/"
        url = f"{gateway_url}{self.ipfs_hash}"
        return url

    @to_thread
    @catch_ipfs_errors("Exception in get from local node by hash")
    def _get_from_local_node_by_hash(self) -> tp.Optional[str]:
        with ipfshttpclient2.connect() as client:
            res = client.cat(self.ipfs_hash)
            res_str = res.decode()
            _LOGGER.debug(f"Got data {self.ipfs_hash} from local gateway")
            return res_str

    async def _get_request(
        self,
        url: str,
        is_directory: bool,
    ) -> tp.Optional[ClientResponse]:
        """Provide async get request to given IPFS gateway.

        :param url: URL with IPFS gateway + IPFS hash of file
        :param is_directory: if requested data is directory, request data in tar format

        :return: Response from get request
        """

        if is_directory:
            url += "?format=tar"
        _LOGGER.debug(f"Request to {url}")
        try:
            resp = await self.websession.get(url)
        except Exception as e:
            _LOGGER.warning(f"Exception - {e} in request to {url}")
            return None
        _LOGGER.debug(f"Response from {url} is {resp.status}")
        if resp.status == 200:
            if self.handle_ipfs_request:
                self.handle_ipfs_request = False
                return resp
            else:
                return None
        else:
            return None

    async def _extract_archive(self, response: ClientResponse, dir_with_path: str):
        tar_buffer = BytesIO()
        tar_content = await response.content.read()
        tar_buffer.write(tar_content)
        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:*") as tar:
            subdir_and_files = []
            for tarinfo in tar.getmembers():
                if tarinfo.name.startswith(f"{self.ipfs_hash}/"):
                    tarinfo.path = tarinfo.path.replace(f"{self.ipfs_hash}/", "")
                    subdir_and_files.append(tarinfo)
            tar_buffer.seek(0)
            tar.extractall(members=subdir_and_files, path=dir_with_path)
