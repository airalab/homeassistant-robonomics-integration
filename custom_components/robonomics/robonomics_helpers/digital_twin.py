import logging

from robonomicsinterface import DigitalTwin
from robonomicsinterface.utils import ipfs_qm_hash_to_32_bytes, ipfs_32_bytes_to_qm_hash
from homeassistant.core import HomeAssistant

from .robonomics_accounts_model import RobonomicsAccounts
from .utils.retry_util import RetryUtil
from ..const import ZERO_ACC

_LOGGER = logging.getLogger(__name__)


class DigitalTwinHelper(RetryUtil):
    def __init__(
        self, hass: HomeAssistant, accounts: RobonomicsAccounts, twin_id: int = None
    ) -> None:
        super().__init__(accounts)
        self._hass: HomeAssistant = hass
        self._accounts: RobonomicsAccounts = accounts
        self._twin_id: int | None = twin_id
        self._digital_twin: DigitalTwin = DigitalTwin(
            self._accounts.controller_account,
            rws_sub_owner=self._accounts.owner_address,
        )

    @RetryUtil.retry_with_change_wss
    async def create_digital_twin(self) -> None:
        await self._hass.async_add_executor_job(self._create_digital_twin)

    async def remove_topic_for_address(self, address: str) -> None:
        _LOGGER.debug(f"Start removing twin topic for address {address}")
        info = await self._get_twin_info_async()
        if info is not None:
            for topic in info:
                if topic[1] == address:
                    bytes_hash = topic[0]
                    break
            else:
                _LOGGER.debug(f"Twin topic for address {address} does not exist")
                return
        await self._remove_topic_async(bytes_hash)

    async def set_or_change_topic(self, address: str, ipfs_hash: str) -> None:
        bytes_hash = ipfs_qm_hash_to_32_bytes(ipfs_hash)
        info = await self._get_twin_info_async()
        if info is not None:
            for topic in info:
                if topic[0] == bytes_hash:
                    if topic[1] == address:
                        _LOGGER.debug(
                            f"Topic for address {address} with this ipfs hash exists"
                        )
                        return
                if topic[1] == address:
                    await self._remove_topic_async(topic[0])
        await self._set_topic_async(bytes_hash, address)

    async def get_ipfs_hash_for_address(self, address: str) -> str | None:
        info = await self._get_twin_info_async()
        if info is not None:
            for topic in info:
                if topic[1] == address:
                    backup_hash = ipfs_32_bytes_to_qm_hash(topic[0])
                    _LOGGER.debug(f"Ipfs hash for address {address}: {backup_hash}")
                    return backup_hash
            else:
                _LOGGER.debug(f"No topic for address {address} was found")
                return None

    def get_twin_id(self) -> int:
        return self._twin_id

    def _create_digital_twin(self) -> None:
        self._twin_id, _ = self._digital_twin.create()

    async def _remove_topic_async(self, bytes_hash: str) -> None:
        await self._set_topic_async(ZERO_ACC, bytes_hash)

    @RetryUtil.retry_with_change_wss
    async def _get_twin_info_async(self) -> list:
        return await self._hass.async_add_executor_job(self._get_twin_info)

    def _get_twin_info(self) -> list:
        return self._digital_twin.get_info(self._twin_id)
    
    @RetryUtil.retry_with_change_wss
    async def _set_topic_async(self, address: str, bytes_hash: str) -> None:
        await self._hass.async_add_executor_job(self._set_topic, address, bytes_hash)

    def _set_topic(self, address: str, bytes_hash: str) -> None:
        self._digital_twin.set_source(self._twin_id, bytes_hash, address)
