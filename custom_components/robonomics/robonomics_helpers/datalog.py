import logging

from robonomicsinterface import Datalog
from homeassistant.core import HomeAssistant

from .robonomics_accounts_model import RobonomicsAccounts
from .utils.retry_util import RetryUtil

_LOGGER = logging.getLogger(__name__)


class DatalogHelper(RetryUtil):
    def __init__(self, hass: HomeAssistant, accounts: RobonomicsAccounts) -> None:
        super().__init__(accounts)
        self._hass: HomeAssistant = hass
        self._accounts: RobonomicsAccounts = accounts
        self._datalog: Datalog = Datalog(
            self._accounts.controller_account,
            rws_sub_owner=self._accounts.owner_address,
        )

    @RetryUtil.retry_with_change_wss
    async def send_datalog(self, ipfs_hash: str) -> None:
        await self._hass.async_add_executor_job(self._send_datalog, ipfs_hash)

    async def get_last_datalog(self, address: str) -> str:
        datalogs = await self.get_n_last_datalogs(address, datalogs_count=1)
        return datalogs[0]

    async def get_n_last_datalogs(self, address: str, datalogs_count: int) -> list[str]:
        datalogs = []
        last_datalog_index = await self._get_last_datalog_index_async(address)
        _LOGGER.debug(f"Last index for address {address}: {last_datalog_index}")
        for i in range(datalogs_count):
            datalog_index = last_datalog_index - i
            datalog_data = await self._get_datalog_item_async(address, datalog_index)
            if datalog_data is not None:
                datalogs.append(datalog_data)
        return datalogs

    def _send_datalog(self, ipfs_hash: str) -> None:
        _LOGGER.debug(f"Start creating datalog with ipfs hash: {ipfs_hash}")
        receipt = self._datalog.record(ipfs_hash)
        _LOGGER.debug(f"Datalog created with hash: {receipt}")

    @RetryUtil.retry_with_change_wss
    async def _get_last_datalog_index_async(self, address: str) -> dict:
        indexes = await self._hass.async_add_executor_job(
            self._datalog.get_index, address
        )
        return indexes["end"] - 1

    @RetryUtil.retry_with_change_wss
    async def _get_datalog_item_async(self, address: str, index: int) -> dict | None:
        if index >= 0:
            datalog_data = await self._hass.async_add_executor_job(
                self._datalog.get_item, address, index
            )
            if datalog_data is not None:
                return datalog_data[1]
