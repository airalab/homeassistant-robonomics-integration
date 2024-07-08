import typing as tp
import logging

from tenacity import AsyncRetrying, wait_fixed, stop_after_attempt

from ...const import ROBONOMICS_WSS
from ..robonomics_accounts_model import RobonomicsAccounts

_LOGGER = logging.getLogger(__name__)

class RetryUtil:
    def __init__(self, accounts: RobonomicsAccounts) -> None:
        self._current_wss: str = ROBONOMICS_WSS[0]
        self._accounts: RobonomicsAccounts = accounts

    def retry_with_change_wss(func: tp.Awaitable) -> tp.Awaitable:
        async def wrapper(self, *args, **kwargs):
            async for attempt in AsyncRetrying(
                wait=wait_fixed(5), stop=stop_after_attempt(len(ROBONOMICS_WSS))
            ):
                with attempt:
                    try:
                        return await func(self, *args, **kwargs)
                    except TimeoutError:
                        self._change_current_wss()
                        raise TimeoutError
        return wrapper

    def _change_current_wss(self) -> None:
        next_wss = self._get_next_wss()
        self._accounts.change_account_wss(next_wss)

    def _get_next_wss(self) -> str:
        current_wss_index = ROBONOMICS_WSS.index(self._current_wss)
        if current_wss_index < len(ROBONOMICS_WSS) - 1:
            next_wss_index = current_wss_index + 1
        else:
            next_wss_index = 0
        return ROBONOMICS_WSS[next_wss_index]