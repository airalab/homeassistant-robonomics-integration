from robonomicsinterface import RWS
from homeassistant.core import HomeAssistant

from .utils.retry_util import RetryUtil
from .robonomics_accounts_model import RobonomicsAccounts


class RWSDevicesHelper(RetryUtil):
    def __init__(self, hass: HomeAssistant, accounts: RobonomicsAccounts) -> None:
        super().__init__(accounts)
        self._accounts: RobonomicsAccounts = accounts
        self._hass: HomeAssistant = hass
        self._rws: RWS = RWS(self._accounts.controller_account)
        self._devices_list: list[str] = []

    def get_devices(self, exclude_controller: bool = False, exclude_owner: bool = False) -> list[str]:
        devices = self._devices_list.copy()
        if exclude_owner:
            devices.remove(self._accounts.owner_address)
        if exclude_controller:
            devices.remove(self._accounts.controller_address)
        return devices
    
    @RetryUtil.retry_with_change_wss
    async def update_devices_list_from_chain(self) -> None:
        self._devices_list = await self._hass.async_add_executor_job(
            self._rws.get_devices(self._accounts.owner_address)
        )

    def set_new_devices_list(self, devices_list: list[str]) -> None:
        self._devices_list = devices_list.copy()
