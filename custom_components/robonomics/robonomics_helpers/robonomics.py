import typing as tp
import logging

from homeassistant.core import HomeAssistant
from robonomicsinterface import SubEvent

from .utils.extrinsic_data import LaunchData, DatalogData, NewDevicesData, TopicChangedData

from .robonomics_accounts_model import RobonomicsAccounts
from .datalog import DatalogHelper
from .digital_twin import DigitalTwinHelper
from .rws_devices import RWSDevicesHelper
from .rws_subscription import RWSSubscriptionHelper

_LOGGER = logging.getLogger(__name__)

class Robonomcis:
    def __init__(self, hass: HomeAssistant, accounts: RobonomicsAccounts) -> None:
        self._hass: HomeAssistant = hass
        self._accounts: RobonomicsAccounts = accounts
        self._datalog_helper = DatalogHelper(hass, accounts)
        self._rws_devices_helper = RWSDevicesHelper(hass, accounts)
        self._rws_subscription_helper = RWSSubscriptionHelper(hass, accounts)
        self._digital_twin_helper: DigitalTwinHelper | None = None

    async def async_setup(self) -> None:
        await self._rws_devices_helper.update_devices_list_from_chain()

    async def async_set_or_create_digital_twin(self, twin_id: int | None = None) -> None:
        self._digital_twin_helper = DigitalTwinHelper(self._hass, self._accounts, twin_id)
        if twin_id is None:
            await self._digital_twin_helper.create_digital_twin()

    def subscribe_for_launch_commands(self, callback: tp.Awaitable) -> None:
        self._rws_subscription_helper.add_callback(SubEvent.NewLaunch, callback, self._check_launch_command)

    def subscribe_for_password_change(self, callback: tp.Awaitable) -> None:
        self._rws_subscription_helper.add_callback(SubEvent.NewLaunch, callback, self._check_password_change)

    def _check_launch_command(self, data: LaunchData) -> bool:
        receiver_is_controller = data.receiver == self._accounts.controller_address
        sender_is_in_devices = data.sender in self._rws_devices_helper.get_devices()
        if not sender_is_in_devices:
            _LOGGER.debug(f"Got launch from not linked device: {data.sender}")
        return receiver_is_controller and sender_is_in_devices
        

    


