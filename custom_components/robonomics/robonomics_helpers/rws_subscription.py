import asyncio
import typing as tp

from robonomicsinterface import Subscriber, SubEvent
from homeassistant.core import HomeAssistant
from aenum import extend_enum

from .utils.retry_util import RetryUtil
from .robonomics_accounts_model import RobonomicsAccounts
from .utils.extrinsic_data import (
    DatalogData,
    LaunchData,
    NewDevicesData,
    TopicChangedData,
    ExtrinsicData,
)

extend_enum(
    SubEvent,
    "MultiEvent",
    f"{SubEvent.NewRecord.value, SubEvent.NewLaunch.value, SubEvent.NewDevices.value, SubEvent.TopicChanged.value}",
)


class RWSSubscriptionHelper(RetryUtil):
    def __init__(self, hass: HomeAssistant, accounts: RobonomicsAccounts) -> None:
        super().__init__(accounts)
        self._accounts: RobonomicsAccounts = accounts
        self._hass: HomeAssistant = hass
        self._subscriber = Subscriber(
            self._accounts.controller_account, SubEvent.MultiEvent
        )
        self._subscription_callbacks: dict[SubEvent, list[tp.Awaitable]] = {}

    def add_callback(
        self,
        extrinsic_type: SubEvent,
        callback: tp.Awaitable,
        sender: str | None = None,
        receiver: str | None = None,
    ) -> None:
        callback_info = {"callback": callback, "sender": sender, "receiver": receiver}
        if extrinsic_type in self._subscription_callbacks:
            self._subscription_callbacks[extrinsic_type].append(callback_info)
        else:
            self._subscription_callbacks[extrinsic_type] = [callback_info]

    def _subscription_callback(self, data: dict) -> None:
        format_data = self._get_format_data(data)
        if format_data.extrinsic_type in self._subscription_callbacks:
            for callback_info in self._subscription_callbacks[
                format_data.extrinsic_type
            ]:
                if self._check_sender(
                    format_data, callback_info["sender"]
                ) and self._check_receiver(format_data, callback_info["receiver"]):
                    asyncio.run_coroutine_threadsafe(
                        callback_info["callback"](self._hass, format_data),
                        self._hass.loop,
                    )

    def _get_format_data(self, data: dict) -> ExtrinsicData:
        if DatalogData.check(data):
            return DatalogData(data)
        elif LaunchData.check(data):
            return LaunchData(data)
        elif NewDevicesData.check(data):
            return NewDevicesData(data)
        elif TopicChangedData.check(data):
            return TopicChangedData(data)
        else:
            raise Exception("Got Robonomics event with unsupported type")

    def _check_sender(self, extrinsic_data: ExtrinsicData, sender: str | None) -> bool:
        if sender is None:
            return True
        return extrinsic_data.sender == sender

    def _check_receiver(
        self, extrinsic_data: ExtrinsicData, receiver: str | None
    ) -> bool:
        if receiver is None or not isinstance(extrinsic_data, LaunchData):
            return True
        return extrinsic_data.receiver == receiver
