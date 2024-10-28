from homeassistant.core import HomeAssistant, callback, Event
from homeassistant.helpers.event import async_track_time_interval
from datetime import timedelta
import logging
import asyncio

from .config_sender import ConfigSender
from .states_sender import StatesSender
from ..const import DOMAIN, TWIN_ID

_LOGGER = logging.getLogger(__name__)

class Telemetry:
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._timer_unsub = None
        self._telemetry_is_sending = False
        self._queue_last_position: int = 0

    def setup(self, sending_timeout: timedelta) -> None:
        _LOGGER.debug(f"Setup telemetry timer with timeout {sending_timeout}")
        self.unload()
        self._set_timer(sending_timeout)

    def unload(self) -> None:
        if self._timer_unsub is not None:
            _LOGGER.debug("Unload telemetry sender")
            self._timer_unsub()

    async def send(self) -> None:
        if TWIN_ID not in self._hass.data[DOMAIN]:
            _LOGGER.debug("Trying to send telemetry before creating twin id")
            return
        should_send = await self._wait_for_the_queue()
        if should_send:
            _LOGGER.debug("Start send telemetry")
            await self._send()

    async def _send(self) -> None:
        await ConfigSender(self._hass).send()
        await StatesSender(self._hass).send()
        self._telemetry_is_sending = False

    def _set_timer(self, sending_timeout: timedelta) -> None:
        self._timer_unsub = async_track_time_interval(self._hass, self._timer_callback, sending_timeout)

    @callback
    def _timer_callback(self, event: Event) -> None:
        _LOGGER.debug(f"Time changed event for telemetry: {event}")
        self._hass.loop.create_task(self.send())

    async def _wait_for_the_queue(self) -> bool:
        if not self._telemetry_is_sending:
            self._telemetry_is_sending = True
            return True
        _LOGGER.debug("Another states are sending. Wait...")
        self._queue_last_position += 1
        queue_position = self._queue_last_position
        if queue_position > 3:
            _LOGGER.debug(
                "Another states are sending too long. Start getting states..."
            )
            self._queue_last_position = 0
            return True
        while self._telemetry_is_sending:
            await asyncio.sleep(5)
            if queue_position < self._queue_last_position:
                _LOGGER.debug("Stop waiting to send states")
                return False
        return True