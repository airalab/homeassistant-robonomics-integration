import logging
import json

from homeassistant.core import HomeAssistant


_LOGGER = logging.getLogger(__name__)

from ..const import DOMAIN, ROBONOMICS
from ..utils import delete_temp_file, write_data_to_temp_file
from ..ipfs import add_telemetry_to_ipfs
from ..hass_helpers import HassStatesHelper

class StatesSender:
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._robonomics = self._hass.data[DOMAIN][ROBONOMICS]

    async def send(self) -> None:
        _LOGGER.debug("Start send states")
        states_json = await HassStatesHelper(self._hass).get_states()
        encrypted_states = self._robonomics.encrypt_for_devices(json.dumps(states_json))
        filename = await self._hass.async_add_executor_job(
            write_data_to_temp_file, encrypted_states
        )
        ipfs_hash = await add_telemetry_to_ipfs(self._hass, filename)
        delete_temp_file(filename)
        await self._robonomics.send_datalog_states(ipfs_hash)
