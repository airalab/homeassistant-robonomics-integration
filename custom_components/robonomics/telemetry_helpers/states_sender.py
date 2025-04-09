import json
import logging

from homeassistant.core import HomeAssistant

from ..const import DOMAIN, ROBONOMICS
from ..hass_helpers import HassStatesHelper
from ..ipfs import add_telemetry_to_ipfs
from ..utils import FileSystemUtils

_LOGGER = logging.getLogger(__name__)

class StatesSender:
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._robonomics = self._hass.data[DOMAIN][ROBONOMICS]

    async def send(self) -> None:
        _LOGGER.debug("Start send states")
        states_json = await HassStatesHelper(self._hass).get_states()
        encrypted_states = self._robonomics.encrypt_for_devices(json.dumps(states_json))
        filename = await FileSystemUtils(self._hass).write_data_to_temp_file(encrypted_states)
        ipfs_hash = await add_telemetry_to_ipfs(self._hass, filename)
        await FileSystemUtils(self._hass).delete_temp_file(filename)
        await self._robonomics.send_datalog_states(ipfs_hash)
