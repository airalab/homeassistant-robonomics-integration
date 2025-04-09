from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.service import async_get_all_descriptions
from homeassistant.components.lovelace.const import DOMAIN as LOVELACE_DOMAIN

import json
import logging
import time
import tempfile
from copy import deepcopy

from ..ipfs import (
    add_config_to_ipfs,
    add_media_to_ipfs,
    read_ipfs_local_file,
)

from ..ipfs_helpers.utils import IPFSLocalUtils

from ..utils import (
    get_hash,
    format_libp2p_node_multiaddress,
    FileSystemUtils,
)

from ..const import (
    CONFIG_ENCRYPTED_PREFIX,
    CONFIG_PREFIX,
    DOMAIN,
    IPFS_CONFIG_PATH,
    ROBONOMICS,
    TWIN_ID,
    IPFS_MEDIA_PATH,
    CONF_SENDING_TIMEOUT,
    PEER_ID_LOCAL,
    LIBP2P_MULTIADDRESS,
)

_LOGGER = logging.getLogger(__name__)

class ConfigSender:
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._services_json: dict | None = None
        self._dashboard_json: dict | None = None
        self._libp2p_multiaddress: list | None = None
        self._peer_id: str | None = None
        self._robonomics = self._hass.data[DOMAIN][ROBONOMICS]

    async def send(self) -> None:
        _LOGGER.debug("Start send config")
        self._services_json = await self._get_services_json()
        dashboard_json = await self._get_dashboard_json()
        self._dashboard_json = await self._save_dashboard_media(dashboard_json)
        self._libp2p_multiaddress, self._peer_id = self._get_libp2p_multiaddress_and_peer_id()
        new_config = self._format_new_config()
        if await self._devices_changed() or await self._data_changed(new_config):
            ipfs_hash = await self._add_config_to_ipfs(new_config)
        else:
            _LOGGER.debug("Config wasn't changed")
            _, ipfs_hash = await IPFSLocalUtils(self._hass).get_last_file_hash(
                IPFS_CONFIG_PATH, CONFIG_ENCRYPTED_PREFIX
            )
        await self._robonomics.set_config_topic(ipfs_hash, self._hass.data[DOMAIN][TWIN_ID])

    async def _get_services_json(self) -> dict | None:
        try:
            entity_registry = er.async_get(self._hass)
            descriptions = json.loads(json.dumps(await async_get_all_descriptions(self._hass)))
            services_list = {}
            for entity in entity_registry.entities:
                entity_data = entity_registry.async_get(entity)
                platform = entity_data.entity_id.split(".")[0]
                if platform not in services_list and platform in descriptions:
                    services_list[platform] = descriptions[platform]
            return services_list
        except Exception as e:
            _LOGGER.error(f"Exception in get services list: {e}")

    async def _get_dashboard_json(self) -> dict | None:
        try:
            dashboard = self._hass.data[LOVELACE_DOMAIN]["dashboards"].get(None)
            config_dashboard_real = await dashboard.async_load(False)
            config_dashboard = deepcopy(config_dashboard_real)
            return config_dashboard
        except Exception as e:
            _LOGGER.warning(f"Exception in get dashboard: {e}")

    async def _save_dashboard_media(self, dashboard_json: dict) -> dict:
        try:
            for view in dashboard_json.get("views", []):
                for card in view.get("cards", []):
                    if "image" in card:
                        _LOGGER.debug(f"Image in config: {card['image']}")
                        image_path = card["image"]
                        if image_path[:6] == "/local":
                            image_path = image_path.replace("/local/", "")
                            filename = f"{self._hass.config.path()}/www/{image_path}"
                            ipfs_hash_media = await get_hash(filename)
                            card["image"] = ipfs_hash_media
                            if not await IPFSLocalUtils(self._hass).check_if_hash_in_folder(
                                ipfs_hash_media, IPFS_MEDIA_PATH
                            ):
                                await add_media_to_ipfs(self._hass, filename)
        except Exception as e:
            _LOGGER.warning(f"Exception in saving media from dashboard: {e}")
        return dashboard_json

    def _get_libp2p_multiaddress_and_peer_id(self) -> tuple[list, str]:
        peer_id = self._hass.data[DOMAIN].get(PEER_ID_LOCAL, "")
        local_libp2p_multiaddress = format_libp2p_node_multiaddress(peer_id)
        libp2p_multiaddress = self._hass.data[DOMAIN].get(LIBP2P_MULTIADDRESS, []).copy()
        libp2p_multiaddress.append(local_libp2p_multiaddress)
        return libp2p_multiaddress, peer_id

    def _format_new_config(self) -> dict:
        new_config = {
            "services": self._services_json,
            "dashboard": self._dashboard_json,
            "twin_id": self._hass.data[DOMAIN][TWIN_ID],
            "sending_timeout": self._hass.data[DOMAIN][CONF_SENDING_TIMEOUT].seconds,
            "peer_id": self._peer_id,
            "libp2p_multiaddress": self._libp2p_multiaddress,
        }
        return new_config

    async def _data_changed(self, new_config: dict) -> bool:
        last_config = await self._get_last_config_data()
        _LOGGER.debug(f"Data changed: {last_config != new_config}")
        return last_config != new_config

    async def _get_last_config_data(self) -> dict:
        last_config_hash, _ = await IPFSLocalUtils(self._hass).get_last_file_hash(IPFS_CONFIG_PATH, CONFIG_PREFIX)
        if last_config_hash is None:
            return {}
        last_config_data = await read_ipfs_local_file(self._hass, last_config_hash, IPFS_CONFIG_PATH)
        if last_config_data is None:
            last_config_data = {}
        return last_config_data

    async def _devices_changed(self) -> bool:
        last_devices = await self._get_last_config_devices()
        new_devices = self._get_new_config_devices()
        _LOGGER.debug(f"Devices changed: {last_devices != new_devices}")
        return last_devices != new_devices

    async def _get_last_config_devices(self) -> list:
        last_config_encrypted_hash, _ = await IPFSLocalUtils(self._hass).get_last_file_hash(IPFS_CONFIG_PATH, CONFIG_ENCRYPTED_PREFIX)
        if last_config_encrypted_hash is None:
            return []
        last_config_encrypted_data = await read_ipfs_local_file(self._hass, last_config_encrypted_hash, IPFS_CONFIG_PATH)
        if last_config_encrypted_data is None:
            last_config_devices = []
        else:
            last_config_devices = list(last_config_encrypted_data.keys())
            last_config_devices.remove("data")
            last_config_devices.sort()
        return last_config_devices

    def _get_new_config_devices(self) -> list:
        new_config_devices = self._robonomics.devices_list.copy()
        controller_address = self._robonomics.controller_address
        new_config_devices.append(controller_address)
        new_config_devices.sort()
        return new_config_devices

    async def _add_config_to_ipfs(self, config: dict) -> str | None:
        try:
            config_filename = await self._write_config_to_file(config)
            encrypted_config_filename = await self._encrypt_config_and_write_to_file(config)
            ipfs_hash = await add_config_to_ipfs(self._hass, config_filename, encrypted_config_filename)
            return ipfs_hash
        except Exception as e:
            _LOGGER.error(f"Exception in add config to IPFS: {e}")
        finally:
            await self._delete_temp_files(config_filename, encrypted_config_filename)

    async def _write_config_to_file(self, config: dict) -> str:
        dirname = tempfile.gettempdir()
        config_filename = f"{dirname}/config-{time.time()}"
        await FileSystemUtils(self._hass).write_file_data(config_filename, json.dumps(config))
        return config_filename

    async def _encrypt_config_and_write_to_file(self, config: dict) -> str:
        encrypted_config = self._robonomics.encrypt_for_devices(json.dumps(config))
        filename = await FileSystemUtils(self._hass).write_data_to_temp_file(encrypted_config, True)
        _LOGGER.debug(f"Encrypted config filename: {filename}")
        return filename

    async def _delete_temp_files(self, filename1: str, filename2: str) -> None:
        await FileSystemUtils(self._hass).delete_temp_file(filename1)
        await FileSystemUtils(self._hass).delete_temp_file(filename2)