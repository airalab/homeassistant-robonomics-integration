"""File with functions for Home Assistant services"""

import logging
import tempfile
import time
import os
import typing as tp
from pathlib import Path
import asyncio

from homeassistant.components.camera.const import DOMAIN as CAMERA_DOMAIN
from homeassistant.components.camera.const import SERVICE_RECORD
from homeassistant.core import HomeAssistant, ServiceCall
from robonomicsinterface import Account
from substrateinterface import Keypair, KeypairType

from .backup_control import create_secure_backup, restore_from_backup, unpack_backup
from .const import (
    CONF_ADMIN_SEED,
    DATA_BACKUP_ENCRYPTED_NAME,
    DOMAIN,
    HANDLE_IPFS_REQUEST,
    IPFS_MEDIA_PATH,
    ROBONOMICS,
    TWIN_ID,
)
from .ipfs import add_backup_to_ipfs, add_media_to_ipfs, get_folder_hash, get_ipfs_data
from .utils import delete_temp_file

_LOGGER = logging.getLogger(__name__)


async def save_video(hass: HomeAssistant, target: tp.Dict[str, str], path: str, duration: int) -> None:
    """Record a video with given duration, save it in IPFS and Digital Twin

    :param hass: Home Assistant instance
    :param entity_id: ID of the camera entity
    :param path: Path to save the video (must be also in configuration.yaml)
    :param duration: Duration of the recording in seconds
    """

    if path[-1] == "/":
        path = path[:-1]
    filename = f"video-{int(time.time())}.mp4"
    data = {"duration": duration, "filename": f"{path}/{filename}"}
    _LOGGER.debug(f"Started recording video {path}/{filename} for {duration} seconds")
    res = await hass.services.async_call(
        domain=CAMERA_DOMAIN, service=SERVICE_RECORD, service_data=data, target=target, blocking=True
    )
    count = 0
    while not os.path.isfile(f"{path}/{filename}"):
        await asyncio.sleep(2)
        count += 1
        if count > 10:
            break
    if os.path.isfile(f"{path}/{filename}"):
        video_ipfs_hash = await add_media_to_ipfs(hass, f"{path}/{filename}")
        folder_ipfs_hash = await get_folder_hash(IPFS_MEDIA_PATH)
        await hass.data[DOMAIN][ROBONOMICS].set_media_topic(folder_ipfs_hash, hass.data[DOMAIN][TWIN_ID])


async def save_backup_service_call(hass: HomeAssistant, call: ServiceCall, sub_admin_acc: Account) -> None:
    """Callback for save_backup_to_robonomics service.
    It creates secure backup, adds to IPFS and updates
    the Digital Twin topic.

    :param hass: HomeAssistant instance
    :param call: service call data
    :param sub_admin_acc: controller Robonomics account
    """

    zigbee2mqtt_path = call.data.get("zigbee2mqtt_path")
    if zigbee2mqtt_path is None:
        zigbee2mqtt_path = "/opt/zigbee2mqtt"
    _LOGGER.debug(f"Zigbee2mqtt path in creating backup: {zigbee2mqtt_path}")
    encrypted_backup_path, backup_path = await create_secure_backup(
        hass,
        Path(hass.config.path()),
        zigbee2mqtt_path,
        admin_keypair=sub_admin_acc.keypair,
    )
    ipfs_hash = await add_backup_to_ipfs(hass, str(backup_path), str(encrypted_backup_path))
    _LOGGER.debug(f"Backup created on {backup_path} with hash {ipfs_hash}")
    delete_temp_file(encrypted_backup_path)
    delete_temp_file(backup_path)
    await hass.data[DOMAIN][ROBONOMICS].set_backup_topic(ipfs_hash, hass.data[DOMAIN][TWIN_ID])


async def restore_from_backup_service_call(hass: HomeAssistant, call: ServiceCall, sub_admin_acc: Account) -> None:
    """Callback for restore_from_robonomics_backup service.
    It restores configuration file from backup.

    :param hass: HomeAssistant instance
    :param call: service call data
    :param sub_admin_acc: controller Robonomics account
    """

    try:
        config_path = Path(hass.config.path())
        backup_encrypted_path = call.data.get("backup_path")
        zigbee2mqtt_path = call.data.get("zigbee2mqtt_path")
        if zigbee2mqtt_path is None:
            zigbee2mqtt_path = "/opt/zigbee2mqtt"
        hass.states.async_set(f"{DOMAIN}.backup", "Restoring")
        if backup_encrypted_path is None:
            hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = True
            _LOGGER.debug("Start looking for backup ipfs hash")
            ipfs_backup_hash = await hass.data[DOMAIN][ROBONOMICS].get_backup_hash(hass.data[DOMAIN][TWIN_ID])
            result = await get_ipfs_data(hass, ipfs_backup_hash, 0)
            backup_path = f"{tempfile.gettempdir()}/{DATA_BACKUP_ENCRYPTED_NAME}"
            with open(backup_path, "w") as f:
                f.write(result)
            sub_admin_kp = Keypair.create_from_mnemonic(
                hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
            )
            await unpack_backup(hass, Path(backup_path), sub_admin_kp)
            await restore_from_backup(hass, zigbee2mqtt_path, Path(hass.config.path()))
        else:
            backup_path = await unpack_backup(hass, backup_encrypted_path, sub_admin_acc.keypair)
            await restore_from_backup(hass, zigbee2mqtt_path, config_path)
            _LOGGER.debug(f"Config restored, restarting...")
    except Exception as e:
        _LOGGER.error(f"Exception in restore from backup service call: {e}")
