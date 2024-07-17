"""File with functions for Home Assistant services"""

import asyncio
import logging
import os
import tempfile
import time
import typing as tp
from pathlib import Path

from homeassistant.components.camera.const import DOMAIN as CAMERA_DOMAIN
from homeassistant.components.camera.const import SERVICE_RECORD
from homeassistant.components.hassio import is_hassio
from homeassistant.core import HomeAssistant, ServiceCall
from robonomicsinterface import Account
from substrateinterface import Keypair, KeypairType

from .backup_control import (
    create_secure_backup,
    restore_from_backup,
    unpack_backup,
    create_secure_backup_hassio,
    restore_backup_hassio,
)
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
from .utils import delete_temp_file, encrypt_message, read_file_data, write_file_data

_LOGGER = logging.getLogger(__name__)


async def save_video(
    hass: HomeAssistant,
    target: tp.Dict[str, str],
    path: str,
    duration: int,
    sub_admin_acc: Account,
) -> None:
    """Record a video with given duration, save it in IPFS and Digital Twin

    :param hass: Home Assistant instance
    :param target: What should this service use as targeted areas, devices or entities. Usually it's camera entity ID.
    :param path: Path to save the video (must be also in configuration.yaml)
    :param duration: Duration of the recording in seconds
    :param sub_admin_acc: Controller account address
    """

    if path[-1] == "/":
        path = path[:-1]
    filename = f"video-{int(time.time())}.mp4"
    data = {"duration": duration, "filename": f"{path}/{filename}"}
    _LOGGER.debug(f"Started recording video {path}/{filename} for {duration} seconds")
    await hass.services.async_call(
        domain=CAMERA_DOMAIN,
        service=SERVICE_RECORD,
        service_data=data,
        target=target,
        blocking=True,
    )
    count = 0
    while not os.path.isfile(f"{path}/{filename}"):
        await asyncio.sleep(2)
        count += 1
        if count > 10:
            break
    if os.path.isfile(f"{path}/{filename}"):
        _LOGGER.debug(f"Start encrypt video {filename}")
        admin_keypair: Keypair = sub_admin_acc.keypair
        video_data = await hass.async_add_executor_job(read_file_data, f"{path}/{filename}", "rb")
        encrypted_data = encrypt_message(
            video_data, admin_keypair, admin_keypair.public_key
        )
        await hass.async_add_executor_job(write_file_data, f"{path}/{filename}", encrypted_data)
        await add_media_to_ipfs(hass, f"{path}/{filename}")
        folder_ipfs_hash = await get_folder_hash(hass, IPFS_MEDIA_PATH)
        # delete file from system
        _LOGGER.debug(f"delete original video {filename}")
        os.remove(f"{path}/{filename}")
        await hass.data[DOMAIN][ROBONOMICS].set_media_topic(
            folder_ipfs_hash, hass.data[DOMAIN][TWIN_ID]
        )


async def save_backup_service_call(
    hass: HomeAssistant, call: ServiceCall, sub_admin_acc: Account
) -> None:
    """Callback for save_backup_to_robonomics service.
    It creates secure backup, adds to IPFS and updates
    the Digital Twin topic.

    :param hass: HomeAssistant instance
    :param call: service call data
    :param sub_admin_acc: controller Robonomics account
    """

    if is_hassio(hass):
        encrypted_backup_path = await create_secure_backup_hassio(
            hass, sub_admin_acc.keypair
        )
    else:
        mosquitto_path = call.data.get("mosquitto_path")
        full = call.data.get("full")
        if mosquitto_path is None:
            mosquitto_path = "/etc/mosquitto"
        encrypted_backup_path, backup_path = await create_secure_backup(
            hass,
            Path(hass.config.path()),
            mosquitto_path,
            admin_keypair=sub_admin_acc.keypair,
            full=full,
        )
    ipfs_hash = await add_backup_to_ipfs(
        hass, str(encrypted_backup_path)
    )
    _LOGGER.debug(f"Backup created with hash {ipfs_hash}")
    delete_temp_file(encrypted_backup_path)
    # delete_temp_file(backup_path)
    await hass.data[DOMAIN][ROBONOMICS].set_backup_topic(
        ipfs_hash, hass.data[DOMAIN][TWIN_ID]
    )


async def restore_from_backup_service_call(
    hass: HomeAssistant, call: ServiceCall, sub_admin_acc: Account
) -> None:
    """Callback for restore_from_robonomics_backup service.
    It restores configuration file from backup.

    :param hass: HomeAssistant instance
    :param call: service call data
    :param sub_admin_acc: controller Robonomics account
    """

    try:
        hass.states.async_set(f"{DOMAIN}.backup", "Restoring")
        hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = True
        _LOGGER.debug("Start looking for backup ipfs hash")
        ipfs_backup_hash = await hass.data[DOMAIN][ROBONOMICS].get_backup_hash(
            hass.data[DOMAIN][TWIN_ID]
        )
        result = await get_ipfs_data(hass, ipfs_backup_hash)
        sub_admin_kp = Account(
            hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
        ).keypair
        if is_hassio(hass):
            await restore_backup_hassio(hass, result, sub_admin_kp)
        else:
            backup_path = f"{tempfile.gettempdir()}/{DATA_BACKUP_ENCRYPTED_NAME}"
            await hass.async_add_executor_job(write_file_data, backup_path, result)
            config_path = Path(hass.config.path())
            zigbee2mqtt_path = call.data.get("zigbee2mqtt_path")
            if zigbee2mqtt_path is None:
                zigbee2mqtt_path = "/opt/zigbee2mqtt"
            mosquitto_path = call.data.get("mosquitto_path")
            if mosquitto_path is None:
                mosquitto_path = "/etc/mosquitto"
            await unpack_backup(hass, Path(backup_path), sub_admin_kp)
            await restore_from_backup(
                hass, zigbee2mqtt_path, mosquitto_path, Path(hass.config.path())
            )
            _LOGGER.debug("Config restored, restarting...")
    except Exception as e:
        _LOGGER.error(f"Exception in restore from backup service call: {e}")
