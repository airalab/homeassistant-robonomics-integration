"""File with functions for Home Assistant services"""

import asyncio
import logging
import os
import tempfile
import time
import typing as tp
from pathlib import Path
import json

from homeassistant.components.camera.const import DOMAIN as CAMERA_DOMAIN
from homeassistant.components.camera.const import SERVICE_RECORD
from homeassistant.components.hassio import is_hassio
from homeassistant.core import HomeAssistant, ServiceCall
from robonomicsinterface import Account
from substrateinterface import Keypair, KeypairType

from homeassistant.components.hassio import is_hassio

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
    LOG_FILE_NAME,
    TRACES_FILE_NAME,
    IPFS_PROBLEM_REPORT_FOLDER,
    PROBLEM_SERVICE_ROBONOMICS_ADDRESS,
)
from .ipfs import add_backup_to_ipfs, add_media_to_ipfs, get_folder_hash, get_ipfs_data, add_problem_report_to_ipfs
from .utils import delete_temp_file, encrypt_message, create_temp_dir_and_copy_files, delete_temp_dir

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
        with open(f"{path}/{filename}", "rb") as f:
            video_data = f.read()
        encrypted_data = encrypt_message(video_data, admin_keypair, admin_keypair.public_key)
        with open(f"{path}/{filename}", "w") as f:
            f.write(encrypted_data)

        await add_media_to_ipfs(hass, f"{path}/{filename}")
        folder_ipfs_hash = await get_folder_hash(IPFS_MEDIA_PATH)
        # delete file from system
        _LOGGER.debug(f"delete original video {filename}")
        os.remove(f"{path}/{filename}")
        await hass.data[DOMAIN][ROBONOMICS].set_media_topic(folder_ipfs_hash, hass.data[DOMAIN][TWIN_ID])


async def save_backup_service_call(hass: HomeAssistant, call: ServiceCall, sub_admin_acc: Account) -> None:
    """Callback for save_backup_to_robonomics service.
    It creates secure backup, adds to IPFS and updates
    the Digital Twin topic.

    :param hass: HomeAssistant instance
    :param call: service call data
    :param sub_admin_acc: controller Robonomics account
    """

    if is_hassio(hass):
        encrypted_backup_path, backup_path = await create_secure_backup_hassio(hass, sub_admin_acc.keypair)
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
        hass.states.async_set(f"{DOMAIN}.backup", "Restoring")
        hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = True
        _LOGGER.debug("Start looking for backup ipfs hash")
        ipfs_backup_hash = await hass.data[DOMAIN][ROBONOMICS].get_backup_hash(hass.data[DOMAIN][TWIN_ID])
        result = await get_ipfs_data(hass, ipfs_backup_hash, 0)
        backup_path = f"{tempfile.gettempdir()}/{DATA_BACKUP_ENCRYPTED_NAME}"
        with open(backup_path, "w") as f:
            f.write(result)
        sub_admin_kp = Keypair.create_from_mnemonic(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
        if is_hassio(hass):
            await restore_backup_hassio(hass, Path(backup_path), sub_admin_kp)
        else:
            config_path = Path(hass.config.path())
            zigbee2mqtt_path = call.data.get("zigbee2mqtt_path")
            if zigbee2mqtt_path is None:
                zigbee2mqtt_path = "/opt/zigbee2mqtt"
            mosquitto_path = call.data.get("mosquitto_path")
            if mosquitto_path is None:
                mosquitto_path = "/etc/mosquitto"
            await unpack_backup(hass, Path(backup_path), sub_admin_kp)
            await restore_from_backup(hass, zigbee2mqtt_path, mosquitto_path, Path(hass.config.path()))
            _LOGGER.debug(f"Config restored, restarting...")
    except Exception as e:
        _LOGGER.error(f"Exception in restore from backup service call: {e}")


async def send_problem_report(hass: HomeAssistant, call: ServiceCall) -> None:
    try:
        problem_text = call.data.get("description")
        email = call.data.get("mail")
        phone_number = call.data.get("phone_number")
        json_text = {"description": problem_text, "e-mail": email, "phone_number": phone_number}
        _LOGGER.debug(f"send problem service: {problem_text}")
        hass_config_path = hass.config.path()
        files = []
        if call.data.get("attach_logs"):
            if os.path.isfile(f"{hass_config_path}/{LOG_FILE_NAME}"):
                files.append(f"{hass_config_path}/{LOG_FILE_NAME}")
            if os.path.isfile(f"{hass_config_path}/{TRACES_FILE_NAME}"):
                files.append(f"{hass_config_path}/{TRACES_FILE_NAME}")
        tempdir = create_temp_dir_and_copy_files(IPFS_PROBLEM_REPORT_FOLDER[1:], files, hass.data[DOMAIN][CONF_ADMIN_SEED], PROBLEM_SERVICE_ROBONOMICS_ADDRESS)
        _LOGGER.debug(f"Tempdir for problem report created: {tempdir}")
        sender_acc = Account(seed=hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
        sender_kp = sender_acc.keypair
        receiver_kp = Keypair(ss58_address=PROBLEM_SERVICE_ROBONOMICS_ADDRESS, crypto_type=KeypairType.ED25519)
        encrypted_json = encrypt_message(json.dumps(json_text), sender_kp, receiver_kp.public_key)
        with open(f"{tempdir}/issue_description.json", "w") as f:
            f.write(encrypted_json)
        ipfs_hash = await add_problem_report_to_ipfs(hass, tempdir)
        await hass.data[DOMAIN][ROBONOMICS].send_launch(PROBLEM_SERVICE_ROBONOMICS_ADDRESS, ipfs_hash)
    except Exception as e:
        _LOGGER.debug(f"Exception in send problem service: {e}")
    finally:
        delete_temp_dir(tempdir)