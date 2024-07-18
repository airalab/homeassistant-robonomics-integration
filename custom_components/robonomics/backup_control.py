"""
Script for managing backups. It containts methods to create HASS configurations' backups and 
restores configuration from uploaded or local backups. 
This file is imported as a module to `__init__.py` to create two services. 
`save_backup_to_robonomics` service uses following function:
    * create_secure_backup - returns the path to backup
`restore_from_robonomics_backup` service uses following functions:
    * unpack_backup - unpacking backup
    * restore_from_backup - rrestores configuration from unpacked backup
"""

import base64
import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
import typing as tp
import zipfile
from datetime import datetime
from pathlib import Path

import aiohttp
from homeassistant.components.hassio.const import DOMAIN as HASSIO_DOMAIN
from homeassistant.components.hassio.handler import async_create_backup
from homeassistant.components.mqtt import ReceiveMessage
from homeassistant.components.mqtt.client import publish, subscribe
from homeassistant.components.mqtt.util import mqtt_config_entry_enabled
from homeassistant.core import HomeAssistant
from substrateinterface import Keypair

from .const import (
    BACKUP_ENCRYPTED_PREFIX,
    BACKUP_PREFIX,
    DOMAIN,
    EXCLUDE_FROM_BACKUP,
    EXCLUDE_FROM_FULL_BACKUP,
    MQTT_CONFIG_NAME,
    Z2M_BACKUP_TOPIC_REQUEST,
    Z2M_BACKUP_TOPIC_RESPONSE,
    Z2M_CONFIG_NAME,
)
from .utils import (
    decrypt_message,
    delete_temp_file,
    encrypt_message,
    to_thread,
    write_data_to_temp_file,
    read_file_data,
)

from .encryption_utils import partial_encrypt, partial_decrypt

_LOGGER = logging.getLogger(__name__)


@to_thread
def create_secure_backup(
    hass: HomeAssistant,
    config_path: Path,
    mosquitto_path: str,
    admin_keypair: Keypair,
    full: bool,
) -> tuple[str, str]:
    """Create secure .tar.xz archive and returns the path to it

    :param hass: HomeAssistant instance
    :param config_path: Path to the configuration file
    :param admin_keypair: Keypair to encrypt backup
    :param full: Create full backup with database or not

    :return: Path to encrypted backup archive and for not encrypted backup
    """
    if mosquitto_path[-1] != "/":
        mosquitto_path = f"{mosquitto_path}/"
    hass.states.async_set(f"{DOMAIN}.backup", "Creating")
    backup_name_time = str(datetime.now()).split()
    backup_name_time[1] = backup_name_time[1].split(".")[0]
    backup_name = f"{BACKUP_PREFIX}{backup_name_time[0]}_{backup_name_time[1]}.tar.xz"
    path_to_tar = Path(tempfile.gettempdir())
    tar_path = path_to_tar.joinpath(f"{backup_name}")
    _LOGGER.debug(f"Start creating backup: {tar_path}, full: {full}")
    list_files = os.listdir(config_path)
    if full:
        excludes = EXCLUDE_FROM_FULL_BACKUP
    else:
        excludes = EXCLUDE_FROM_BACKUP
    try:
        with tarfile.open(tar_path, "w:xz") as tar:
            for file_item in list_files:
                for exclude in excludes:
                    path = Path(file_item)
                    if path.match(exclude):
                        # _LOGGER.debug(f"Exclude {path}")
                        break
                else:
                    # _LOGGER.debug(f"Addidng {config_path}/{file_item}")
                    tar.add(f"{config_path}/{file_item}")
            if mqtt_config_entry_enabled(hass):
                z2m_backup_path = _BackupZ2M(hass)._create_z2m_backup()
                if z2m_backup_path is not None:
                    tar.add(z2m_backup_path, arcname=Z2M_CONFIG_NAME)
                    delete_temp_file(z2m_backup_path)
            if os.path.isdir(mosquitto_path) and os.path.isfile(
                f"{mosquitto_path}passwd"
            ):
                _LOGGER.debug(
                    "Mosquitto configuration exists and will be added to backup"
                )
                tar.add(f"{mosquitto_path}passwd", arcname=MQTT_CONFIG_NAME)
        _LOGGER.debug(f"Backup {tar_path} was created")
        _LOGGER.debug(f"Start encrypt backup {tar_path}")
        with open(tar_path, "rb") as f:
            tar_data = f.read()
        encrypted_data = encrypt_message(
            tar_data, admin_keypair, admin_keypair.public_key
        )
        encrypted_tar_path = path_to_tar.joinpath(
            f"{BACKUP_ENCRYPTED_PREFIX}_{backup_name_time[0]}_{backup_name_time[1]}"
        )
        with open(encrypted_tar_path, "w") as f:
            f.write(encrypted_data)
        _LOGGER.debug("Backup was encrypted")
        hass.states.async_set(f"{DOMAIN}.backup", "Saved")
        return encrypted_tar_path, tar_path
    except Exception as e:
        _LOGGER.error(f"Exception in creating backup: {e}")


@to_thread
def unpack_backup(
    hass: HomeAssistant,
    path_to_encrypted: Path,
    admin_keypair: Keypair,
    path_to_unpack: Path = Path(f"{os.path.expanduser('~')}/backup_new"),
) -> None:
    """Unpack the archive with backup file

    :param hass: HomeAssistant instance
    :param path_to_encrypted: Path to the encrypted backup archive
    :param admin_keypair: Keypair to decrypt backup archive
    :param path_to_unpack: Path to store the unpacked backup
    """

    _LOGGER.debug(f"Start restoring configuration from backup {path_to_encrypted}")
    hass.states.async_set(f"{DOMAIN}.backup", "Restoring")
    try:
        with open(path_to_encrypted) as f:
            encrypted = f.read()
        decrypted = decrypt_message(encrypted, admin_keypair.public_key, admin_keypair)
        path_to_tar = f"{tempfile.gettempdir()}/backup_remote_decrypted.tar.xz"
        with open(path_to_tar, "wb") as f:
            f.write(decrypted)
        with tarfile.open(path_to_tar, "r:xz") as tar:
            tar.extractall(path_to_unpack)
        _LOGGER.debug(f"Backup {path_to_tar} was unpacked")
    except Exception as e:
        _LOGGER.error(f"Exception in unpacking backup: {e}")
        shutil.rmtree(path_to_unpack)
        return


async def restore_from_backup(
    hass: HomeAssistant,
    zigbee2mqtt_path: str,
    mosquitto_path: str,
    path_to_old_config: Path,
    path_to_new_config_dir: Path = Path(f"{os.path.expanduser('~')}/backup_new"),
) -> None:
    """Configuration file is replaced with a backup file. Remove unpacked backup.
    :param hass: HomeAssistant instance
    :param path_to_old_config: Path to the hass configuration directory
    :param path_to_new_config_dir: Path to the unpacked backup
    :param zigbee2mqtt_path: Path to unpack zigbee2mqtt config
    :param mosquitto_path: Path to unpack mosquitto config
    """

    if mosquitto_path[-1] != "/":
        mosquitto_path = f"{mosquitto_path}/"
    if zigbee2mqtt_path[-1] != "/":
        zigbee2mqtt_path = f"{zigbee2mqtt_path}/"
    try:
        old_config_files = os.listdir(path_to_old_config)
        for old_file in old_config_files:
            try:
                if os.path.isdir(f"{path_to_old_config}/{old_file}"):
                    shutil.rmtree(f"{path_to_old_config}/{old_file}")
                else:
                    os.remove(f"{path_to_old_config}/{old_file}")
            except Exception as e:
                _LOGGER.debug(f"Exception in deleting files: {e}")
        for dirname, dirnames, filenames in os.walk(path_to_new_config_dir):
            if ".HA_VERSION" in filenames:
                path_to_new_config = dirname
                new_config_files = filenames
                new_config_dirs = dirnames
        for new_dir in new_config_dirs:
            try:
                shutil.copytree(
                    f"{path_to_new_config}/{new_dir}", f"{path_to_old_config}/{new_dir}"
                )
            except Exception as e:
                _LOGGER.debug(f"Exception in copy directories: {e}")
        for new_file in new_config_files:
            try:
                shutil.copy(
                    f"{path_to_new_config}/{new_file}",
                    f"{path_to_old_config}/{new_file}",
                )
            except Exception as e:
                _LOGGER.debug(f"Exception in copy files: {e}")
        try:
            if os.path.exists(f"{path_to_new_config_dir}/{MQTT_CONFIG_NAME}"):
                if os.path.isdir(mosquitto_path) and os.path.exists(
                    f"{mosquitto_path}passwd"
                ):
                    os.remove(f"{mosquitto_path}passwd")
                shutil.copy(
                    f"{path_to_new_config_dir}/{MQTT_CONFIG_NAME}",
                    f"{mosquitto_path}passwd",
                )
                _LOGGER.debug(
                    f"Mosquitto password file was restored to {mosquitto_path}passwd"
                )
        except Exception as e:
            _LOGGER.warning(
                f"Exception in restoring mosquitto password: {e}. Mosquitto configuration will be placed in homeassistant configuration directory"
            )
            shutil.copy(
                f"{path_to_new_config_dir}/{MQTT_CONFIG_NAME}",
                f"{path_to_old_config}/{MQTT_CONFIG_NAME}",
            )
        try:
            if os.path.exists(f"{path_to_new_config_dir}/{Z2M_CONFIG_NAME}"):
                if os.path.isdir(zigbee2mqtt_path):
                    if os.path.isdir(f"{zigbee2mqtt_path}data"):
                        shutil.rmtree(f"{zigbee2mqtt_path}data")
                    with zipfile.ZipFile(
                        f"{path_to_new_config_dir}/{Z2M_CONFIG_NAME}", "r"
                    ) as zip_ref:
                        zip_ref.extractall(f"{zigbee2mqtt_path}data")
                    _LOGGER.debug(
                        f"Z2M configuration was restored to {zigbee2mqtt_path}data"
                    )
                else:
                    _LOGGER.warning(
                        f"Zigbee2mqtt does not exist in {zigbee2mqtt_path}, configuration will be restored in homeassistant configuration directory"
                    )
                    shutil.copy(
                        f"{path_to_new_config_dir}/{Z2M_CONFIG_NAME}",
                        f"{path_to_old_config}/{Z2M_CONFIG_NAME}",
                    )
        except Exception as e:
            _LOGGER.warning(
                f"Exception in restoring z2m: {e}. Zigbee2mqtt configuration will be placed in homeassistant configuration directory"
            )
            shutil.copy(
                f"{path_to_new_config_dir}/{Z2M_CONFIG_NAME}",
                f"{path_to_old_config}/{Z2M_CONFIG_NAME}",
            )
        shutil.rmtree(path_to_new_config_dir)
        _LOGGER.debug("Config was replaced")
        hass.states.async_set(f"{DOMAIN}.backup", "Restored")
        await hass.services.async_call("homeassistant", "restart")
    except Exception as e:
        _LOGGER.debug(f"Exception in restore from backup: {e}")


async def restore_backup_hassio(
    hass: HomeAssistant, encrypted_data: str, admin_keypair: Keypair
) -> None:
    """Restore superviser backup
    :param hass: Home Assistant instanse
    :param path_to_encrypted: Path to encrypted backup downloaded from IPFS
    :param admin_keypair: Controller Keypair
    """
    _LOGGER.debug("Start decrypting backup")
    decrypted = await partial_decrypt(encrypted_data, admin_keypair, admin_keypair.public_key)
    _LOGGER.error("Start uploading backup to hassio")
    response = await _send_command_hassio(
        hass, "/backups/new/upload", "post", {"file": decrypted}
    )
    try:
        resp = await response.json()
        _LOGGER.debug(f"Backup upload responce: {resp}")
        slug = resp["data"]["slug"]
        _LOGGER.debug(f"Response upload: {resp}")
        _LOGGER.debug(f"Backup {slug} uploaded")
    except Exception as e:
        _LOGGER.error(f"Exception in respose from backup upload request: {e}")
    _LOGGER.debug("Start restoring backup hassio")
    response = await _send_command_hassio(hass, f"/backups/{slug}/restore/full", "post")


async def create_secure_backup_hassio(
    hass: HomeAssistant, admin_keypair: Keypair
) -> tuple[str, str]:
    """Create superviser backup
    :param hass: Home Assistant instanse
    :param admin_keypair: Controller Keypair

    :return: Path to encrypted backup archive and for not encrypted backup
    """
    _LOGGER.debug("Start creating hassio backup")
    backup_name_time = str(datetime.now()).split()
    backup_name_time[1] = backup_name_time[1].split(".")[0]
    backup_name = f"{BACKUP_ENCRYPTED_PREFIX}_{backup_name_time[0]}_{backup_name_time[1]}"
    encrypted_backup_filepath = f"{hass.config.path()}/{backup_name}"
    _delete_found_backup_files(hass)
    resp_create = await async_create_backup(hass, {})
    _LOGGER.debug(f"Hassio backup was created with response {resp_create}")
    slug = resp_create["slug"]
    response = await _send_command_hassio(hass, f"/backups/{slug}/download", "get")
    backup = await response.read()
    _LOGGER.debug(f"Backup {slug} downloaded, len: {len(backup)}")
    _LOGGER.debug(f"Start deleting backup {slug}")
    response = await _send_command_hassio(hass, f"/backups/{slug}", "delete")
    _LOGGER.debug(f"Delete response: {response}")
    await partial_encrypt(
        hass, backup, admin_keypair, admin_keypair.public_key, encrypted_backup_filepath
    )
    _LOGGER.debug(f"Backup {slug} encrypted")
    return encrypted_backup_filepath
    
    
def _delete_found_backup_files(hass: HomeAssistant) -> None:
    files = os.listdir(hass.config.path())
    for filename in files:
        if filename.startswith(BACKUP_ENCRYPTED_PREFIX):
            _LOGGER.debug(f"Deleting {filename}")
            os.remove(f"{hass.config.path()}/{filename}")
            _LOGGER.debug(f"{filename} was deleted")


async def _send_command_hassio(
    hass: HomeAssistant,
    command: str,
    method: str,
    payload: tp.Optional[tp.Dict[str, tp.Any]] = None,
) -> tp.Coroutine:
    """Send API command to Superviser
    :param hass: Home Assistant instanse
    :param command: Superviser API endpoint
    :param method: 'get' or 'post' request
    :param payload: Payload for the request

    :return: Coroutine response
    """
    hassio = hass.data[HASSIO_DOMAIN]
    try:
        _LOGGER.debug(f"Start {method} request to {command} hassio")
        request = await hassio.websession.request(
            method,
            f"http://{hassio._ip}{command}",
            data=payload,
            headers={
                aiohttp.hdrs.AUTHORIZATION: (
                    f"Bearer {os.environ.get('SUPERVISOR_TOKEN', '')}"
                ),
                "X-Hass-Source": "core.handler",
            },
            timeout=aiohttp.ClientTimeout(total=300),
        )
        _LOGGER.debug(f"request to http://{hassio._ip}{command}, headers: {request.headers}")
        return request
    except Exception as e:
        _LOGGER.error(f"Exception in download backup hassio: {e}")


class _BackupZ2M:
    """Class to create zigbee2mqtt backup"""

    def __init__(self, hass: HomeAssistant) -> None:
        self.remove_mqtt_subscribe: tp.Optional[tp.Callable] = None
        self.hass: HomeAssistant = hass
        self.received: bool = False
        self.z2m_backup_path: tp.Optional[str] = None

    def _z2m_backup_callback(self, msg: ReceiveMessage) -> None:
        """Callback on response topic for z2m backup.
        It will create a zip file anc close subscription to the topic.
        :param msg: MQTT message
        """
        _LOGGER.debug("Received message with z2m backup")
        payload = json.loads(msg.payload)
        zip_arc_b64 = payload["data"]["zip"]
        zip_arc_bytes = base64.b64decode(zip_arc_b64)
        self.z2m_backup_path = write_data_to_temp_file(zip_arc_bytes)
        _LOGGER.debug(f"z2m archive was written to {self.z2m_backup_path}")
        self.remove_mqtt_subscribe()
        _LOGGER.debug("Subscription to response topic was removed")
        self.received = True

    def _create_z2m_backup(self) -> tp.Optional[str]:
        """Send message to mqtt topic to create z2m backup and supscribe to the response topic

        :return: Path to the backup file
        """
        _LOGGER.debug("Start creating zigbee2mqtt backup")
        publish(self.hass, Z2M_BACKUP_TOPIC_REQUEST, "")
        _LOGGER.debug("Message to create z2m backup was sent")
        self.remove_mqtt_subscribe = subscribe(
            self.hass, Z2M_BACKUP_TOPIC_RESPONSE, self._z2m_backup_callback
        )
        _LOGGER.debug("Subscribed")
        i = 0
        while not self.received:
            time.sleep(1)
            i = i + 1
            if i > 10:
                _LOGGER.debug("Backup zigbee2mqtt wasn't created")
                break
        return self.z2m_backup_path
