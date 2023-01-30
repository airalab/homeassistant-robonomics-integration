from pathlib import Path
from homeassistant.core import HomeAssistant
from securetar import SecureTarFile, atomic_contents_add, secure_path
from substrateinterface import Keypair, KeypairType
import hashlib
import tarfile
from datetime import datetime
import logging
import shutil
import os
import typing as tp
import ipfshttpclient2

from .utils import to_thread, encrypt_message, decrypt_message
from .const import (
    EXCLUDE_FROM_BACKUP,
    ROBONOMICS,
    DOMAIN,
    TWIN_ID,
    DATA_BACKUP_PATH,
    DATA_BACKUP_ENCRYPTED_PATH,
)

_LOGGER = logging.getLogger(__name__)


@to_thread
def get_hash(filename: str) -> tp.Optional[str]:
    try:
        with ipfshttpclient2.connect() as client:
            ipfs_hash_local = client.add(filename, pin=False)["Hash"]
    except Exception as e:
        _LOGGER.error(f"Exception in get_hash with local node: {e}")
        ipfs_hash_local = None
    return ipfs_hash_local


async def check_backup_change(hass: HomeAssistant) -> None:
    try:
        _LOGGER.debug(f"Start checking backup")
        ipfs_hash_remote = await hass.data[DOMAIN][ROBONOMICS].get_backup_hash(
            hass.data[DOMAIN][TWIN_ID]
        )
        _LOGGER.debug(f"Backup remote hash: {ipfs_hash_remote}")
        if os.path.isdir(f"{os.path.expanduser('~')}/{DATA_BACKUP_PATH}"):
            if os.path.isfile(
                f"{os.path.expanduser('~')}/{DATA_BACKUP_ENCRYPTED_PATH}"
            ):
                path_to_latest_backup = (
                    f"{os.path.expanduser('~')}/{DATA_BACKUP_ENCRYPTED_PATH}"
                )
                _LOGGER.debug(f"Latest local backup is from robonomcis")
            else:
                path_to_backups = f"{os.path.expanduser('~')}/{DATA_BACKUP_PATH}"
                list_files = os.listdir(path_to_backups)
                path_to_latest_backup = f"{path_to_backups}/{list_files[0]}"
                if "encrypted" not in path_to_latest_backup:
                    path_to_latest_backup += "_encrypted"
                _LOGGER.debug(f"Latest local backup is {path_to_latest_backup}")
            ipfs_hash_local = await get_hash(path_to_latest_backup)
            _LOGGER.debug(f"Backup local hash: {ipfs_hash_local}")
            if ipfs_hash_remote != ipfs_hash_local:
                _LOGGER.debug("Backup was updated")
                service_data = {
                    "message": "Remote backup was updated in Robonomics",
                    "title": "Update Backup",
                }
                await hass.services.async_call(
                    domain="notify",
                    service="persistent_notification",
                    service_data=service_data,
                )
            else:
                _LOGGER.debug("Backup wasn't updated")
        else:
            _LOGGER.debug("No backups exist")
    except Exception as e:
        _LOGGER.error(f"Exception in check backup change: {e}")


@to_thread
def create_secure_backup(
    hass: HomeAssistant,
    config_path: Path,
    path_for_tar: Path,
    admin_keypair: Keypair = None,
) -> str:
    """ "Create secure .tar.gz archive and returns the path to it"""
    hass.states.async_set(f"{DOMAIN}.backup", "Creating")
    backup_name = str(datetime.now()).split()
    backup_name[1] = backup_name[1].split(".")[0]
    backup_name = f"{backup_name[0]}_{backup_name[1]}.tar.xz"
    tar_path = path_for_tar.joinpath(f"{backup_name}")
    _LOGGER.debug(f"Start creating backup: {tar_path}")
    list_files = os.listdir(config_path)
    try:
        with tarfile.open(tar_path, "w:xz") as tar:
            for file_item in list_files:
                for exclude in EXCLUDE_FROM_BACKUP:
                    path = Path(file_item)
                    if path.match(exclude):
                        # _LOGGER.debug(f"Exclude {path}")
                        break
                else:
                    # _LOGGER.debug(f"Addidng {config_path}/{file_item}")
                    tar.add(f"{config_path}/{file_item}")
        _LOGGER.debug(f"Backup {tar_path} was created")
        if admin_keypair is not None:
            _LOGGER.debug(f"Start encrypt backup {tar_path}")
            with open(tar_path, "rb") as f:
                tar_data = f.read()
            encrypted_data = encrypt_message(
                tar_data, admin_keypair, admin_keypair.public_key
            )
            with open(f"{tar_path}_encrypted", "w") as f:
                f.write(encrypted_data)
            _LOGGER.debug(f"Backup was encrypted")
            hass.states.async_set(f"{DOMAIN}.backup", "Saved")
            return f"{tar_path}_encrypted"
        else:
            return tar_path
    except Exception as e:
        _LOGGER.error(f"Exception in creating backup: {e}")


@to_thread
def unpack_backup(
    hass: HomeAssistant,
    path_to_encrypted: Path,
    admin_keypair: Keypair,
    path_to_unpack: Path = Path(f"{os.path.expanduser('~')}/backup_new"),
) -> None:
    """ "Unpack the archive with backup and change the configuration"""
    _LOGGER.debug(f"Start restore configuration from backup {path_to_encrypted}")
    hass.states.async_set(f"{DOMAIN}.backup", "Restoring")
    try:
        with open(path_to_encrypted) as f:
            encrypted = f.read()
        decrypted = decrypt_message(encrypted, admin_keypair.public_key, admin_keypair)
        path_to_tar = f"{os.path.expanduser('~')}/{DATA_BACKUP_PATH}/backup_remote_decrypted.tar.xz"
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
    path_to_old_config: Path,
    path_to_new_config: Path = Path(f"{os.path.expanduser('~')}/backup_new"),
) -> None:
    try:
        shutil.rmtree(path_to_old_config)
        os.replace(
            f"{path_to_new_config}/home/homeassistant/.homeassistant",
            path_to_old_config,
        )
        _LOGGER.debug(f"Config was replaced")
        hass.states.async_set(f"{DOMAIN}.backup", "Restored")
        await hass.services.async_call("homeassistant", "restart")
    except Exception as e:
        _LOGGER.debug(f"Exception in restoer from backup: {e}")
    # service_data = {"message": "Configuration was restored from remote Robonomics backup. Restart Home Assistant.", "title": "Configuration Restored"}
    # hass.async_create_task(hass.services.async_call(domain="notify", service="persistent_notification", service_data=service_data))
