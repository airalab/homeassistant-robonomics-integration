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

import logging
import os
import shutil
import tarfile
from datetime import datetime
from pathlib import Path
import tempfile

from homeassistant.core import HomeAssistant
from substrateinterface import Keypair

from .const import (
    DOMAIN,
    EXCLUDE_FROM_BACKUP,
    ROBONOMICS,
    TWIN_ID,
    BACKUP_ENCRYPTED_PREFIX,
    IPFS_BACKUP_PATH,
    BACKUP_PREFIX,
)
from .utils import decrypt_message, encrypt_message, to_thread
from .ipfs import get_last_file_hash

_LOGGER = logging.getLogger(__name__)


async def check_backup_change(hass: HomeAssistant) -> None:
    """Compare local and remote (from Robonomics) backups. If they are not the same, user is notified.

    :param hass: HomeAssistant instance
    """

    try:
        _LOGGER.debug(f"Start checking backup")
        ipfs_hash_remote = await hass.data[DOMAIN][ROBONOMICS].get_backup_hash(hass.data[DOMAIN][TWIN_ID])
        _LOGGER.debug(f"Backup remote hash: {ipfs_hash_remote}")
        _, ipfs_hash_local = await get_last_file_hash(IPFS_BACKUP_PATH, prefix=BACKUP_ENCRYPTED_PREFIX)
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
    except Exception as e:
        _LOGGER.warning(f"Exception in check backup change: {e}")


@to_thread
def create_secure_backup(
    hass: HomeAssistant,
    config_path: Path,
    admin_keypair: Keypair,
) -> (str, str):
    """Create secure .tar.xz archive and returns the path to it

    :param hass: HomeAssistant instance
    :param config_path: Path to the configuration file
    :param admin_keypair: Keypair to encrypt backup

    :return: Path to encrypted backup archive and for not encrypted backup
    """

    hass.states.async_set(f"{DOMAIN}.backup", "Creating")
    backup_name_time = str(datetime.now()).split()
    backup_name_time[1] = backup_name_time[1].split(".")[0]
    backup_name = f"{BACKUP_PREFIX}{backup_name_time[0]}_{backup_name_time[1]}.tar.xz"
    path_to_tar = Path(tempfile.gettempdir())
    tar_path = path_to_tar.joinpath(f"{backup_name}")
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
        _LOGGER.debug(f"Start encrypt backup {tar_path}")
        with open(tar_path, "rb") as f:
            tar_data = f.read()
        encrypted_data = encrypt_message(tar_data, admin_keypair, admin_keypair.public_key)
        encrypted_tar_path = path_to_tar.joinpath(
            f"{BACKUP_ENCRYPTED_PREFIX}_{backup_name_time[0]}_{backup_name_time[1]}"
        )
        with open(encrypted_tar_path, "w") as f:
            f.write(encrypted_data)
        _LOGGER.debug(f"Backup was encrypted")
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
    path_to_old_config: Path,
    path_to_new_config_dir: Path = Path(f"{os.path.expanduser('~')}/backup_new"),
) -> None:
    """Configuration file is replaced with a backup file. Remove unpacked backup.
    :param hass: HomeAssistant instance
    :param path_to_old_config: Path to the hass configuration directory
    :param path_to_new_config_dir: Path to the unpacked backup
    """

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
            if "configuration.yaml" in filenames:
                path_to_new_config = dirname
                new_config_files = filenames
                new_config_dirs = dirnames
        for new_dir in new_config_dirs:
            try:
                shutil.copytree(f"{path_to_new_config}/{new_dir}", f"{path_to_old_config}/{new_dir}")
            except Exception as e:
                _LOGGER.debug(f"Exception in copy directories: {e}")
        for new_file in new_config_files:
            try:
                shutil.copy(f"{path_to_new_config}/{new_file}", f"{path_to_old_config}/{new_file}")
            except Exception as e:
                _LOGGER.debug(f"Exception in copy files: {e}")
        shutil.rmtree(path_to_new_config_dir)
        _LOGGER.debug(f"Config was replaced")
        hass.states.async_set(f"{DOMAIN}.backup", "Restored")
        await hass.services.async_call("homeassistant", "restart")
    except Exception as e:
        _LOGGER.debug(f"Exception in restore from backup: {e}")
