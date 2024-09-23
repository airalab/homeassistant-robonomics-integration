import typing as tp
import logging
from homeassistant.core import HomeAssistant
from .utils.service import Service
from .utils.utils import format_files_list
from ....const import DOMAIN, IPFS_MEDIA_PATH, IPFS_TELEMETRY_PATH, IPFS_BACKUP_PATH, IPFS_CONFIG_PATH, IPFS_USERS_PATH, IPFS_STATUS, IPFS_STATUS_ENTITY

_LOGGER = logging.getLogger(__name__)


class MFSFoldersManager:

    @staticmethod
    async def create(hass: HomeAssistant) -> None:
        try:
            folders = await hass.async_add_executor_job(Service.mfs_ls, "/")
            folder_names = format_files_list(folders)
            _LOGGER.debug(f"IPFS folders: {folder_names}")
            if IPFS_MEDIA_PATH[1:] not in folder_names:
                await hass.async_add_executor_job(Service.mfs_mkdir, IPFS_MEDIA_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_MEDIA_PATH} created")
            if IPFS_TELEMETRY_PATH[1:] not in folder_names:
                await hass.async_add_executor_job(Service.mfs_mkdir, IPFS_TELEMETRY_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_TELEMETRY_PATH} created")
            if IPFS_BACKUP_PATH[1:] not in folder_names:
                await hass.async_add_executor_job(Service.mfs_mkdir, IPFS_BACKUP_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_BACKUP_PATH} created")
            if IPFS_CONFIG_PATH[1:] not in folder_names:
                await hass.async_add_executor_job(Service.mfs_mkdir, IPFS_CONFIG_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_CONFIG_PATH} created")
            if IPFS_USERS_PATH[1:] not in folder_names:
                await hass.async_add_executor_job(Service.mfs_mkdir, IPFS_USERS_PATH)
                _LOGGER.debug(f"IPFS folder {IPFS_USERS_PATH} created")
            hass.data[DOMAIN][IPFS_STATUS] = "OK"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
        except Exception as e:
            _LOGGER.error(f"Exception in creating ipfs folders: {e}")
            hass.data[DOMAIN][IPFS_STATUS] = "Error"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )

    @staticmethod
    async def is_hash_in_folder(hass: HomeAssistant, ipfs_hash: str, folder: str) -> bool:
        try:
            list_files = await hass.async_add_executor_job(Service.mfs_ls, folder)
            if not list_files:
                await hass.async_add_executor_job(MFSFoldersManager.create_folders, hass)
                return False
            for file_info in list_files:
                stat_info = await hass.async_add_executor_job(Service.mfs_stat, folder, file_info["Name"])
                hass.data[DOMAIN][IPFS_STATUS] = "OK"
                hass.states.async_set(
                        f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
                )
                if ipfs_hash == stat_info["Hash"]:
                    return True
            return False
        except Exception as e:
            _LOGGER.error(f"Exception in check if hash in folder: {e}")
            hass.data[DOMAIN][IPFS_STATUS] = "Error"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
    
    @staticmethod
    async def delete(hass: HomeAssistant, dir_name: str) -> None:
        try:
            _LOGGER.debug(f"Start deleting ipfs folder {dir_name}")
            folders = await hass.async_add_executor_job(Service.mfs_ls, "/")
            folder_names = format_files_list(folders)
            is_dir = True
            if dir_name[1:] in folder_names:
                await hass.async_add_executor_job(Service.mfs_rm, dir_name, is_dir)
                hass.data[DOMAIN][IPFS_STATUS] = "OK"
                hass.states.async_set(
                    f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
                )
                _LOGGER.debug(f"Ipfs folder {dir_name} was deleted")
        except Exception as e:
            _LOGGER.error(f"Exception in deleting folder {dir_name}: {e}")
            hass.data[DOMAIN][IPFS_STATUS] = "Error"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
    
    @staticmethod
    async def get_folder_hash(hass: HomeAssistant, folder_name_with_path: str) -> tp.Optional[str]:
        try:
            res = await hass.async_add_executor_job(Service.mfs_stat, folder_name_with_path)
            hass.data[DOMAIN][IPFS_STATUS] = "OK"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
            return res["Hash"]
        except Exception as e:
            _LOGGER.error(f"Exception in getting folder hash: {e}")
            hass.data[DOMAIN][IPFS_STATUS] = "Error"
            hass.states.async_set(
                f"sensor.{IPFS_STATUS_ENTITY}", hass.data[DOMAIN][IPFS_STATUS]
            )
