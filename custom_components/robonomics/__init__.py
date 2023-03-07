"""
Entry point for integration.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import timedelta
from pathlib import Path
from platform import platform
import tempfile

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType
from pinatapy import PinataPy
from robonomicsinterface import Account
from substrateinterface import Keypair, KeypairType

_LOGGER = logging.getLogger(__name__)

from .backup_control import check_backup_change, create_secure_backup, restore_from_backup, unpack_backup
from .const import (
    CONF_ADMIN_SEED,
    CONF_IPFS_GATEWAY,
    CONF_IPFS_GATEWAY_AUTH,
    CONF_IPFS_GATEWAY_PORT,
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_SENDING_TIMEOUT,
    CONF_SUB_OWNER_ADDRESS,
    DATA_BACKUP_ENCRYPTED_NAME,
    DATA_PATH,
    DOMAIN,
    HANDLE_IPFS_REQUEST,
    HANDLE_TIME_CHANGE,
    MAX_NUMBER_OF_REQUESTS,
    PINATA,
    ROBONOMICS,
    TIME_CHANGE_COUNT,
    TIME_CHANGE_UNSUB,
    TWIN_ID,
    IPFS_CONFIG_PATH,
    CONFIG_PREFIX,
)
from .get_states import get_and_send_data
from .ipfs import add_backup_to_ipfs, create_folders, get_ipfs_data, get_last_file_hash, read_ipfs_local_file
from .manage_users import manage_users
from .robonomics import Robonomics, check_subscription_left_days
from .utils import decrypt_message, delete_temp_file


async def init_integration(hass: HomeAssistant) -> None:
    """Compare rws devices with users from Home Assistant

    :param hass: HomeAssistant instance
    """

    try:
        await asyncio.sleep(60)
        start_devices_list = hass.data[DOMAIN][ROBONOMICS].get_devices_list()
        _LOGGER.debug(f"Start devices list is {start_devices_list}")
        hass.async_create_task(manage_users(hass, ("0", start_devices_list)))
    except Exception as e:
        print(f"Exception in fist check devices {e}")

    await check_backup_change(hass)
    # await asyncio.sleep(60)
    await get_and_send_data(hass)


async def update_listener(hass: HomeAssistant, entry: ConfigEntry):
    """Handle options update. It's called when config updates.

    :param hass: HomeAssistant instance
    :param entry: Data from config
    """
    try:
        _LOGGER.debug("Reconfigure Robonomics Integration")
        _LOGGER.debug(f"HASS.data before: {hass.data[DOMAIN]}")
        _LOGGER.debug(f"entry options before: {entry.options}")
        if CONF_IPFS_GATEWAY in entry.options:
            hass.data[DOMAIN][CONF_IPFS_GATEWAY] = entry.options[CONF_IPFS_GATEWAY]
        hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = entry.options[CONF_IPFS_GATEWAY_AUTH]
        hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT] = entry.options[CONF_IPFS_GATEWAY_PORT]
        hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(minutes=entry.options[CONF_SENDING_TIMEOUT])
        if (CONF_PINATA_PUB in entry.options) and (CONF_PINATA_SECRET in entry.options):
            hass.data[DOMAIN][PINATA] = PinataPy(entry.options[CONF_PINATA_PUB], entry.options[CONF_PINATA_SECRET])
            _LOGGER.debug("Use Pinata to pin files")
        else:
            hass.data[DOMAIN][PINATA] = None
            _LOGGER.debug("Use local node to pin files")
        hass.data[DOMAIN][TIME_CHANGE_UNSUB]()
        hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(
            hass,
            hass.data[DOMAIN][HANDLE_TIME_CHANGE],
            hass.data[DOMAIN][CONF_SENDING_TIMEOUT],
        )
        _LOGGER.debug(f"HASS.data after: {hass.data[DOMAIN]}")
    except Exception as e:
        _LOGGER.error(f"Exception in update_listener: {e}")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Robonomics Integration from a config entry.
    It calls every time integration uploading and after config flow during initial
    setup.

    :param hass: HomeAssistant instance
    :param entry: Data from config

    :return: True after succesfull setting up

    """

    hass.data.setdefault(DOMAIN, {})
    _LOGGER.debug(f"Robonomics user control starting set up")
    conf = entry.data
    if CONF_IPFS_GATEWAY in conf:
        hass.data[DOMAIN][CONF_IPFS_GATEWAY] = conf[CONF_IPFS_GATEWAY]
    hass.data[DOMAIN][CONF_IPFS_GATEWAY_AUTH] = conf[CONF_IPFS_GATEWAY_AUTH]
    hass.data[DOMAIN][CONF_IPFS_GATEWAY_PORT] = conf[CONF_IPFS_GATEWAY_PORT]
    hass.data[DOMAIN][CONF_SENDING_TIMEOUT] = timedelta(minutes=conf[CONF_SENDING_TIMEOUT])
    _LOGGER.debug(f"Sending interval: {conf[CONF_SENDING_TIMEOUT]} minutes")
    hass.data[DOMAIN][CONF_ADMIN_SEED] = conf[CONF_ADMIN_SEED]
    hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS] = conf[CONF_SUB_OWNER_ADDRESS]

    sub_admin_acc = Account(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
    _LOGGER.debug(f"sub admin: {sub_admin_acc.get_address()}")
    _LOGGER.debug(f"sub owner: {hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS]}")
    hass.data[DOMAIN][ROBONOMICS]: Robonomics = Robonomics(
        hass,
        hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS],
        hass.data[DOMAIN][CONF_ADMIN_SEED],
    )
    if (CONF_PINATA_PUB in conf) and (CONF_PINATA_SECRET in conf):
        hass.data[DOMAIN][CONF_PINATA_PUB] = conf[CONF_PINATA_PUB]
        hass.data[DOMAIN][CONF_PINATA_SECRET] = conf[CONF_PINATA_SECRET]
        hass.data[DOMAIN][PINATA] = PinataPy(hass.data[DOMAIN][CONF_PINATA_PUB], hass.data[DOMAIN][CONF_PINATA_SECRET])
        _LOGGER.debug("Use Pinata to pin files")
    else:
        hass.data[DOMAIN][PINATA] = None
        _LOGGER.debug("Use local node to pin files")
    data_path = f"{os.path.expanduser('~')}/{DATA_PATH}"
    if os.path.isdir(data_path):
        shutil.rmtree(data_path)

    await create_folders()

    hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = False
    entry.async_on_unload(entry.add_update_listener(update_listener))

    hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0

    async def handle_time_changed(event):
        """Callback for time' changing subscription.
        It calls every timeout from config to get and send telemtry.

        :param event: Current date & time
        """

        try:
            time_change_count_in_day = 24 * 60 / (hass.data[DOMAIN][CONF_SENDING_TIMEOUT].seconds / 60)
            hass.data[DOMAIN][TIME_CHANGE_COUNT] += 1
            if hass.data[DOMAIN][TIME_CHANGE_COUNT] >= time_change_count_in_day:
                hass.data[DOMAIN][TIME_CHANGE_COUNT] = 0
                await check_subscription_left_days(hass)
            _LOGGER.debug(f"Time changed: {event}")
            await get_and_send_data(hass)
        except Exception as e:
            _LOGGER.error(f"Exception in handle_time_changed: {e}")

    hass.data[DOMAIN][HANDLE_TIME_CHANGE] = handle_time_changed

    async def handle_save_backup(call):
        """Callback for save_backup_to_robonomics service.
        It creates secure backup, adds to IPFS and updates
        the Digital Twin topic.
        """

        encrypted_backup_path, backup_path = await create_secure_backup(
            hass,
            Path(hass.config.path()),
            admin_keypair=sub_admin_acc.keypair,
        )
        ipfs_hash = await add_backup_to_ipfs(hass, str(backup_path), str(encrypted_backup_path))
        _LOGGER.debug(f"Backup created on {backup_path} with hash {ipfs_hash}")
        delete_temp_file(encrypted_backup_path)
        delete_temp_file(backup_path)
        await hass.data[DOMAIN][ROBONOMICS].set_backup_topic(ipfs_hash, hass.data[DOMAIN][TWIN_ID])

    async def handle_restore_from_backup(call):
        """Callback for restore_from_robonomics_backup service.
        It restores configuration file from backup.
        """

        try:
            config_path = Path(hass.config.path())
            backup_encrypted_path = call.data.get("backup_path")
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
                await restore_from_backup(hass, Path(hass.config.path()))
            else:
                backup_path = await unpack_backup(hass, backup_encrypted_path, sub_admin_acc.keypair)
                await restore_from_backup(hass, config_path)
                _LOGGER.debug(f"Config restored, restarting...")
        except Exception as e:
            _LOGGER.error(f"Exception in restore from backup service call: {e}")

    hass.services.async_register(DOMAIN, "save_backup_to_robonomics", handle_save_backup)
    hass.services.async_register(DOMAIN, "restore_from_robonomics_backup", handle_restore_from_backup)

    hass.data[DOMAIN][TIME_CHANGE_UNSUB] = async_track_time_interval(
        hass,
        hass.data[DOMAIN][HANDLE_TIME_CHANGE],
        hass.data[DOMAIN][CONF_SENDING_TIMEOUT],
    )
    hass.data[DOMAIN][ROBONOMICS].subscribe()
    await check_subscription_left_days(hass)
    if TWIN_ID not in hass.data[DOMAIN]:
        try:
            config_name, _ = await get_last_file_hash(IPFS_CONFIG_PATH, CONFIG_PREFIX)
            current_config = await read_ipfs_local_file(config_name, IPFS_CONFIG_PATH)
            _LOGGER.debug(f"Current twin id is {current_config['twin_id']}")
            hass.data[DOMAIN][TWIN_ID] = current_config["twin_id"]
        except Exception as e:
            _LOGGER.debug(f"Can't load config: {e}")
            last_telemetry_hash = await hass.data[DOMAIN][ROBONOMICS].get_last_telemetry_hash()
            if last_telemetry_hash is not None:
                hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = True
                res = await get_ipfs_data(hass, last_telemetry_hash, MAX_NUMBER_OF_REQUESTS - 1)
                if res is not None:
                    try:
                        _LOGGER.debug("Start getting info about telemetry")
                        sub_admin_kp = Keypair.create_from_mnemonic(
                            hass.data[DOMAIN][CONF_ADMIN_SEED],
                            crypto_type=KeypairType.ED25519,
                        )
                        decrypted = decrypt_message(res, sub_admin_kp.public_key, sub_admin_kp)
                        decrypted_str = decrypted.decode("utf-8")
                        decrypted_json = json.loads(decrypted_str)
                        _LOGGER.debug(f"Restored twin id is {decrypted_json['twin_id']}")
                        hass.data[DOMAIN][TWIN_ID] = decrypted_json["twin_id"]
                    except Exception as e:
                        _LOGGER.debug(f"Can't decrypt last telemetry: {e}")
                try:
                    if TWIN_ID not in hass.data[DOMAIN]:
                        _LOGGER.debug(f"Start creating new digital twin")
                        hass.data[DOMAIN][TWIN_ID] = await hass.data[DOMAIN][ROBONOMICS].create_digital_twin()
                        _LOGGER.debug(f"New twin id is {hass.data[DOMAIN][TWIN_ID]}")
                    else:
                        _LOGGER.debug(f"Got twin id from telemetry: {hass.data[DOMAIN][TWIN_ID]}")
                except Exception as e:
                    _LOGGER.debug(f"Exception in configure digital twin: {e}")
            else:
                hass.data[DOMAIN][TWIN_ID] = await hass.data[DOMAIN][ROBONOMICS].create_digital_twin()
                _LOGGER.debug(f"New twin id is {hass.data[DOMAIN][TWIN_ID]}")

    asyncio.ensure_future(init_integration(hass))

    # hass.config_entries.async_setup_platforms(entry, PLATFORMS)
    _LOGGER.debug(f"Robonomics user control successfuly set up")
    return True


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    _LOGGER.debug(f"setup data: {config.get(DOMAIN)}")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.
    It calls during integration's removing.

    :param hass: HomeAssistant instance
    :param entry: Data from config

    :return: True when integration is unloaded
    """

    hass.data[DOMAIN][TIME_CHANGE_UNSUB]()
    hass.data[DOMAIN][ROBONOMICS].subscriber.cancel()
    hass.data.pop(DOMAIN)
    _LOGGER.debug(f"Robonomics integration was unloaded")
    return True
