"""
This module contain functions to work with Home Assistant users.

It allows to create or delete Home Assistant user from Robonomics device list.
External functions here are manage_users() and change_password().
"""

from __future__ import annotations

from homeassistant.auth import auth_manager_from_config, models
from homeassistant.auth.providers import AuthProvider
from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.core import HomeAssistant

from substrateinterface import Keypair, KeypairType
from robonomicsinterface import Account

import typing as tp
import logging
import json

from .utils import decrypt_message
from .const import (
    CONF_SUB_OWNER_ADDRESS,
    CONF_ADMIN_SEED,
    DOMAIN,
    ROBONOMICS,
)

_LOGGER = logging.getLogger(__name__)

manage_users_queue = 0


async def manage_users(hass: HomeAssistant, data: tp.Tuple[str]) -> None:
    """Compare users and data from transaction

    Compare current users of Home Assistant and Robonomics subscription device list. Decide what users must be
    created or deleted.

    :param hass: Home Assistant instance
    :param data: tuple of addresses in robonomics subscription

    """

    global manage_users_queue
    manage_users_queue += 1
    my_queue = manage_users_queue
    provider = await _get_provider(hass)
    users = provider.data.users
    _LOGGER.debug(f"Begining users: {users}")
    usernames_hass = [user["username"] for user in users if len(user["username"]) == 48 and user["username"][0] == "4"]
    devices = data[1]
    if devices is None:
        devices = []
    try:
        sub_admin_acc = Account(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
        if sub_admin_acc.get_address() in devices:
            devices.remove(sub_admin_acc.get_address())
        if hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS] in devices:
            devices.remove(hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS])
    except Exception as e:
        _LOGGER.error(f"Exception in deleting sub admin and sub owner from devices: {e}")
    hass.data[DOMAIN][ROBONOMICS].devices_list = devices.copy()
    devices = [device.lower() for device in devices]
    users_to_add = list(set(devices) - set(usernames_hass))
    _LOGGER.debug(f"New users: {users_to_add}")
    users_to_delete = list(set(usernames_hass) - set(devices))
    _LOGGER.debug(f"Following users will be deleted: {users_to_delete}")
    rec_kp = Keypair.create_from_mnemonic(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
    created_users = 0
    for user in users_to_add:
        for device in hass.data[DOMAIN][ROBONOMICS].devices_list:
            if device.lower() == user:
                sender_kp = Keypair(ss58_address=device, crypto_type=KeypairType.ED25519)
                encrypted_password = await hass.data[DOMAIN][ROBONOMICS].find_password(device)
                if encrypted_password != None:
                    try:
                        password = str(decrypt_message(encrypted_password, sender_kp.public_key, rec_kp))
                        password = password[2:-1]
                        await _create_user(hass, provider, user, password)
                        created_users += 1
                        break
                    except Exception as e:
                        _LOGGER.warning(f"Can't decrypt password for {device}")
                else:
                    _LOGGER.debug(f"Password for user {user} wasn't found")

    for user in users_to_delete:
        await _delete_user(hass, provider, user)

    if len(users_to_delete) > 0 or created_users > 0:
        await provider.data.async_save()
        _LOGGER.debug(f"Finishing user managment, user list: {provider.data.users}")
        if my_queue < manage_users_queue:
            _LOGGER.debug(f"Another thread will restart homeassistant")
            return
        _LOGGER.debug("Restarting...")
        manage_users_queue = 0
        # await hass.async_stop(RESTART_EXIT_CODE)
        # _LOGGER.debug(f"After restart")
        await hass.services.async_call("homeassistant", "restart")


async def change_password(hass: HomeAssistant, data: tp.Tuple[tp.Union[str, tp.List[str]]]) -> None:
    """Change password for existing user or create new user

    :param hass: Home assistant instance
    :param data: data from datalog to change password

    """

    _LOGGER.debug(f"Start setting password for username {data[0]}")
    provider = await _get_provider(hass)
    sender_kp = Keypair(ss58_address=data[0], crypto_type=KeypairType.ED25519)
    sub_admin_acc = Account(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
    rec_kp = sub_admin_acc.keypair
    try:
        message = json.loads(data[2])
    except Exception as e:
        _LOGGER.warning(f"Message in Datalog is in wrong format: {e}\nMessage: {data[2]}")
        return
    if (
        "admin" in message
        and message["subscription"] == hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS]
        and message["ha"] == sub_admin_acc.get_address()
    ):
        try:
            password = str(decrypt_message(message["admin"], sender_kp.public_key, rec_kp))
            password = password[2:-1]
            _LOGGER.debug(f"Decrypted password: {password}")
        except Exception as e:
            _LOGGER.error(f"Exception in change password decrypt: {e}")
            return
        try:
            username = data[0].lower()
            users = await hass.auth.async_get_users()
            for user in users:
                if user.name == username:
                    await _delete_user(hass, provider, username)
            await _create_user(hass, provider, username, password)

        except Exception as e:
            _LOGGER.error(f"Exception in change password: {e}")
            return
        _LOGGER.debug("Restarting...")
        await provider.data.async_save()
        # hass.data[DOMAIN][ROBONOMICS].subscriber.cancel()
        # while hass.data[DOMAIN][ROBONOMICS].subscriber._subscription.is_alive():
        #     await asyncio.sleep(0.5)
        await hass.services.async_call("homeassistant", "restart")
    else:
        _LOGGER.warning(f"Message for setting password for {data[0]} is in wrong format")


async def _get_provider(hass: HomeAssistant) -> AuthProvider:
    """Returns Home Assistant auth provider

    :param hass: Home Assistant instance

    :return: Home Assistant auth provider
    """

    hass.auth = await auth_manager_from_config(hass, [{"type": "homeassistant"}], [])
    provider = hass.auth.auth_providers[0]
    await provider.async_initialize()
    return provider


async def _create_user(hass: HomeAssistant, provider, username: str, password: str) -> None:
    """Create user in Home Assistant

    :param hass: Home Assistant instance
    :param provider: Provider of user authentication
    :param username: New user username
    :param password: New user password
    """

    try:
        _LOGGER.debug(f"Start creating user: {username}")
        created_user = await hass.auth.async_create_user(username, group_ids=[GROUP_ID_USER])
        provider.data.add_auth(username, password)
        credentials = await provider.async_get_or_create_credentials({"username": username})
        await provider.data.async_save()
        await hass.auth.async_link_user(created_user, credentials)
        _LOGGER.debug(f"User was created: {username}, password: {password}")
    except Exception as e:
        _LOGGER.error(f"Exception in create user: {e}")


async def _delete_user(hass: HomeAssistant, provider, username: str) -> None:
    """Delete user from Home Assistant

    :param hass: Home Assistant instance
    :param provider: Provider of user authentication
    :param username: Username to delete
    """

    try:
        _LOGGER.debug(f"Start deleting user {username}")
        provider.data.async_remove_auth(username)
        users = await hass.auth.async_get_users()
        for user in users:
            if user.name == username:
                await hass.auth.async_remove_user(user)
        _LOGGER.debug(f"User was deleted: {username}")
    except Exception as e:
        _LOGGER.error(f"Exception in delete user: {e}")
