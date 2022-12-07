from __future__ import annotations
from platform import platform

from homeassistant.core import HomeAssistant
from homeassistant.auth import auth_manager_from_config, models

from substrateinterface import Keypair, KeypairType
from robonomicsinterface import Account
import logging
import typing as tp

_LOGGER = logging.getLogger(__name__)

from .const import (
    CONF_SUB_OWNER_ADDRESS,
    CONF_ADMIN_SEED,
    DOMAIN,
    ROBONOMICS,
)
from .utils import decrypt_message
import json

manage_users_queue = 0

async def get_provider(hass: HomeAssistant):
    """
    Returns Home Assistant auth provider
    """
    hass.auth = await auth_manager_from_config(
        hass, [{"type": "homeassistant"}], []
    )
    provider = hass.auth.auth_providers[0]
    await provider.async_initialize()
    return provider

async def create_user(hass: HomeAssistant, provider, username: str, password: str) -> None:
    """
    Create user in Home Assistant
    """
    try:
        _LOGGER.debug(f"Start creating user: {username}")
        provider.data.add_auth(username, password)
        creds = models.Credentials(
            auth_provider_type="homeassistant",
            auth_provider_id=None,
            data={"username": username},
            id=username,
            is_new=True,
        )
        resp = await hass.auth.async_get_or_create_user(creds)
        # new_user = await hass.auth.async_create_user(username, ["system-users"])
        # await async_create_person(hass, username, user_id=new_user.id)
        _LOGGER.debug(f"User was created: {username}, password: {password}")
    except Exception as e:
        _LOGGER.error(f"Exception in create user: {e}")

async def delete_user(hass: HomeAssistant, provider, username: str) -> None:
    """
    Delete user from Home Assistant
    """
    try:
        _LOGGER.debug(f"Start deleting user {username}")
        provider.data.async_remove_auth(username)
        users = await hass.auth.async_get_users()
        for user in users:
            if user.name == username:
                await hass.auth.async_remove_user(user)
        # await storage_collection.async_update_item(
        #         person[CONF_ID], {CONF_USER_ID: None}
        #     )
        _LOGGER.debug(f"User was deleted: {username}")
    except Exception as e:
        _LOGGER.error(f"Exception in delete user: {e}")

async def change_password(hass: HomeAssistant, data):
    """
    Chage password for existing user or create new user
    """
    _LOGGER.debug(f"Start setting password for username {data[0]}")
    provider = await get_provider(hass)
    sender_kp = Keypair(
            ss58_address=data[0], crypto_type=KeypairType.ED25519
        )
    rec_kp = Keypair.create_from_mnemonic(
        hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519
    )
    try:
        message = json.loads(data[2])
    except Exception as e:
        _LOGGER.warning(f"Message in Datalog is in wrong format: {e}\nMessage: {data[2]}")
        return
    if ("admin" in message) and (message["subscription"] == hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS]):
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
                    await delete_user(hass, provider, username)
            await create_user(hass, provider, username, password)
            
        except Exception as e:
            _LOGGER.error(f"Exception in change password: {e}")
            return
        _LOGGER.debug("Restarting...")
        await provider.data.async_save()
        await hass.services.async_call("homeassistant", "restart")

async def manage_users(hass: HomeAssistant, data: tp.Tuple(str), add_users: bool = True) -> None:
    """
    Compare users and data from transaction decide what users must be created or deleted
    """
    global manage_users_queue
    manage_users_queue += 1
    my_queue = manage_users_queue
    provider = await get_provider(hass)
    users = provider.data.users
    _LOGGER.debug(f"Begining users: {users}")
    usernames_hass = []
    for user in users:
        try:
            username = user["username"]
            if len(username) == 48 and username[0] == "4":
                usernames_hass.append(username)
        except Exception as e:
            _LOGGER.error(f"Exception from manage users: {e}")
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
    if add_users:
        for user in users_to_add:
            for device in hass.data[DOMAIN][ROBONOMICS].devices_list:
                if device.lower() == user:
                    sender_kp = Keypair(ss58_address=device, crypto_type=KeypairType.ED25519)
                    encrypted_password = await hass.data[DOMAIN][ROBONOMICS].find_password(device)
                    if encrypted_password != None:
                        password = str(decrypt_message(encrypted_password, sender_kp.public_key, rec_kp))
                        password = password[2:-1]
                        await create_user(hass, provider, user, password)
                        created_users += 1
                        break
                    else:
                        _LOGGER.debug(f"Password for user {user} wasn't found")
                
    for user in users_to_delete:
        await delete_user(hass, provider, user)

    if len(users_to_delete) > 0 or created_users > 0:
        await provider.data.async_save()
        _LOGGER.debug(f"Finishing user managment, user list: {provider.data.users}")
        if my_queue < manage_users_queue:
            _LOGGER.debug(f"Another thread will restart homeassistant")
            return
        _LOGGER.debug("Restarting...")
        manage_users_queue = 0
        await hass.services.async_call("homeassistant", "restart")