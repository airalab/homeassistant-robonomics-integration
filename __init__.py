from __future__ import annotations
from pickle import FALSE
from platform import platform

from homeassistant.components.sensor import SensorEntity
from homeassistant.components.person import async_create_person
from homeassistant.const import TEMP_CELSIUS
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.core import StateMachine as sm
from homeassistant.helpers.template import AllStates
from homeassistant.auth import auth_manager_from_config, auth_store, models

from homeassistant.helpers import device_registry as dr

from substrateinterface import SubstrateInterface, Keypair, KeypairType
from substrateinterface.exceptions import SubstrateRequestException
import asyncio
import nacl.secret
import requests
from homeassistant import *
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, StateMachine
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import *
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)
import logging
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from robonomicsinterface import Account, Subscriber, SubEvent, Datalog
from robonomicsinterface.utils import ipfs_32_bytes_to_qm_hash
import functools
from tenacity import retry, stop_after_attempt, wait_fixed
from substrateinterface.utils.ss58 import is_valid_ss58_address
import typing as tp
from pinatapy import PinataPy
import os
from aenum import extend_enum
from ast import literal_eval


DATALOG_SWITCH = False
CONTROL_SWITCH = False
ATTR_NAME = "name"
DEFAULT_NAME = "World"

ATTR_ENTITY = "entity_id"
DEFAULT_ENTITY = "sun.sun"
_LOGGER = logging.getLogger(__name__)
datalog_data = ''

SUBSCRIPTION = True

from .const import CONF_REPOS, DOMAIN
from .utils import encrypt_message, str2bool, generate_pass


def to_thread(func: tp.Callable) -> tp.Coroutine:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)
    return wrapper

async def call_service(hass: core.HomeAssistant, platform: str, name: str, params) -> None:
    try:
        await hass.services.async_call(platform, name, params)
        _LOGGER.debug(f"service worked")
    except Exception as e:
        _LOGGER.error(f"Call service exception: {e}")

@to_thread
def add_to_ipfs(pinata: PinataPy, data: str) -> str:
    with open("data_now", "w") as f:
        f.write(data)
    resp = pinata.pin_file_to_ipfs("data_now")
    _LOGGER.debug(f"Data pinned to IPFS with hash: {resp['IpfsHash']}")
    os.remove("data_now")
    return resp['IpfsHash']

async def async_setup_entry(
    hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry
) -> bool:
    """Set up platform from a ConfigEntry."""
    hass.data.setdefault(DOMAIN, {})
    conf = config_entry.data
    mnemonic = conf['seed']
    subscription_owner = conf['sub_owner_address']
    pinata = PinataPy(conf['pinata_pub'], conf['pinata_secret'])
    _LOGGER.debug(f"Robonomics user control starting set up")


    def subscribe(callback):
        try:
            account = Account()
            extend_enum(SubEvent, "MultiEvent", f"{SubEvent.NewDevices.value, SubEvent.NewLaunch.value}")
            Subscriber(account, SubEvent.MultiEvent, subscription_handler=callback)
            #Subscriber(interface, SubEvent.NewDevices, callback, subscription_owner)
        except Exception as e:
            _LOGGER.debug(f"subscribe exception {e}")

    async def get_provider():
        hass.auth = await auth_manager_from_config(hass, [{"type": "homeassistant"}], [])
        provider = hass.auth.auth_providers[0]
        await provider.async_initialize()
        return provider

    async def create_user(provider, username: str, password: str) -> None:
        """
        Create user in Home Assistant
        """
        try:
            _LOGGER.debug(f"Start creating user: {username}")
            provider.data.add_auth(username, password)
            creds = models.Credentials(auth_provider_type='homeassistant', 
                                    auth_provider_id=None, 
                                    data={'username': username}, 
                                    id=username, is_new=True)
            
            resp = await hass.auth.async_get_or_create_user(creds)
            # new_user = await hass.auth.async_create_user(username, ["system-users"])
            # await async_create_person(hass, username, user_id=new_user.id)
            _LOGGER.debug(f"User was created: {username}, password: {password}")
        except Exception as e:
            _LOGGER.error(f"Exception in create user: {e}")

    async def delete_user(provider, username: str) -> None:
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
            _LOGGER.debug(f"User was deleted: {user.name}")
        except Exception as e:
            _LOGGER.error(f"Exception in delete user: {e}")

    async def manage_users(data) -> None:
        """
        Compare users and data from transaction decide what users must be created or deleted
        """
        provider = await get_provider()

        # users = await hass.auth.async_get_users()
        users = provider.data.users
        print(f"Begining users: {users}")
        usernames_hass = []
        for user in users:
            try:
                username = user['username']
                # username = user.credentials[0].data['username']
                # print(username)
                if len(username) == 48 and username[0] == "4":
                    # print(f"here {username}")
                    usernames_hass.append(username)
                    # print(usernames_hass)
            except Exception as e:
                _LOGGER.error(f"Exception from manage users: {e}")
        _LOGGER.debug(f"Users before: {provider.data.users}")
        devices = data[1]
        devices = [device.lower() for device in devices]
        # _LOGGER.debug(f"Users {provider.data.users}")
        print(f"Devices: {set(devices)}")
        print(f"Users: {set(usernames_hass)}")
        users_to_add = list(set(devices) - set(usernames_hass))
        _LOGGER.debug(f"New users will be created: {users_to_add}")
        users_to_delete = list(set(usernames_hass) - set(devices))
        _LOGGER.debug(f"Following users will be deleted: {users_to_delete}")

        sender_kp = Keypair.create_from_mnemonic(mnemonic, crypto_type=KeypairType.ED25519)
        for user in users_to_add:
            password = generate_pass(6)
            await create_user(provider, user, password)
            for address in data[1]:
                if address.lower() == user:
                    try:
                        rec_kp = Keypair(ss58_address=address, crypto_type=KeypairType.ED25519)
                        encrypted = encrypt_message(f"Username: {address}, password: {password}", sender_kp, rec_kp.public_key)
                        await send_datalog(encrypted)
                    except Exception as e:
                        _LOGGER.error(f"create keypair exception: {e}")
        for user in users_to_delete:
            await delete_user(provider, user)

        if len(users_to_add) > 0 or len(users_to_delete) > 0:
            await provider.data.async_save()
            _LOGGER.debug(f"Finishing user managment, user list: {provider.data.users}")
            _LOGGER.debug("Restarting...")
            await hass.services.async_call("homeassistant", "restart")

    def handle_launch(data: str):
        ipfs_hash = ipfs_32_bytes_to_qm_hash(data)
        url = f"https://gateway.moralisipfs.com/ipfs/{ipfs_hash}/"
        message = requests.get(url) # 
        message = literal_eval(message)
        hass.services.call(message['platform'], message['name'], message['params'])

    @callback
    def callback_new_devices(data) -> None:
        _LOGGER.debug(f"Got NewDevices event: {data}")
        print(type(data[1]))
        if type(data[1]) == str and data[1] == sub_owner_address:
            handle_launch(data[2])
        elif type(data[1]) == list and data[0] == sub_owner_address:
            hass.async_create_task(manage_users(data))

    def get_states() -> tp.Dict[str, tp.Dict[str, tp.Union[str, tp.Dict[str, tp.Dict[str, tp.Union[str, float]]]]]]:
        registry = dr.async_get(hass)
        entity_registry = er.async_get(hass)
        devices_data = {}
        data = {}
        for entity in entity_registry.entities:
            entity_data = entity_registry.async_get(entity)
            if entity_data.device_id != None:
                entity_state = hass.states.get(entity)
                if entity_state != None:
                    try:
                        units = entity_state.attributes.get("unit_of_measurement")
                    except:
                        units = None
                    entity_info = {'device_class': entity_data.device_class, 'units': units, 'state': entity_state.state}
                    if entity_data.device_id not in devices_data:
                        device = registry.async_get(entity_data.device_id)
                        device_name = device.name_by_user if device.name_by_user != None else device.name
                        devices_data[entity_data.device_id] = {'name': device_name, 'entities': {entity_data.entity_id: entity_info}}
                    else:
                        devices_data[entity_data.device_id]['entities'][entity_data.entity_id] = entity_info
        return devices_data

    def fail_send_datalog(retry_state):
        _LOGGER.error(f"Failed send datalog, retry_state: {retry_state}")

    @to_thread
    @retry(stop=stop_after_attempt(5), wait=wait_fixed(5), retry_error_callback=fail_send_datalog)
    def send_datalog(data: str) -> None:
        interface = RobonomicsInterface(mnemonic)
        if SUBSCRIPTION:
            try:
                _LOGGER.debug(f"Start creating rws datalog")
                receipt = interface.rws_record_datalog(subscription_owner, data)
                _LOGGER.debug(f"Datalog created with hash: {receipt}")
            except Exception as e:
                _LOGGER.error(f"send rws datalog exception: {e}")
                raise e
        else:
            try:
                _LOGGER.debug(f"Start creating datalog")
                receipt = interface.record_datalog(data)
                _LOGGER.debug(f"Datalog created with hash: {receipt}")
            except Exception as e:
                _LOGGER.error(f"send datalog exception: {e}")
                raise e

    async def handle_datalog(call):
        """Handle the service call."""
        entity_id = call.data.get(ATTR_ENTITY, DEFAULT_ENTITY)
        state = hass.states.get(entity_id)
        _LOGGER.debug(f"Datalog service state: {state.state}")
        await send_datalog(state.state)

    hass.services.async_register(DOMAIN, "datalog_send", handle_datalog)

    async def get_and_send_data():
        try:
            sender_kp = Keypair.create_from_mnemonic(mnemonic, crypto_type=KeypairType.ED25519)
            data = get_states()
            _LOGGER.debug(f"Got states to send datalog: {data}")
            encrypted_data = encrypt_message(str(data), sender_kp, sender_kp.public_key)
            # ipfs_hash = await add_to_ipfs(pinata, encrypted_data)
            # await send_datalog(ipfs_hash)
        except Exception as e:
            _LOGGER.error(f"Exception in get_and_send_data: {e}")

    async def handle_state_changed(event):
        try:
            if (event.data['old_state'] != None and 
                    event.data['entity_id'].split('.')[0] == 'binary_sensor' and 
                    event.data['old_state'].state != event.data['new_state'].state):
                await get_and_send_data()
        except Exception as e:
            _LOGGER.error(f"Exception in handle_state_changed: {e}")

    async def handle_time_changed(event):
        try:
            if event.data['now'].minute % 5 == 0 and event.data['now'].second == 0:
                await get_and_send_data()
        except Exception as e:
            _LOGGER.error(f"Exception in handle_time_changed: {e}")

    hass.bus.async_listen("state_changed", handle_state_changed)
    hass.bus.async_listen("time_changed", handle_time_changed)

    hass.async_add_executor_job(subscribe, callback_new_devices)

    hass.states.async_set(f"{DOMAIN}.state", "Online")

    _LOGGER.debug(f"Robonomics user control successfuly set up")
    return True

async def async_setup(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:

    return True