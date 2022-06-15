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
from homeassistant.helpers.event import async_track_time_interval

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
from tenacity import retry, stop_after_attempt, wait_fixed
from substrateinterface.utils.ss58 import is_valid_ss58_address
import typing as tp
from pinatapy import PinataPy
import os
from aenum import extend_enum
from ast import literal_eval
import ipfsApi
import time
import getpass
import http3
from datetime import timedelta

_LOGGER = logging.getLogger(__name__)

from .const import (
    MORALIS_GATEWAY,
    IPFS_GATEWAY,
    INFURA_API,
    CONF_PINATA_PUB,
    CONF_PINATA_SECRET,
    CONF_REPOS,
    CONF_SUB_OWNER_ED,
    CONF_SUB_OWNER_SEED,
    CONF_USER_ED,
    CONF_USER_SEED,
    DOMAIN,
    CONF_SENDING_TIMEOUT
)
from .utils import encrypt_message, str2bool, generate_pass, decrypt_message, to_thread
from .robonomics import Robonomics



async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Robonomics Control from a config entry."""
    # TODO Store an API object for your platforms to access
    # hass.data[DOMAIN][entry.entry_id] = MyApi(...)

    hass.data.setdefault(DOMAIN, {})
    _LOGGER.debug(f"Robonomics user control starting set up")
    conf = entry.data
    sending_timeout = timedelta(minutes=conf[CONF_SENDING_TIMEOUT])
    _LOGGER.debug(f"Sending interval: {conf[CONF_SENDING_TIMEOUT]} minutes")
    user_mnemonic: str = conf[CONF_USER_SEED]
    sub_owner_seed: str = conf[CONF_SUB_OWNER_SEED]
    robonomics: Robonomics = Robonomics(
                            hass,
                            sub_owner_seed,
                            conf[CONF_SUB_OWNER_ED],
                            user_mnemonic,
                            conf[CONF_USER_ED]
                            )
    if (CONF_PINATA_PUB in conf) and (CONF_PINATA_SECRET in conf):
        pinata = PinataPy(conf[CONF_PINATA_PUB], conf[CONF_PINATA_SECRET])
        _LOGGER.debug("Use Pinata to pin files")
    else: 
        pinata = None
        _LOGGER.debug("Use local node to pin files")
    data_path = f"/home/{getpass.getuser()}/ha_robonomics_data"
    if not os.path.isdir(data_path):
        os.mkdir(data_path)
    api = ipfsApi.Client('127.0.0.1', 5001)

    @to_thread
    def add_to_ipfs(api: ipfsApi.Client, data: str, data_path, pinata: PinataPy = None) -> str:
        filename = f"{data_path}/data{time.time()}"
        with open(filename, "w") as f:
            f.write(data)
        if pinata is not None:
            res = pinata.pin_file_to_ipfs(filename)
            ipfs_hash = res['IpfsHash']
        files = {
        'file': (data),
        }
        try:
            response = requests.post(INFURA_API, files=files)
            p = response.json()
            ipfs_hash_infura = p['Hash']
        except Exception as e:
            _LOGGER.error(f"Pin to infura exception: {e}")
        res = api.add(filename)
        ipfs_hash_local = res[0]['Hash']

        _LOGGER.debug(f"Data pinned to IPFS with hash: {ipfs_hash_local}")
        return ipfs_hash_local

    async def get_provider():
        hass.auth = await auth_manager_from_config(
            hass, [{"type": "homeassistant"}], []
        )
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

    async def manage_users(data: tp.Tuple(str)) -> None:
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
                username = user["username"]
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

        sender_kp = Keypair.create_from_mnemonic(
            sub_owner_seed, crypto_type=KeypairType.ED25519
        )
        for user in users_to_add:
            password = generate_pass(6)
            await create_user(provider, user, password)
            for address in data[1]:
                if address.lower() == user:
                    try:
                        rec_kp = Keypair(
                            ss58_address=address, crypto_type=KeypairType.ED25519
                        )
                        encrypted = encrypt_message(
                            f"Username: {address}, password: {password}",
                            sender_kp,
                            rec_kp.public_key,
                        )
                    except Exception as e:
                        _LOGGER.error(f"create keypair exception: {e}")
                    await robonomics.send_datalog_creds(encrypted)
        for user in users_to_delete:
            await delete_user(provider, user)

        if len(users_to_add) > 0 or len(users_to_delete) > 0:
            await provider.data.async_save()
            _LOGGER.debug(f"Finishing user managment, user list: {provider.data.users}")
            _LOGGER.debug("Restarting...")
            await hass.services.async_call("homeassistant", "restart")

    async def get_ipfs_data(
                ipfs_hash: str, 
                gateways: tp.List[str] = [IPFS_GATEWAY, 
                                        MORALIS_GATEWAY]   
                ) -> str:
        client = http3.AsyncClient()
        try:
            for gateway in gateways:
                if gateway[-1] != "/":
                    gateway += "/"
                url = f"{gateway}{ipfs_hash}"
                resp = await client.get(url)
                _LOGGER.debug(f"Response from {gateway}: {resp.status_code}")
                if resp.status_code == 200:
                    return resp.text
            else:
                return await get_ipfs_data(ipfs_hash, gateways)
        except Exception as e:
            _LOGGER.error(f"Exception in get ipfs: {e}")
            return await get_ipfs_data(ipfs_hash, gateways)

    @callback
    async def handle_launch(data: tp.List[str]) -> None:
        _LOGGER.debug("Start handle launch")
        try:
            ipfs_hash = ipfs_32_bytes_to_qm_hash(data[2])
            response_text = await get_ipfs_data(ipfs_hash)  # {'platform': 'light', 'name', 'turn_on', 'params': {'entity_id': 'light.lightbulb'}}
        except Exception as e:
            _LOGGER.error(f"Exception in get ipfs command: {e}")
            return
        _LOGGER.debug(f"Got from launch: {response_text}")
        if "platform" in response_text:
            message = literal_eval(response_text)
        else:
            kp_sender = Keypair(ss58_address=data[0], crypto_type=KeypairType.ED25519)
            if conf[CONF_SUB_OWNER_ED]:
                subscription_owner = Account(
                    seed=sub_owner_seed, crypto_type=KeypairType.ED25519
                )
            else:
                subscription_owner = Account(seed=sub_owner_seed, crypto_type=KeypairType.ED25519)
            try:
                decrypted = decrypt_message(response_text, kp_sender.public_key, subscription_owner.keypair)
            except Exception as e:
                _LOGGER.error(f"Exception in decript command: {e}")
                return
            decrypted = str(decrypted)[2:-1]
            _LOGGER.debug(f"Decrypted command: {decrypted}")
            message = literal_eval(decrypted)
        try:
            hass.async_create_task(
                hass.services.async_call(
                    message["platform"], message["name"], message["params"]
                )
            )
        except Exception as e:
            _LOGGER.error(f"Exception in sending command: {e}")
            

    def get_states() -> tp.Dict[
        str,
        tp.Dict[str, tp.Union[str, tp.Dict[str, tp.Dict[str, tp.Union[str, float]]]]],
    ]:
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
                    entity_info = {
                        "device_class": entity_data.device_class,
                        "units": units,
                        "state": entity_state.state,
                    }
                    if entity_data.device_id not in devices_data:
                        device = registry.async_get(entity_data.device_id)
                        device_name = (
                            device.name_by_user
                            if device.name_by_user != None
                            else device.name
                        )
                        devices_data[entity_data.device_id] = {
                            "name": device_name,
                            "entities": {entity_data.entity_id: entity_info},
                        }
                    else:
                        devices_data[entity_data.device_id]["entities"][
                            entity_data.entity_id
                        ] = entity_info
        return devices_data

    # async def handle_datalog(call):
    #     """Handle the service call."""
    #     entity_id = call.data.get(ATTR_ENTITY, DEFAULT_ENTITY)
    #     state = hass.states.get(entity_id)
    #     _LOGGER.debug(f"Datalog service state: {state.state}")
    #     await send_datalog(state.state)

    # hass.services.async_register(DOMAIN, "datalog_send", handle_datalog)

    async def get_and_send_data():
        try:
            sender_acc = Account(seed=user_mnemonic, crypto_type=KeypairType.ED25519)
            sender_kp = sender_acc.keypair
            data = get_states()
            _LOGGER.debug(f"Got states to send datalog: {data}")
            encrypted_data = encrypt_message(str(data), sender_kp, sender_kp.public_key)
            await asyncio.sleep(2)
            ipfs_hash = await add_to_ipfs(api, encrypted_data, data_path, pinata=pinata)
            await robonomics.send_datalog_states(ipfs_hash)
        except Exception as e:
            _LOGGER.error(f"Exception in get_and_send_data: {e}")
        

    async def handle_state_changed(event):
        try:
            if (
                    event.data["old_state"] != None
                    and event.data["old_state"].state != "unknown"
                    and event.data["entity_id"].split(".")[0] == "binary_sensor"
                    and event.data["old_state"].state != event.data["new_state"].state
                ):
                print(f"State changed: {event.data}")
                await get_and_send_data()
        except Exception as e:
            _LOGGER.error(f"Exception in handle_state_changed: {e}")

    async def handle_time_changed(event):
        try:
            print(f"State changed: {event}")
            await get_and_send_data()
        except Exception as e:
            _LOGGER.error(f"Exception in handle_time_changed: {e}")


    hass.bus.async_listen("state_changed", handle_state_changed)
    async_track_time_interval(hass, handle_time_changed, sending_timeout)

    hass.async_add_executor_job(robonomics.subscribe, handle_launch, manage_users)

    hass.states.async_set(f"{DOMAIN}.state", "Online")

    _LOGGER.debug(f"Robonomics user control successfuly set up")

    # hass.config_entries.async_setup_platforms(entry, PLATFORMS)

    return True

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:

    _LOGGER.debug(f"setup data: {config.get(DOMAIN)}")

    return True

# async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
#     """Unload a config entry."""
#     print(f"hass.data: {hass.data}")
#     print(f"entry id: {entry.entry_id}")
#     print(f"hass domain data: {hass.data[DOMAIN][entry.entry_id]}")
#     component: EntityComponent = hass.data[DOMAIN]
#     return await component.async_unload_entry(entry)

# async def async_remove_entry(hass, entry) -> None:
#     """Handle removal of an entry."""