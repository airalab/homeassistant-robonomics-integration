from substrateinterface import Keypair, KeypairType
from robonomicsinterface import Account
import functools
import asyncio
import logging
import os
import random
import string
import socket
import tempfile
import time
import typing as tp
import shutil
import json

import ipfshttpclient2
from homeassistant.components.persistent_notification import DOMAIN as NOTIFY_DOMAIN
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.json import JSONEncoder
from homeassistant.helpers.storage import Store

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)
VERSION_STORAGE = 6
SERVICE_PERSISTENT_NOTIFICATION = "create"

async def create_notification(hass: HomeAssistant, service_data: tp.Dict[str, str]) -> None:
    """Create HomeAssistant notification.

    :param hass: HomeAssistant instance
    :param service_data: Message for notification
    """
    service_data["notification_id"] =  DOMAIN
    await hass.services.async_call(
        domain=NOTIFY_DOMAIN,
        service=SERVICE_PERSISTENT_NOTIFICATION,
        service_data=service_data,
    )


def encrypt_message(message: tp.Union[bytes, str], sender_keypair: Keypair, recipient_public_key: bytes) -> str:
    """Encrypt message with sender private key and recipient public key

    :param message: Message to encrypt
    :param sender_keypair: Sender account Keypair
    :param recipient_public_key: Recipient public key

    :return: encrypted message
    """

    encrypted = sender_keypair.encrypt_message(message, recipient_public_key)
    return f"0x{encrypted.hex()}"


def decrypt_message(encrypted_message: str, sender_public_key: bytes, recipient_keypair: Keypair) -> str:
    """Decrypt message with recepient private key and sender puplic key

    :param encrypted_message: Message to decrypt
    :param sender_public_key: Sender public key
    :param recipient_keypair: Recepient account keypair

    :return: Decrypted message
    """

    if encrypted_message[:2] == "0x":
        encrypted_message = encrypted_message[2:]
    bytes_encrypted = bytes.fromhex(encrypted_message)

    return recipient_keypair.decrypt_message(bytes_encrypted, sender_public_key)


def encrypt_for_devices(data: str, sender_kp: Keypair, devices: tp.List[str]) -> str:
    """
    Encrypt data for random generated private key, then encrypt this key for device from the list

    :param data: Data to encrypt
    :param sender_kp: ED25519 account keypair that encrypts the data
    :param devices: List of ss58 ED25519 addresses

    :return: JSON string consists of encrypted data and a key encrypted for all accounts in the subscription
    """
    try:
        random_seed = Keypair.generate_mnemonic()
        random_acc = Account(random_seed, crypto_type=KeypairType.ED25519)
        encrypted_data = encrypt_message(str(data), sender_kp, random_acc.keypair.public_key)
        encrypted_keys = {}
        # _LOGGER.debug(f"Encrypt states for following devices: {devices}")
        for device in devices:
            try:
                receiver_kp = Keypair(ss58_address=device, crypto_type=KeypairType.ED25519)
                encrypted_key = encrypt_message(random_seed, sender_kp, receiver_kp.public_key)
            except Exception as e:
                _LOGGER.warning(f"Faild to encrypt key for: {device} with error: {e}")
            encrypted_keys[device] = encrypted_key
        encrypted_keys["data"] = encrypted_data
        data_final = json.dumps(encrypted_keys)
        return data_final
    except Exception as e:
        _LOGGER.error(f"Exception in encrypt for devices: {e}")


def decrypt_message_devices(data: tp.Union[str, dict], sender_public_key: bytes, recipient_keypair: Keypair) -> str:
    """Decrypt message that was encrypted fo devices
    
    :param data: Ancrypted data
    :param sender_public_key: Sender address
    :param recipient_keypair: Recepient account keypair

    :return: Decrypted message
    """
    try:
        _LOGGER.debug(f"Start decrypt for device {recipient_keypair.ss58_address}")
        if type(data) == str:
            data_json = json.loads(data)
        else:
            data_json = data
        if recipient_keypair.ss58_address in data_json:
            decrypted_seed = decrypt_message(data_json[recipient_keypair.ss58_address], sender_public_key, recipient_keypair).decode("utf-8")
            decrypted_acc = Account(decrypted_seed, crypto_type=KeypairType.ED25519)
            decrypted_data = decrypt_message(data_json["data"], sender_public_key, decrypted_acc.keypair).decode("utf-8")
            return decrypted_data
        else:
            _LOGGER.error(f"Error in decrypt for devices: account is not in devices")
    except Exception as e:
        _LOGGER.error(f"Exception in decrypt for devices: {e}")


def generate_password(length: int = 10) -> str:
    """Generate random string with the given length

    :param lenght: Password length

    :return: Generated password
    """

    letters = string.ascii_letters + string.digits
    return "".join(random.choice(letters) for i in range(length))


def to_thread(func: tp.Callable) -> tp.Coroutine:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return wrapper


@to_thread
def get_hash(filename: str) -> tp.Optional[str]:
    """Getting file's IPFS hash

    :param filename: Path to the backup file

    :return: Hash of the file or None
    """

    try:
        with ipfshttpclient2.connect() as client:
            ipfs_hash_local = client.add(filename, pin=False)["Hash"]
    except Exception as e:
        _LOGGER.error(f"Exception in get_hash with local node: {e}")
        ipfs_hash_local = None
    return ipfs_hash_local


def write_data_to_temp_file(data: tp.Union[str, bytes], config: bool = False, filename: str = None) -> str:
    """
    Create file and store data in it

    :param data: data, which to be written to the file
    :param config: is file fo config (True) or for telemetry (False)
    :param filename: Name of the file if not config or z2m backup

    :return: path to created file
    """
    dirname = tempfile.gettempdir()
    if filename is not None:
        filepath = f"{dirname}/{filename}"
        if type(data) == str:
            with open(filepath, "w") as f:
                f.write(data)
        else:
            with open(filepath, "wb") as f:
                f.write(data)
    else:
        if type(data) == str:
            if config:
                filepath = f"{dirname}/config_encrypted-{time.time()}"
            else:
                filepath = f"{dirname}/data-{time.time()}"
            with open(filepath, "w") as f:
                f.write(data)
        else:
            filepath = f"{dirname}/z2m-backup.zip"
            with open(filepath, "wb") as f:
                f.write(data)
    return filepath


def delete_temp_dir(dirpath: str) -> None:
    """
    Delete temporary directory

    :param dirpath: the path to the directory
    """
    shutil.rmtree(dirpath)


def delete_temp_file(filename: str) -> None:
    """
    Delete temporary file

    :param filename: the name of the file to delete
    """
    os.remove(filename)


def _get_store_for_key(hass: HomeAssistant, key: str):
    """Create a Store object for the key."""
    return Store(hass, VERSION_STORAGE, f"robonomics.{key}", encoder=JSONEncoder, atomic_writes=True)


async def async_load_from_store(hass, key):
    """Load the retained data from store and return de-serialized data."""
    return await _get_store_for_key(hass, key).async_load() or {}

async def async_remove_store(hass: HomeAssistant, key: str):
    """Remove data from store for given key"""
    await _get_store_for_key(hass, key).async_remove()


async def async_save_to_store(hass, key, data) -> bool:
    """Generate dynamic data to store and save it to the filesystem.

    The data is only written if the content on the disk has changed
    by reading the existing content and comparing it.

    If the data has changed this will generate two executor jobs

    If the data has not changed this will generate one executor job
    """
    current = await async_load_from_store(hass, key)
    if current is None or current != data:
        await _get_store_for_key(hass, key).async_save(data)
        return
    _LOGGER.debug(f"Content in .storage/robonomics.{key} was't changed")

async def add_or_change_store(
    hass: HomeAssistant, store_key: str, data_key: str, data_value: str
) -> None:
    current_data = await async_load_from_store(hass, store_key)
    if current_data is None:
        current_data = {}
    current_data[data_key] = data_value
    await async_save_to_store(hass, store_key, current_data)


async def remove_from_store(hass: HomeAssistant, store_key: str, data_key: str) -> None:
    current_data = await async_load_from_store(hass, store_key)
    if current_data is not None:
        if current_data.pop(data_key, None):
            await async_save_to_store(hass, store_key, current_data)

async def async_post_request(hass: HomeAssistant, url: str, headers: dict, data: str) -> tp.Optional[dict]:
    _LOGGER.debug(f"Request to {url} with data: {data}")
    websession = async_create_clientsession(hass)  
    resp = await websession.post(url, headers=headers, data=data)
    if resp.status == 200:
        return await resp.json()
    else:
        _LOGGER.error(f"Post request faild with response {resp.status}")

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        ip_address = s.getsockname()[0]
        return ip_address
    except socket.error:
        return None

def verify_sign(signature: str, address: str) -> bool:
    try:
        if signature.startswith("0x"):
            signature = signature[2:]
        signature_bytes = bytes.fromhex(signature)
        keypair = Keypair(ss58_address=address, crypto_type=KeypairType.ED25519)
        return keypair.verify(address, signature_bytes)
    except Exception as e:
        _LOGGER.error(f"Exception during signature verification: {e}")

def format_libp2p_node_multiaddress(peer_id: str) -> tp.Optional[str]:
    """Format libp2p node local multiaddress from ip and peer id.

    :param peer_id: Peer id of the libp2p node.
    :return: Formatted multiaddress or None.
    """

    ip_address = get_ip_address()
    _LOGGER.debug(f"IP address {ip_address}")
    if (ip_address is not None) and (peer_id):
        multiaddress = f"/ip4/{ip_address}/tcp/9999/ws/p2p/{peer_id}"
        return multiaddress