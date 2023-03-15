import asyncio
import functools
import logging
import os
import random
import string
import tempfile
import time
import typing as tp
from typing import Union

import ipfshttpclient2
from homeassistant.components.notify.const import DOMAIN as NOTIFY_DOMAIN
from homeassistant.components.notify.const import SERVICE_PERSISTENT_NOTIFICATION
from homeassistant.core import HomeAssistant
from substrateinterface import Keypair

_LOGGER = logging.getLogger(__name__)


async def create_notification(hass: HomeAssistant, service_data: tp.Dict[str, str]) -> None:
    """Create HomeAssistant notification.

    :param hass: HomeAssistant instance
    :param service_data: Message for notification
    """

    await hass.services.async_call(
        domain=NOTIFY_DOMAIN,
        service=SERVICE_PERSISTENT_NOTIFICATION,
        service_data=service_data,
    )


def encrypt_message(message: Union[bytes, str], sender_keypair: Keypair, recipient_public_key: bytes) -> str:
    """Encrypt message with sender private key and recepient public key

    :param message: Message to encrypt
    :param sender_keypair: Sender account Keypair
    :param recipient_public_key: Recepient public key

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


def generate_pass(length: int) -> str:
    """Generate random low letter string with the given length

    :param lenght: Password length

    :return: Generated password
    """

    letters = string.ascii_lowercase
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


def write_data_to_temp_file(data: str, config: bool = False) -> str:
    """
    Create file and store data in it

    :param data: data, which to be written to the file
    :param config: is file fo config (True) or for telemetry (False)

    :return: path to created file
    """
    dirname = tempfile.gettempdir()
    if config:
        filename = f"{dirname}/config_encrypted-{time.time()}"
    else:
        filename = f"{dirname}/data-{time.time()}"
    with open(filename, "w") as f:
        f.write(data)
    return filename


def delete_temp_file(filename: str) -> None:
    """
    Delete temporary file

    :param filename: the name of the file to delete
    """
    os.remove(filename)
