import nacl.bindings
import nacl.public
from substrateinterface import Keypair, KeypairType
import secrets
from typing import Union
import base64
import random, string
import functools
import typing as tp
import asyncio

def encrypt_message(message: Union[bytes, str], sender_keypair: Keypair, recipient_public_key: bytes) -> str:
    """
    Encrypt message with sender private key and recepient public key

    :param message: Message to encrypt
    :param sender_keypair: Sender account Keypair
    :param recipient_public_key: Recepient public key

    :return: encrypted message
    """
    encrypted = sender_keypair.encrypt_message(message, recipient_public_key)
    return f"0x{encrypted.hex()}"

def decrypt_message(encrypted_message: str, sender_public_key: bytes, recipient_keypair: Keypair) -> str:
    """
    Decrypt message with recepient private key and sender puplic key

    :param encrypted_message: Message to decrypt
    :param sender_public_key: Sender public key
    :param recipient_keypair: Recepient account keypair

    :return: Decrypted message
    """
    if encrypted_message[:2] == "0x":
        encrypted_message = encrypted_message[2:]
    bytes_encrypted = bytes.fromhex(encrypted_message)

    return recipient_keypair.decrypt_message(bytes_encrypted, sender_public_key)

def str2bool(v):
    return v.lower() in ("on", "true", "t", "1", 'y', 'yes', 'yeah')

def generate_pass(length: int) -> str:
    """
    Generate random low letter string with the given length

    :param lenght: Password length

    :return: Generated password
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def to_thread(func: tp.Callable) -> tp.Coroutine:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)
    return wrapper