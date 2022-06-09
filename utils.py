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
    curve25519_public_key = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(recipient_public_key)
    recipient = nacl.public.PublicKey(curve25519_public_key)
    private_key = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(sender_keypair.private_key + sender_keypair.public_key)
    sender = nacl.public.PrivateKey(private_key)
    box = nacl.public.Box(sender, recipient)
    encrypted = box.encrypt(message if isinstance(message, bytes) else message.encode("utf-8"), secrets.token_bytes(24))
    return base64.b64encode(encrypted).decode("ascii")

def decrypt_message(encrypted_message: bytes, sender_public_key: bytes, recipient_keypair: Keypair) -> str:
    """
    Decrypt message with recepient private key and sender puplic key

    :param encrypted_message: Message to decrypt
    :param sender_public_key: Sender public key
    :param recipient_keypair: Recepient account keypair

    :return: Decrypted message
    """
    private_key = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(recipient_keypair.private_key + recipient_keypair.public_key)
    recipient = nacl.public.PrivateKey(private_key)
    curve25519_public_key = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(sender_public_key)
    sender = nacl.public.PublicKey(curve25519_public_key)
    encrypted = base64.b64decode(encrypted_message)
    return nacl.public.Box(recipient, sender).decrypt(encrypted)

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