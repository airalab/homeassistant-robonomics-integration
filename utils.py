import nacl.bindings
import nacl.public
from substrateinterface import Keypair, KeypairType
import secrets
from typing import Union
import base64

def encrypt_message(
    message: Union[bytes, str], sender_keypair: Keypair, recipient_public_key: bytes, nonce: bytes = secrets.token_bytes(24),
) -> bytes:
    curve25519_public_key = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(recipient_public_key)
    recipient = nacl.public.PublicKey(curve25519_public_key)
    private_key = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(sender_keypair.private_key + sender_keypair.public_key)
    sender = nacl.public.PrivateKey(private_key)
    box = nacl.public.Box(sender, recipient)
    encrypted = box.encrypt(message if isinstance(message, bytes) else message.encode("utf-8"), nonce)
    return base64.b64encode(encrypted).decode("ascii")

def decrypt_message(encrypted_message: bytes, sender_public_key: bytes, recipient_keypair: Keypair) -> bytes:
    private_key = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(recipient_keypair.private_key + recipient_keypair.public_key)
    recipient = nacl.public.PrivateKey(private_key)
    curve25519_public_key = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(sender_public_key)
    sender = nacl.public.PublicKey(curve25519_public_key)
    encrypted = base64.b64decode(encrypted_message)
    return nacl.public.Box(recipient, sender).decrypt(encrypted)


def str2bool(v):
  return v.lower() in ("on", "true", "t", "1", 'y', 'yes', 'yeah')