import os
import typing as tp
from substrateinterface import KeypairType, Keypair
from nacl.secret import SecretBox

from .sr25519_const import NONCE_SIZE, DERIVATION_KEY_SALT_SIZE
from .sr25519_utils import get_sr25519_agreement, derive_key, bytes_concat, generate_mac_data


def sr25519_encrypt(message: str | bytes,
                    receiver_public_key: bytes,
                    sender_keypair: tp.Optional[Keypair] = None
                    ) -> bytes:

    # 1. Ephemeral key generation if no sender keypair is provided
    if sender_keypair is not None:
        message_keypair = sender_keypair
    else:
        message_keypair = Keypair.create_from_mnemonic(
            mnemonic=Keypair.generate_mnemonic(),
            crypto_type=KeypairType.SR25519
        )

    # 2. Key agreement
    agreement_key = get_sr25519_agreement(secret_key=message_keypair.private_key,
                                          public_key=receiver_public_key)

    # 2.5 Master secret and cryptographic random salt with KEY_DERIVATION_SALT_SIZE bytes
    master_secret = bytes_concat(message_keypair.public_key, agreement_key)
    salt = os.urandom(DERIVATION_KEY_SALT_SIZE)

    # 3. Key derivation
    encryption_key, mac_key = derive_key(master_secret, salt)

    # 4 Encryption
    nonce = os.urandom(NONCE_SIZE)
    encrypted_message = _nacl_encrypt(message, encryption_key, nonce)

    # 5 MAC Generation
    mac_value = generate_mac_data(
        nonce=nonce,
        encrypted_message=encrypted_message,
        message_public_key=message_keypair.public_key,
        mac_key=mac_key
    )

    return bytes_concat(nonce, salt, message_keypair.public_key, mac_value, encrypted_message)

def _nacl_encrypt(message: str | bytes, encryption_key: bytes, nonce: bytes) -> bytes:
    # Ensure the encryption key is 32 bytes
    if len(encryption_key) != 32:
        raise ValueError("Encryption key must be 32 bytes long.")

    # Create a nacl SecretBox using the encryption key
    box = SecretBox(encryption_key)

    try:
        # Encrypt the message
        encrypted_message = box.encrypt(_message_to_bytes(message), nonce)
        return encrypted_message.ciphertext
    except Exception as e:
        raise ValueError("Invalid secret or pubkey provided") from e
    
def _message_to_bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return value
    elif isinstance(value, str):
        return value.encode('utf-8')
    else:
        raise TypeError("Unsupported message type for encryption")