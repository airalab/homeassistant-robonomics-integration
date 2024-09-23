import hashlib
import hmac

import rbcl

from .sr25519_const import (
    DERIVATION_KEY_ROUNDS,
    DERIVATION_KEY_SIZE,
    ENCRYPTION_KEY_SIZE,
    MAC_KEY_SIZE,
    PBKDF2_HASH_ALGORITHM,
)


def get_sr25519_agreement(secret_key: bytes, public_key: bytes) -> bytes:
    try:
        # Get canonical part of secret key
        canonical_secret_key = secret_key[:32]

        # Perform elliptic curve point multiplication
        # Since secret and public key are already in sr25519, that can be used as scalar and Ristretto point
        shared_secret = rbcl.crypto_scalarmult_ristretto255(
            s=canonical_secret_key, p=public_key
        )

        return shared_secret
    except Exception as e:
        raise ValueError("Invalid secret or pubkey provided") from e


def derive_key(master_secret: bytes, salt: bytes) -> tuple:
    # Derive a 64-byte key using PBKDF2
    password = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_ALGORITHM,
        master_secret,
        salt,
        DERIVATION_KEY_ROUNDS,  # Number of iterations
        dklen=DERIVATION_KEY_SIZE,  # Desired length of the derived key
    )

    assert (
        len(password) >= MAC_KEY_SIZE + ENCRYPTION_KEY_SIZE
    ), "Wrong derived key length"

    # Split the derived password into encryption key and MAC key
    mac_key = password[:MAC_KEY_SIZE]
    encryption_key = password[MAC_KEY_SIZE : MAC_KEY_SIZE + ENCRYPTION_KEY_SIZE]

    return encryption_key, mac_key


def generate_mac_data(
    nonce: bytes, encrypted_message: bytes, message_public_key: bytes, mac_key: bytes
) -> bytes:
    if len(mac_key) != 32:
        raise ValueError("MAC key must be 32 bytes long.")

    # Concatenate nonce, message public key, and encrypted message
    data_to_mac = bytes_concat(nonce, message_public_key, encrypted_message)

    # Generate HMAC-SHA256
    mac_data = hmac.new(key=mac_key, msg=data_to_mac, digestmod=hashlib.sha256).digest()
    return mac_data


def bytes_concat(*arrays) -> bytes:
    """
    Concatenate multiple byte arrays into a single byte array.

    Args:
        *arrays: Variable length argument list of byte arrays to concatenate.

    Returns:
        bytes: A single concatenated byte array.
    """
    return b"".join(arrays)
