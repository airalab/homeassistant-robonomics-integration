import json

from conf import LAUNCH_CONTROLLER_ADDRESS, LAUNCH_SEED, URL_TO_READ
from requests import get
from robonomicsinterface import Account
from substrateinterface import Keypair, KeypairType


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


def main():
    sender = Account(LAUNCH_SEED, crypto_type=KeypairType.ED25519)
    print(f"Get request to {URL_TO_READ}")
    resp = get(URL_TO_READ)
    print(f"Response: {resp.status_code}")
    encrypted = resp.text
    encr_json = json.loads(encrypted)
    new_encr_seed = encr_json[sender.get_address()]
    new_seed = decrypt_message(new_encr_seed, sender.keypair.public_key, sender.keypair)
    new_sender = Account(new_seed.decode(), crypto_type=KeypairType.ED25519)
    encrypted_message = encr_json["data"]

    message = decrypt_message(encrypted_message, sender.keypair.public_key, new_sender.keypair)
    # encrypted_message = encrypted
    # message = decrypt_message(encrypted_message, sender.keypair.public_key, sender.keypair)
    # with open("decrypted.tar.xz", "wb") as f:
    #      f.write(message)
    message = message.decode("utf-8")
    with open("decrypted", "w") as f:
        f.write(message)
    json_message = json.loads(message)
    return json_message


main()
