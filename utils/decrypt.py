import json

from conf import LAUNCH_CONTROLLER_ADDRESS, LAUNCH_SEED, URL_TO_READ
from requests import get
from robonomicsinterface import Account
from substrateinterface import Keypair, KeypairType


def decrypt_message(encrypted_message: str, sender_public_key: bytes, recipient_keypair: Keypair) -> str:
    if encrypted_message[:2] == "0x":
        encrypted_message = encrypted_message[2:]
    bytes_encrypted = bytes.fromhex(encrypted_message)
    return recipient_keypair.decrypt_message(bytes_encrypted, sender_public_key)

# def decrypt_message_devices(
#     data, sender_public_key: bytes, recipient_keypair: Keypair
# ) -> str:
#     try:
#         print(f"Start decrypt for device {recipient_keypair.ss58_address}")
#         if isinstance:
#             data_json = json.loads(data)
#         else:
#             data_json = data
#         if recipient_keypair.ss58_address in data_json:
#             decrypted_seed = decrypt_message(
#                 data_json[recipient_keypair.ss58_address],
#                 sender_public_key,
#                 recipient_keypair,
#             ).decode("utf-8")
#             decrypted_acc = Account(decrypted_seed, crypto_type=KeypairType.ED25519)
#             decrypted_data = decrypt_message(
#                 data_json["data"], sender_public_key, decrypted_acc.keypair
#             ).decode("utf-8")
#             return decrypted_data
#         else:
#             print("Error in decrypt for devices: account is not in devices")
#     except Exception as e:
#         print(f"Exception in decrypt for devices: {e}")


def main():
    sender = Account(LAUNCH_SEED, crypto_type=KeypairType.ED25519)
    controller_kp = Keypair(ss58_address=LAUNCH_CONTROLLER_ADDRESS)
    print(f"Get request to {URL_TO_READ}")
    resp = get(URL_TO_READ)
    print(f"Response: {resp.status_code}")
    encrypted = resp.text
    encr_json = json.loads(encrypted)
    print(f"Encrypted seed: {encr_json[sender.get_address()]}")
    new_encr_seed = encr_json[sender.get_address()]
    new_seed = decrypt_message(new_encr_seed, controller_kp.public_key, sender.keypair)
    print(f"Decrypted seed: {new_seed.decode()}")
    new_sender = Account(new_seed.decode(), crypto_type=KeypairType.ED25519)
    encrypted_message = encr_json["data"]

    message = decrypt_message(encrypted_message, controller_kp.public_key, new_sender.keypair)
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
