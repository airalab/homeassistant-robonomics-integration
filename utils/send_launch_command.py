import json
import os

import ipfshttpclient2
from conf import (LAUNCH_COMMAND, LAUNCH_CONTROLLER_ADDRESS,
                  LAUNCH_GATEWAY_PORT, LAUNCH_GATEWAY_URL, LAUNCH_SEED,
                  LAUNCH_SUB_OWNER_ADDRESS)
from robonomicsinterface import Account, Launch
from robonomicsinterface.utils import ipfs_qm_hash_to_32_bytes, web_3_auth
from substrateinterface import Keypair, KeypairType

seed = LAUNCH_SEED
command = LAUNCH_COMMAND
controller_address = LAUNCH_CONTROLLER_ADDRESS
sub_owner_address = LAUNCH_SUB_OWNER_ADDRESS
url = LAUNCH_GATEWAY_URL
port = LAUNCH_GATEWAY_PORT
encrypt = True


def encrypt_message(
    message, sender_keypair: Keypair, recipient_public_key: bytes
) -> str:
    """
    Encrypt message with sender private key and recepient public key

    :param message: Message to encrypt
    :param sender_keypair: Sender account Keypair
    :param recipient_public_key: Recepient public key

    :return: encrypted message
    """
    encrypted = sender_keypair.encrypt_message(message, recipient_public_key)
    return f"0x{encrypted.hex()}"


message = json.dumps(command)
print(f"Message: {message}")
sender = Account(seed, crypto_type=KeypairType.ED25519)
if encrypt:
    recepient = Keypair(
        ss58_address=controller_address, crypto_type=KeypairType.ED25519
    )
    message = encrypt_message(message, sender.keypair, recepient.public_key)
    print(f"Ecrypted message: {message}")

filename = "temporal_file"
with open(filename, "w") as f:
    f.write(message)

usr, pwd = web_3_auth(seed)
with ipfshttpclient2.connect(
    addr=f"/dns4/{url}/tcp/{port}/https", auth=(usr, pwd)
) as client:
    result_ipfs = client.add(filename, pin=False)["Hash"]
print(f"IPFS hash: {result_ipfs}")
print(f"IPFS hash for launch {ipfs_qm_hash_to_32_bytes(result_ipfs)}")
os.remove(filename)

launch = Launch(sender, rws_sub_owner=sub_owner_address)
res = launch.launch(controller_address, result_ipfs)
print(f"Transaction result: {res}")
