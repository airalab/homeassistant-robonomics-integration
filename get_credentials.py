from robonomicsinterface import Account, Subscriber, SubEvent
from utils import decrypt_message
from substrateinterface import Keypair

def callback(data):
    # print(data)
    recep_kp = Keypair.create_from_mnemonic(USER_SEED, crypto_type=KeypairType.ED25519)
    sender_kp = Keypair(ss58_address=SUB_OWNER_ADDRESS, crypto_type=KeypairType.ED25519)
    decrypted = decrypt_message(data[2], recep_kp, sender_kp.public_key)
    print(decrypted)

if __name__ == '__main__':
    interface = Account()
    subscriber = Subscriber(interface, SubEvent.NewRecord, callback, SUB_OWNER_ADDRESS)