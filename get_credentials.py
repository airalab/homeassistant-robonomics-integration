from robonomicsinterface import RobonomicsInterface, Subscriber, SubEvent
from config import SUB_OWNER_ADDRESS, USER_SEED
from utils import decrypt_message

def callback(data):
    # print(data)
    recep_kp = Keypair.create_from_mnemonic(USER_SEED, crypto_type=KeypairType.ED25519)
    sender_kp = Keypair(ss58_address=SUB_OWNER_ADDRESS, crypto_type=KeypairType.ED25519)
    decrypted = decrypt_message(data[2], recep_kp, sender_kp.public_key)
    print(decrypted)

if __name__ == '__main__':
    interface = RobonomicsInterface()
    subscriber = Subscriber(interface, SubEvent.NewRecord, callback, SUB_OWNER_ADDRESS)