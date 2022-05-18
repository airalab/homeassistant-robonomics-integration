from robonomicsinterface import RobonomicsInterface, Subscriber, SubEvent
from config import SUB_OWNER_SEED
from utils import decrypt

def callback(data):
    # print(data)
    decrypted = decrypt(SUB_OWNER_SEED, data[2]).decode()
    print(decrypted)

if __name__ == '__main__':
    interface = RobonomicsInterface(seed=SUB_OWNER_SEED)
    subscriber = Subscriber(interface, SubEvent.NewRecord, callback, interface.define_address())