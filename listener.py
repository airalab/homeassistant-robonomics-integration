from robonomicsinterface import RobonomicsInterface, Subscriber, SubEvent
import substrateinterface as substrate
import typing as tp
import asyncio
import functools
from async_class import AsyncClass

# def callback(data):
#     print(data)

# interface = RobonomicsInterface()
# subscriber = Subscriber(interface, SubEvent, callback, "4DUAnmLeEto197jDDSgvfjfS65MGvReMXibqp9ADg7ZgCDp9")

SUBSCRIPTION = True
DIGITAL_TWIN = False

def to_thread(func: tp.Callable) -> tp.Coroutine:
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        print("hi")
        return await asyncio.to_thread(func, *args, **kwargs)
    return wrapper

class SubscriptionListener(AsyncClass):
    async def __ainit__(self, owner_address: str, create_user: tp.Callable):
        self.address: str = owner_address
        self.create_user: tp.Callable = create_user
        interface: RobonomicsInterface = RobonomicsInterface()
        self.subscriber_interface: substrate.SubstrateInterface = substrate.SubstrateInterface(
                url=interface.remote_ws,
                ss58_format=32,
                type_registry_preset="substrate-node-template",
                type_registry=interface.type_registry,
            )
        await self.run()
        
    @to_thread
    def run(self):
        self.subscriber_interface.subscribe_block_headers(self.event_callback)

    def event_callback(self, index_obj: tp.Any, update_nr: int, subscription_id: int):
        if update_nr != 0:
            chain_events: list = self.subscriber_interface.query("System", "Events").value
            for events in chain_events:
                # print(events["event_id"])
                if events["event_id"] == "NewDevices":
                    if SUBSCRIPTION:
                        print(events["event"]["attributes"])
                        if events["event"]["attributes"][0] == self.address:
                            asyncio.create_task(self.create_user("hello", "hello"))
                            # await self.create_user("hello", "hello")
                elif events["event_id"] == "TopicChanged":
                    print(events["event"]["attributes"])