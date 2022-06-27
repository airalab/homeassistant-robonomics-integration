from substrateinterface import SubstrateInterface, Keypair, KeypairType
from robonomicsinterface import Account, Subscriber, SubEvent, Datalog, RWS
from robonomicsinterface.utils import ipfs_32_bytes_to_qm_hash
from aenum import extend_enum
from homeassistant.core import callback, HomeAssistant
import logging
import typing as tp
import asyncio
import time
from tenacity import retry, stop_after_attempt, wait_fixed
from .utils import encrypt_message, str2bool, generate_pass, decrypt_message, to_thread

_LOGGER = logging.getLogger(__name__)

def fail_send_datalog(retry_state):
        _LOGGER.error(f"Failed send datalog, retry_state: {retry_state}")

class Robonomics:
    def __init__(self,
                hass: HomeAssistant, 
                sub_owner_seed: str, 
                sub_owner_ed: bool, 
                sub_admin_seed: str, 
                sub_admin_ed: bool
                ) -> None:
        self.hass: HomeAssistant = hass
        self.sub_owner_seed: str = sub_owner_seed
        self.sub_owner_ed: bool = sub_owner_ed
        self.sub_admin_seed: str = sub_admin_seed
        self.sub_admin_ed: bool = sub_admin_ed
        self.sending: bool = False
        self.on_queue: int = 0

    def subscribe(self, handle_launch: tp.Callable, manage_users: tp.Callable) -> None:
        """
        Subscribe to NewDevices and NewLaunch events

        :param handle_launch: Call this function if NewLaunch event
        :param manage_users: Call this function if NewDevices event

        """
        self.handle_launch: tp.Callable = handle_launch
        self.manage_users: tp.Callable = manage_users
        try:
            account = Account()
            extend_enum(
                SubEvent,
                "MultiEvent",
                f"{SubEvent.NewDevices.value, SubEvent.NewLaunch.value}",
            )
            Subscriber(account, SubEvent.MultiEvent, subscription_handler=self.callback_new_event)
        except Exception as e:
            _LOGGER.debug(f"subscribe exception {e}")
    
    @callback
    def callback_new_event(self, data: tp.Tuple[tp.Union[str, tp.List[str]]]) -> None:
        """
        Check the event and call handlers

        :param data: Data from event

        """
        _LOGGER.debug(f"Got Robonomics event: {data}")
        print(type(data[1]))
        if self.sub_owner_ed:
            subscription_owner = Account(
                seed=self.sub_owner_seed, crypto_type=KeypairType.ED25519
            )
        else:
            subscription_owner = Account(seed=self.sub_owner_seed)
        if self.sub_admin_ed:
            sub_admin = Account(
                seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519
            )
        else:
            sub_admin = Account(seed=self.sub_admin_seed)
        print(f"Owner {data[0]} {subscription_owner.get_address()}")
        if type(data[1]) == str and data[1] == sub_admin.get_address():
            self.hass.async_create_task(self.handle_launch(data))
        elif type(data[1]) == list and data[0] == subscription_owner.get_address():
            self.hass.async_create_task(self.manage_users(data))


    @to_thread
    # @retry(
    #     stop=stop_after_attempt(5),
    #     wait=wait_fixed(5),
    #     retry_error_callback=fail_send_datalog,
    # )
    def send_datalog(
        self, data: str, seed: str, crypto_type_ed: bool, subscription: bool
    ) -> str:
        """
        Record datalog

        :param data: Data for Datalog recors
        :param seed: Mnemonic or raw seed for account that will send the transaction
        :param crypto_type_ed: True if account is ED25519 type
        :param subscription: True if record datalog as RWS call

        :return: Exstrinsic hash

        """
        _LOGGER.debug(f"Send datalog request, another datalog: {self.sending}")
        if self.sending: 
            _LOGGER.debug("Another datalog is sending. Wait...")
            self.on_queue += 1
            on_queue = self.on_queue
            while self.sending:
                time.sleep(5)
                if on_queue < self.on_queue:
                    _LOGGER.debug("Stop waiting to send datalog")
                    return
            self.sending = True
            self.on_queue = 0
            time.sleep(300)
        else:
            self.sending = True
            self.on_queue = 0
        if crypto_type_ed:
            account = Account(seed=seed, crypto_type=KeypairType.ED25519)
        else:
            account = Account(seed=seed)
        if subscription:
            if self.sub_owner_ed:
                subscription_owner = Account(
                    seed=self.sub_owner_seed, crypto_type=KeypairType.ED25519
                )
            else:
                subscription_owner = Account(seed=self.sub_owner_seed)
            try:
                _LOGGER.debug(f"Start creating rws datalog")
                datalog = Datalog(
                    account, rws_sub_owner=subscription_owner.get_address()
                )
            except Exception as e:
                _LOGGER.error(f"Create datalog class exception: {e}")
        else:
            try:
                _LOGGER.debug(f"Start creating datalog")
                datalog = Datalog(account)
            except Exception as e:
                _LOGGER.error(f"Create datalog class exception: {e}")
        try:    
            receipt = datalog.record(data)
            self.sending = False
            _LOGGER.debug(f"Datalog created with hash: {receipt}")
            return receipt
        except Exception as e:
            _LOGGER.error(f"send datalog exception: {e}")
            self.sending = False
                #raise e

    async def send_datalog_states(self, data: str) -> str:
        """
        Record datalog from sub admin using subscription

        :param data: Data to record

        :return: Exstrinsic hash

        """
        receipt = await self.send_datalog(data, self.sub_admin_seed, self.sub_admin_ed, True)
        return receipt

    async def send_datalog_creds(self, data: str) -> str:
        """
        Record datalog from subscription owner

        :param data: Data to record

        :return: Exstrinsic hash

        """
        receipt = await self.send_datalog(data, self.sub_owner_seed, self.sub_owner_ed, True)
        return receipt

    def get_devices_list(self):
        try:
            if self.sub_owner_ed:
                account = Account(seed=self.sub_owner_seed, crypto_type=KeypairType.ED25519)
            else:
                account = Account(seed=self.sub_owner_seed)
            return RWS(account).get_devices()
        except Exception as e:
            print(f"error while getting rws devices list {e}")
