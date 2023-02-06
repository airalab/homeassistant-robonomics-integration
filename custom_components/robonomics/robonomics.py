from substrateinterface import SubstrateInterface, Keypair, KeypairType
from robonomicsinterface import (
    Account,
    Subscriber,
    SubEvent,
    Datalog,
    RWS,
    Datalog,
    DigitalTwin,
)
from robonomicsinterface.utils import ipfs_32_bytes_to_qm_hash, ipfs_qm_hash_to_32_bytes
from aenum import extend_enum
from homeassistant.core import callback, HomeAssistant

# from homeassistant.components.notify.const import DOMAIN as NOTIFY_DOMAIN
# from homeassistant.components.notify.const import SERVICE_PERSISTENT_NOTIFICATION
from threading import Thread
import logging
import typing as tp
import asyncio
import time
import json
from .utils import to_thread, create_notification
from .ipfs import get_ipfs_data
from .manage_users import change_password, manage_users
from .const import HANDLE_LAUNCH, DOMAIN, ROBONOMICS, TWIN_ID, RWS_DAYS_LEFT_NOTIFY
from datetime import datetime, timedelta

_LOGGER = logging.getLogger(__name__)

ZERO_ACC = "0x0000000000000000000000000000000000000000000000000000000000000000"


async def check_subscription_left_days(hass: HomeAssistant) -> None:
    """Check subscription status and send notification.

    :param hass: HomeAssistant instance
    """

    await hass.data[DOMAIN][ROBONOMICS].get_rws_left_days()
    hass.states.async_set(f"{DOMAIN}.subscription_left_days", hass.data[DOMAIN][ROBONOMICS].rws_days_left)
    if hass.data[DOMAIN][ROBONOMICS].rws_days_left <= 0:
        service_data = {
            "message": f"Your subscription has ended. You can renew it in [Robonomics DApp](https://dapp.robonomics.network/#/subscription).",
            "title": "Robonomics Subscription Expires",
        }
        await create_notification(hass, service_data)
    elif hass.data[DOMAIN][ROBONOMICS].rws_days_left <= RWS_DAYS_LEFT_NOTIFY:
        service_data = {
            "message": f"Your subscription is ending. You can use it for another {hass.data[DOMAIN][ROBONOMICS].rws_days_left} days, after that it should be renewed. You can do in in [Robonomics DApp](https://dapp.robonomics.network/#/subscription).",
            "title": "Robonomics Subscription Expires",
        }
        await create_notification(hass, service_data)


@callback
async def _handle_launch(hass: HomeAssistant, data: tp.Tuple[str]) -> None:
    """Handle a command from launch transaction

    :param hass: HomeAssistant instance
    :param data: Data from extrinsic
    """

    _LOGGER.debug("Start handle launch")
    hass.data[DOMAIN][HANDLE_LAUNCH] = True
    try:
        ipfs_hash = ipfs_32_bytes_to_qm_hash(data[2])
        response_text = await get_ipfs_data(
            hass, ipfs_hash, data[0], 0
        )  # {'platform': 'light', 'name', 'turn_on', 'params': {'entity_id': 'light.lightbulb'}}
    except Exception as e:
        _LOGGER.error(f"Exception in get ipfs command: {e}")
        return


@callback
async def _handle_backup_change(hass: HomeAssistant) -> None:
    """Handle change a backup hash in digital twin.

    :param hass: HomeAssistant instance
    """

    _LOGGER.debug("Start handle backup change")
    service_data = {"message": "Backup was updated in Robonomics", "title": "Update Backup"}
    await create_notification(hass, service_data)


class Robonomics:
    """Represents methods to interact with Robonomics parachain"""

    def __init__(
        self,
        hass: HomeAssistant,
        sub_owner_address: str,
        sub_admin_seed: str,
    ) -> None:
        self.hass: HomeAssistant = hass
        self.sub_owner_address: str = sub_owner_address
        self.sub_admin_seed: str = sub_admin_seed
        self.sending_states: bool = False
        self.sending_creds: bool = False
        self.on_queue: int = 0
        self.devices_list: tp.List[str] = []
        self.subscriber: tp.Optional[Thread] = None
        self.rws_days_left = 30
        try:
            extend_enum(
                SubEvent,
                "MultiEvent",
                f"{SubEvent.NewDevices.value, SubEvent.NewLaunch.value, SubEvent.NewRecord.value, SubEvent.TopicChanged.value}",
            )
        except Exception as e:
            _LOGGER.error(f"Exception in enum: {e}")

    @to_thread
    def get_last_telemetry_hash(self) -> tp.Optional[str]:
        """Getting the last hash with telemetry from Datalog.

        :return: Last IPFS hash if success, None otherwise
        """

        try:
            sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
            datalog = Datalog(Account())
            last_hash = datalog.get_item(sub_admin.get_address())
            _LOGGER.debug(f"Got last hash from datalog: {last_hash}")
            if last_hash[1][:2] != "Qm":
                return None
            else:
                return last_hash[1]
        except Exception as e:
            _LOGGER.debug(f"Exception in getting last telemetry hash: {e}")

    @to_thread
    def get_rws_left_days(self):
        try:
            _LOGGER.debug(f"Start getting RWS date info")
            rws = RWS(Account())
            res = rws.get_ledger(self.sub_owner_address)
            start_timestamp = res["issue_time"] / 1000
            start_date = datetime.fromtimestamp(start_timestamp)
            now_date = datetime.now()
            delta = now_date - start_date
            self.rws_days_left = 30 - delta.days
            _LOGGER.debug(f"RWS left {self.rws_days_left} days")
        except Exception as e:
            _LOGGER.debug(f"Exception in getting rws left days: {e}")

    @to_thread
    def create_digital_twin(self) -> int:
        """
        Create new digital twin

        :return: Number of created twin or -1 if failed
        """

        try:
            sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
            dt = DigitalTwin(sub_admin, rws_sub_owner=self.sub_owner_address)
            dt_it, tr_hash = dt.create()
            _LOGGER.debug(f"Digital twin number {dt_it} was created with transaction hash {tr_hash}")
            return dt_it
        except Exception as e:
            _LOGGER.error(f"Exception in creating digital twin: {e}")
            return -1

    @to_thread
    def get_backup_hash(self, twin_number: int) -> tp.Optional[str]:
        """Getting hash for backup file from Datalog.

        :param twin_number: Twin number where hash for backup file stores

        :return: Hash for backup file if success, None otherwise
        """

        try:
            sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
            dt = DigitalTwin(sub_admin, rws_sub_owner=self.sub_owner_address)
            info = dt.get_info(twin_number)
            if info is not None:
                for topic in info:
                    if topic[1] == self.sub_owner_address:
                        backup_hash = ipfs_32_bytes_to_qm_hash(topic[0])
                        _LOGGER.debug(f"Backup hash is {backup_hash}")
                        return backup_hash
                else:
                    _LOGGER.debug(f"No backup topic was found")
                    return None
        except Exception as e:
            _LOGGER.error(f"Exception in getting backup hash: {e}")
            return None

    @to_thread
    def set_backup_topic(self, ipfs_hash: str, twin_number: int) -> None:
        """Create new topic in Digital Twin for updated backup
        
        :param ipfs_hash: Hash for current backup file
        :param twin_number: Twin number where hash for backup file stores
        """

        try:
            sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
            dt = DigitalTwin(sub_admin, rws_sub_owner=self.sub_owner_address)
            info = dt.get_info(twin_number)
            bytes_hash = ipfs_qm_hash_to_32_bytes(ipfs_hash)
            _LOGGER.debug(f"Bytes config hash: {bytes_hash}")
            if info is not None:
                for topic in info:
                    _LOGGER.debug(f"Topic {topic}, ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}")
                    if topic[0] == bytes_hash:
                        if topic[1] == self.sub_owner_address:
                            _LOGGER.debug(f"Topic with this backup exists")
                            service_data = {
                                "message": "Recently created backup is the same as backup saved in Robonomics blockchain",
                                "title": "Backup wasn't updated",
                            }
                            self.hass.async_create_task(create_notification(self.hass, service_data))
                            return
                    if topic[1] == self.sub_owner_address:
                        dt.set_source(twin_number, topic[0], ZERO_ACC)
                        _LOGGER.debug(
                            f"Old backup topic removed {topic[0]}, old ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}"
                        )
            dt.set_source(twin_number, bytes_hash, self.sub_owner_address)
            _LOGGER.debug(f"New backup topic was created: {bytes_hash}, new ipfs hash: {ipfs_hash}")
        except Exception as e:
            _LOGGER.error(f"Exception in set config topic {e}")

    @to_thread
    def set_config_topic(self, ipfs_hash: str, twin_number: int) -> None:
        """Create new topic in Digital Twin for updated config
        
        :param ipfs_hash: Hash for current config file
        :param twin_number: Twin number where hash for config file stores
        """

        try:
            sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
            dt = DigitalTwin(sub_admin, rws_sub_owner=self.sub_owner_address)
            info = dt.get_info(twin_number)
            bytes_hash = ipfs_qm_hash_to_32_bytes(ipfs_hash)
            _LOGGER.debug(f"Bytes config hash: {bytes_hash}")
            if info is not None:
                for topic in info:
                    _LOGGER.debug(f"Topic {topic}, ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}")
                    if topic[0] == bytes_hash:
                        if topic[1] == sub_admin.get_address():
                            _LOGGER.debug(f"Topic with this config exists")
                            return
                    if topic[1] == sub_admin.get_address():
                        dt.set_source(twin_number, topic[0], ZERO_ACC)
                        _LOGGER.debug(
                            f"Old topic removed {topic[0]}, old ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}"
                        )
            dt.set_source(twin_number, bytes_hash, sub_admin.get_address())
            _LOGGER.debug(f"New topic was created: {bytes_hash}, new ipfs hash: {ipfs_hash}")
        except Exception as e:
            _LOGGER.error(f"Exception in set config topic {e}")

    @to_thread
    def find_password(self, address: str) -> tp.Optional[str]:
        """Look for encrypted password in the datalog of the given account

        :param address: The address of the account

        :return: Encrypted password or None if password wasn't found
        """

        _LOGGER.debug(f"Start look for password for {address}")
        datalog = Datalog(Account())
        sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
        try:
            last_datalog = datalog.get_item(address, 0)[1]
        except:
            return
        _LOGGER.debug(f"Last datalog: {last_datalog}")
        try:
            data = json.loads(last_datalog)
            if "admin" in data:
                if data["subscription"] == self.sub_owner_address and data["ha"] == sub_admin.get_address():
                    return data["admin"]
        except:
            pass
        indexes = datalog.get_index(address)
        last_datalog_index = indexes["end"] - 2
        _LOGGER.debug(f"Last index {last_datalog_index}")
        for i in range(5):
            try:
                datalog_data = datalog.get_item(address, last_datalog_index - i)[1]
                _LOGGER.debug(datalog_data)
                data = json.loads(datalog_data)
                if "admin" in data:
                    if data["subscription"] == self.sub_owner_address and data["ha"] == sub_admin.get_address():
                        return data["admin"]
            except Exception as e:
                # _LOGGER.error(f"Exception in find password {e}")
                continue
        else:
            return None

    def subscribe(self) -> None:
        """Subscribe to NewDevices and NewLaunch events

        :param handle_launch: Call this function if NewLaunch event
        :param manage_users: Call this function if NewDevices event
        :param change_password: Call this function if NewRecord event from one of devices
        """

        try:
            account = Account()
            self.subscriber = Subscriber(
                account,
                SubEvent.MultiEvent,
                subscription_handler=self.callback_new_event,
            )
        except Exception as e:
            _LOGGER.debug(f"subscribe exception {e}")

            time.sleep(4)
            self.hass.data[DOMAIN][ROBONOMICS].subscribe()

    @callback
    def callback_new_event(self, data: tp.Tuple[tp.Union[str, tp.List[str]]]) -> None:
        """Check the event and call handlers

        :param data: Data from event
        """

        try:
            # _LOGGER.debug(f"Data from subscription callback: {data}")
            sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
            if type(data[1]) == str and data[1] == sub_admin.get_address():  ## Launch
                if data[0] in self.devices_list:
                    self.hass.async_create_task(_handle_launch(self.hass, data))
                else:
                    _LOGGER.debug(f"Got launch from not linked device: {data[0]}")
            elif type(data[1]) == int and len(data) == 4:
                if TWIN_ID in self.hass.data[DOMAIN]:
                    if (
                        data[1] == self.hass.data[DOMAIN][TWIN_ID] and data[3] == self.sub_owner_address
                    ):  ## Change backup topic in Digital Twin
                        self.hass.async_create_task(_handle_backup_change(self.hass, data))
            elif type(data[1]) == int and data[0] in self.devices_list:  ## Datalog to change password
                self.hass.async_create_task(change_password(self.hass, data))
            elif type(data[1]) == list and data[0] == self.sub_owner_address:  ## New Device in subscription
                self.hass.async_create_task(manage_users(self.hass, data))
        except Exception as e:
            _LOGGER.warning(f"Exception in subscription callback: {e}")

    @to_thread
    def send_datalog(self, data: str, seed: str, subscription: bool) -> str:
        """Record datalog

        :param data: Data for Datalog recors
        :param seed: Mnemonic or raw seed for account that will send the transaction
        :param subscription: True if record datalog as RWS call

        :return: Exstrinsic hash
        """

        account = Account(seed=seed, crypto_type=KeypairType.ED25519)
        if subscription:
            try:
                _LOGGER.debug(f"Start creating rws datalog")
                datalog = Datalog(account, rws_sub_owner=self.sub_owner_address)
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
            _LOGGER.debug(f"Datalog created with hash: {receipt}")
            return receipt
        except Exception as e:
            _LOGGER.error(f"send datalog exception: {e}")
            return None

    async def send_datalog_states(self, data: str) -> str:
        """Record datalog from sub admin using subscription

        :param data: Data to record

        :return: Exstrinsic hash
        """

        _LOGGER.debug(f"Send datalog states request, another datalog: {self.sending_states}")
        if self.sending_states:
            _LOGGER.debug("Another datalog is sending. Wait...")
            self.on_queue += 1
            on_queue = self.on_queue
            while self.sending_states:
                await asyncio.sleep(5)
                if on_queue < self.on_queue:
                    _LOGGER.debug("Stop waiting to send datalog")
                    return
            self.sending_states = True
            self.on_queue = 0
            await asyncio.sleep(10)
        else:
            self.sending_states = True
            self.on_queue = 0
        receipt = await self.send_datalog(data, self.sub_admin_seed, True)
        self.sending_states = False
        return receipt

    def get_devices_list(self):
        """Return devices list for sub owner account

        :return: List of devices
        """

        try:
            devices_list = RWS(Account()).get_devices(self.sub_owner_address)
            _LOGGER.debug(f"Got devices list: {devices_list}")
            sub_admin = Account(seed=self.sub_admin_seed, crypto_type=KeypairType.ED25519)
            if devices_list != None:
                devices_list.remove(sub_admin.get_address())
                try:
                    devices_list.remove(self.sub_owner_address)
                except:
                    pass
            self.devices_list = devices_list
            return self.devices_list
        except Exception as e:
            print(f"error while getting rws devices list {e}")
