"""This module contain methods to communicate with Robonomics blockchain"""

import asyncio
import json
import logging
import time
import typing as tp
from ast import literal_eval
from threading import Thread

import substrateinterface as substrate
from aenum import extend_enum
from homeassistant.core import HomeAssistant, callback
from robonomicsinterface import RWS, Account, Datalog, DigitalTwin, SubEvent, Subscriber
from robonomicsinterface.utils import ipfs_32_bytes_to_qm_hash, ipfs_qm_hash_to_32_bytes
from substrateinterface import Keypair, KeypairType

from .const import (
    CONF_ADMIN_SEED,
    CONF_SUB_OWNER_ADDRESS,
    DOMAIN,
    HANDLE_IPFS_REQUEST,
    MEDIA_ACC,
    ROBONOMICS,
    RWS_DAYS_LEFT_NOTIFY,
    TWIN_ID,
    ZERO_ACC,
)
from .get_states import get_and_send_data
from .ipfs import get_ipfs_data
from .manage_users import change_password, manage_users
from .utils import create_notification, decrypt_message, to_thread

_LOGGER = logging.getLogger(__name__)


async def check_subscription_left_days(hass: HomeAssistant) -> None:
    """Check subscription status and send notification.

    :param hass: HomeAssistant instance
    """

    rws = RWS(Account())
    rws_days_left = rws.get_days_left(addr=hass.data[DOMAIN][CONF_SUB_OWNER_ADDRESS])
    _LOGGER.debug(f"Left {rws_days_left} days of subscription")
    if rws_days_left == -1:
        hass.states.async_set(f"{DOMAIN}.subscription_left_days", 100000)
        _LOGGER.debug("Subscription is endless")
        return
    if rws_days_left:
        hass.states.async_set(f"{DOMAIN}.subscription_left_days", rws_days_left)
        if rws_days_left <= RWS_DAYS_LEFT_NOTIFY:
            service_data = {
                "message": f"""Your subscription is ending. You can use it for another {rws_days_left} days, 
                                after that it should be renewed. You can do in in [Robonomics DApp](https://dapp.robonomics.network/#/subscription).""",
                "title": "Robonomics Subscription Expires",
            }
            await create_notification(hass, service_data)
    else:
        hass.states.async_set(f"{DOMAIN}.subscription_left_days", 0)
        service_data = {
            "message": f"Your subscription has ended. You can renew it in [Robonomics DApp](https://dapp.robonomics.network/#/subscription).",
            "title": "Robonomics Subscription Expires",
        }
        await create_notification(hass, service_data)


def _run_launch_command(hass: HomeAssistant, encrypted_command: str, sender_address: str) -> None:
    """Function to unwrap launch command and call Home Assistant service for device

    :param hass: Home Assistant instance
    :param encrypted_command: command from IPFS
    :param sender_address: launch's user address
    """

    try:
        if encrypted_command is None:
            _LOGGER.error(f"Can't get command")
            return
    except Exception as e:
        _LOGGER.error(f"Exception in get ipfs command: {e}")
        return None
    _LOGGER.debug(f"Got from launch: {encrypted_command}")
    if "platform" in encrypted_command:
        message = literal_eval(encrypted_command)
    else:
        kp_sender = Keypair(ss58_address=sender_address, crypto_type=KeypairType.ED25519)
        sub_admin_kp = Keypair.create_from_mnemonic(hass.data[DOMAIN][CONF_ADMIN_SEED], crypto_type=KeypairType.ED25519)
        try:
            decrypted = decrypt_message(encrypted_command, kp_sender.public_key, sub_admin_kp)
        except Exception as e:
            _LOGGER.error(f"Exception in decrypt command: {e}")
            return None
        decrypted = str(decrypted)[2:-1]
        _LOGGER.debug(f"Decrypted command: {decrypted}")
        message = literal_eval(decrypted)
    try:
        # domain="light", service="turn_on", service_data={"rgb_color": [30, 30, 230]}
        # target={"entity_id": "light.shapes_9275"}
        message_entity_id = message["params"]["entity_id"]
        params = message["params"].copy()
        del params["entity_id"]
        if params == {}:
            params = None
        hass.async_create_task(
            hass.services.async_call(
                domain=message["platform"],
                service=message["name"],
                service_data=params,
                target={"entity_id": message_entity_id},
            )
        )
    except Exception as e:
        _LOGGER.error(f"Exception in sending command: {e}")


@callback
async def _handle_launch(hass: HomeAssistant, data: tp.Tuple[str]) -> None:
    """Handle a command from launch transaction

    :param hass: HomeAssistant instance
    :param data: Data from extrinsic
    """

    _LOGGER.debug("Start handle launch")
    hass.data[DOMAIN][HANDLE_IPFS_REQUEST] = True
    try:
        ipfs_hash = ipfs_32_bytes_to_qm_hash(data[2])
        result = await get_ipfs_data(
            hass, ipfs_hash, 0
        )  # {'platform': 'light', 'name', 'turn_on', 'params': {'entity_id': 'light.lightbulb'}}
        _LOGGER.debug(f"Result: {result}")
        _run_launch_command(hass, result, data[0])
        await get_and_send_data(hass)
    except Exception as e:
        _LOGGER.error(f"Exception in launch handler command: {e}")
        return


@callback
async def _handle_backup_change(hass: HomeAssistant) -> None:
    """Handle change a backup hash in digital twin.

    :param hass: HomeAssistant instance
    """

    _LOGGER.debug("Start handle backup change")
    service_data = {
        "message": "Backup was updated in Robonomics",
        "title": "Update Backup",
    }
    await create_notification(hass, service_data)


class Robonomics:
    """Represents methods to interact with Robonomics parachain"""

    def __init__(
        self,
        hass: HomeAssistant,
        sub_owner_address: str,
        controller_seed: str,
    ) -> None:
        self.hass: HomeAssistant = hass
        self.sub_owner_address: str = sub_owner_address
        self.controller_seed: str = controller_seed
        self.controller_account: Account = Account(seed=self.controller_seed, crypto_type=KeypairType.ED25519)
        self.controller_address: str = self.controller_account.get_address()
        self.sending_states: bool = False
        self.sending_creds: bool = False
        self.on_queue: int = 0
        self.devices_list: tp.List[str] = []
        self.subscriber: tp.Optional[Thread] = None
        try:
            extend_enum(
                SubEvent,
                "MultiEvent",
                f"{SubEvent.NewDevices.value, SubEvent.NewLaunch.value, SubEvent.NewRecord.value, SubEvent.TopicChanged.value}",
            )
        except TypeError:
            pass
        except Exception as e:
            _LOGGER.error(f"Exception in enum: {e}")

    @to_thread
    def get_last_telemetry_hash(self) -> tp.Optional[str]:
        """Getting the last hash with telemetry from Datalog.

        :return: Last IPFS hash if success, None otherwise
        """

        try:
            datalog = Datalog(Account())
            last_hash = datalog.get_item(self.controller_address)
            _LOGGER.debug(f"Got last hash from datalog: {last_hash}")
            if last_hash[1][:2] != "Qm":
                return None
            else:
                return last_hash[1]
        except Exception as e:
            _LOGGER.debug(f"Exception in getting last telemetry hash: {e}")

    @to_thread
    def create_digital_twin(self) -> int:
        """
        Create new digital twin

        :return: Number of created twin or -1 if failed
        """

        try:
            dt = DigitalTwin(self.controller_account, rws_sub_owner=self.sub_owner_address)
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
            dt = DigitalTwin(self.controller_account, rws_sub_owner=self.sub_owner_address)
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
            dt = DigitalTwin(self.controller_account, rws_sub_owner=self.sub_owner_address)
            info = dt.get_info(twin_number)
            bytes_hash = ipfs_qm_hash_to_32_bytes(ipfs_hash)
            _LOGGER.debug(f"Bytes config hash: {bytes_hash}")
            if info is not None:
                for topic in info:
                    # _LOGGER.debug(f"Topic {topic}, ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}")
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
            dt = DigitalTwin(self.controller_account, rws_sub_owner=self.sub_owner_address)
            info = dt.get_info(twin_number)
            bytes_hash = ipfs_qm_hash_to_32_bytes(ipfs_hash)
            _LOGGER.debug(f"Bytes config hash: {bytes_hash}")
            if info is not None:
                for topic in info:
                    # _LOGGER.debug(f"Topic {topic}, ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}")
                    if topic[0] == bytes_hash:
                        if topic[1] == self.controller_address:
                            _LOGGER.debug(f"Topic with this config exists")
                            return
                    if topic[1] == self.controller_address:
                        dt.set_source(twin_number, topic[0], ZERO_ACC)
                        _LOGGER.debug(
                            f"Old topic removed {topic[0]}, old ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}"
                        )
            dt.set_source(twin_number, bytes_hash, self.controller_address)
            _LOGGER.debug(f"New topic was created: {bytes_hash}, new ipfs hash: {ipfs_hash}")
        except Exception as e:
            _LOGGER.error(f"Exception in set config topic {e}")

    @to_thread
    def set_media_topic(self, ipfs_hash: str, twin_number: int) -> None:
        """Create new topic in Digital Twin for updated media folder

        :param ipfs_hash: Hash for the media folder
        :param twin_number: Twin number where hash stores
        """

        try:
            dt = DigitalTwin(self.controller_account, rws_sub_owner=self.sub_owner_address)
            info = dt.get_info(twin_number)
            bytes_hash = ipfs_qm_hash_to_32_bytes(ipfs_hash)
            _LOGGER.debug(f"Bytes media hash: {bytes_hash}")
            if info is not None:
                for topic in info:
                    # _LOGGER.debug(f"Topic {topic}, ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}")
                    if topic[0] == bytes_hash:
                        if topic[1] == MEDIA_ACC:
                            _LOGGER.debug(f"Topic with this config exists")
                            return
                    if topic[1] == MEDIA_ACC:
                        dt.set_source(twin_number, topic[0], ZERO_ACC)
                        _LOGGER.debug(
                            f"Old topic removed {topic[0]}, old ipfs hash: {ipfs_32_bytes_to_qm_hash(topic[0])}"
                        )
            dt.set_source(twin_number, bytes_hash, MEDIA_ACC)
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
        try:
            last_datalog = datalog.get_item(address, 0)[1]
        except:
            return
        _LOGGER.debug(f"Last datalog: {last_datalog}")
        try:
            data = json.loads(last_datalog)
            if "admin" in data:
                if data["subscription"] == self.sub_owner_address and data["ha"] == self.controller_address:
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
                    if data["subscription"] == self.sub_owner_address and data["ha"] == self.controller_address:
                        return data["admin"]
            except Exception as e:
                # _LOGGER.error(f"Exception in find password {e}")
                continue
        else:
            return None

    def subscribe(self) -> None:
        """Subscribe to NewDevices and NewLaunch events"""

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
            if type(data[1]) == str and data[1] == self.controller_address:  ## Launch
                if data[0] in self.devices_list or data[0] == self.controller_address:
                    self.hass.async_create_task(_handle_launch(self.hass, data))
                else:
                    _LOGGER.debug(f"Got launch from not linked device: {data[0]}")
            elif type(data[1]) == int and len(data) == 4:
                if TWIN_ID in self.hass.data[DOMAIN]:
                    if (
                        data[1] == self.hass.data[DOMAIN][TWIN_ID] and data[3] == self.sub_owner_address
                    ):  ## Change backup topic in Digital Twin
                        self.hass.async_create_task(_handle_backup_change(self.hass))
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
        receipt = await self.send_datalog(data, self.controller_seed, True)
        self.sending_states = False
        return receipt

    def get_devices_list(self):
        """Return devices list for sub owner account

        :return: List of devices
        """

        try:
            devices_list = RWS(Account()).get_devices(self.sub_owner_address)
            _LOGGER.debug(f"Got devices list: {devices_list}")
            if devices_list != None:
                devices_list.remove(self.controller_address)
                try:
                    devices_list.remove(self.sub_owner_address)
                except:
                    pass
            self.devices_list = devices_list
            return self.devices_list
        except Exception as e:
            print(f"error while getting rws devices list {e}")

    @to_thread
    def get_last_digital_twin(self, account: str = None) -> tp.Optional[int]:
        """Find the last digital twin belongint to the given account

        :param account: Address of the account that own the Digital Twin

        :return: The last Twin id belonging to the account
        """
        try:
            if account is None:
                account = self.controller_address

            REMOTE_WS = "wss://kusama.rpc.robonomics.network"
            TYPE_REGISTRY = {
                "types": {
                    "Record": "Vec<u8>",
                    "<T as frame_system::Config>::AccountId": "AccountId",
                    "RingBufferItem": {
                        "type": "struct",
                        "type_mapping": [
                            ["timestamp", "Compact<u64>"],
                            ["payload", "Vec<u8>"],
                        ],
                    },
                    "RingBufferIndex": {
                        "type": "struct",
                        "type_mapping": [
                            ["start", "Compact<u64>"],
                            ["end", "Compact<u64>"],
                        ],
                    },
                }
            }

            ri_instance = substrate.SubstrateInterface(
                url=REMOTE_WS,
                ss58_format=32,
                type_registry_preset="substrate-node-template",
                type_registry=TYPE_REGISTRY,
            )

            query = ri_instance.query_map("DigitalTwin", "Owner")
            twins = []
            for twin in query:
                if twin[1].value == account:
                    twins.append(twin[0].value)
            _LOGGER.debug(f"Digital twinf belonging to controller account: {twins}")
            if len(twins) > 0:
                return max(twins)
            else:
                return
        except Exception as e:
            _LOGGER.error(f"Exception in looking for the last digital twin: {e}")
