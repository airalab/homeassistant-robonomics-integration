import asyncio
import logging
import json
import typing as tp
from homeassistant.core import HomeAssistant

from .const import (
    LIBP2P_WS_SERVER,
    DOMAIN,
    PEER_ID_LOCAL,
    LIBP2P_LISTEN_COMMANDS_PROTOCOL,
    LIBP2P_SEND_STATES_PROTOCOL,
    LIBP2P_LISTEN_TOKEN_REQUEST_PROTOCOL,
    LIBP2P_SEND_TOKEN_PROTOCOL,
    ROBONOMICS,
    LIBP2P_RELAY_ADDRESSES,
    LIBP2P_MULTIADDRESS,
)
from .utils import verify_sign
from .manage_users import UserManager
from .get_states import get_and_send_data

from pyproxy import Libp2pProxyAPI
from pyproxy.utils.message import InitialMessage

_LOGGER = logging.getLogger(__name__)

class LibP2P:
    def __init__(self, hass: HomeAssistant):
        self.hass: HomeAssistant = hass
        self.libp2p_proxy = Libp2pProxyAPI(LIBP2P_WS_SERVER, self._set_peer_id)

    async def connect_to_websocket(self):
        # await self.libp2p_proxy.set_relay(LIBP2P_RELAY_ADDRESSES[0])
        await self.libp2p_proxy.subscribe_to_protocol_sync(
            LIBP2P_LISTEN_COMMANDS_PROTOCOL, self._run_command, reconnect=True
        )
        await self.libp2p_proxy.subscribe_to_protocol_async(
            LIBP2P_LISTEN_TOKEN_REQUEST_PROTOCOL, self._send_token, reconnect=True
        )

    def _run_command(self, received_data: tp.Union[str, dict]) -> None:
        if isinstance(received_data, str):
            try:
                data = json.loads(received_data)
            except Exception as e:
                decrypted_data = self.hass.data[DOMAIN][ROBONOMICS].decrypt_message(received_data)
                data = json.loads(decrypted_data)
        else:
            data = received_data
        if "sender" in data:
            decrypted_data = self.hass.data[DOMAIN][ROBONOMICS].decrypt_message(data["data"], data["sender"])
            data = json.loads(decrypted_data)
        message_entity_id = data["params"]["entity_id"]
        params = data["params"].copy()
        del params["entity_id"]
        if params == {}:
            params = None
        self.hass.async_create_task(
            self.hass.services.async_call(
                domain=data["platform"],
                service=data["name"],
                service_data=params,
                target={"entity_id": message_entity_id},
            )
        )

    async def _send_token(self, data: tp.Union[str, dict]) -> None:
        if isinstance(data, str):
            data = json.loads(data)
        if verify_sign(data["sign"], data["address"]):
            token = await UserManager(self.hass).get_access_token_for_address(data["address"])
            encrypted_token = self.hass.data[DOMAIN][ROBONOMICS].encrypt_message(token, data["address"])
            await self.send_token_to_libp2p({"token": encrypted_token})
        else:
            _LOGGER.debug(f"Signature for token request for address: {data['address']} wasn't verified")

    def _set_peer_id(self, message: InitialMessage) -> None:
        self.hass.data[DOMAIN][PEER_ID_LOCAL] = message.peer_id
        self.hass.data[DOMAIN][LIBP2P_MULTIADDRESS] = message.multi_addressess
        asyncio.ensure_future(get_and_send_data(self.hass))

    async def send_states_to_websocket(self, data: str):
        if self.libp2p_proxy.is_connected():
            await self.libp2p_proxy.send_msg_to_libp2p(
                data, LIBP2P_SEND_STATES_PROTOCOL, save_data=True
            )

    async def send_token_to_libp2p(self, data: tp.Dict[str, str]) -> None:
        if self.libp2p_proxy.is_connected():
            await self.libp2p_proxy.send_msg_to_libp2p(
                json.dumps(data), LIBP2P_SEND_TOKEN_PROTOCOL, save_data=False
            )

    async def close_connection(self) -> None:
        await self.libp2p_proxy.unsubscribe_from_all_protocols()
