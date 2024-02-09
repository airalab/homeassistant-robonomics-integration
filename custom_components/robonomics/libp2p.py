import asyncio
import websockets
import logging
import json
import typing as tp
from homeassistant.core import HomeAssistant

from .const import (
    LIBP2P_WS_SERVER,
    WEBSOCKET,
    DOMAIN,
    PEER_ID_LOCAL,
    LIBP2P_LISTEN_PROTOCOL,
    LIBP2P_SEND_STATES_PROTOCOL,
)

_LOGGER = logging.getLogger(__name__)


class LibP2PProxyMessage:
    def __init__(self, message: tp.Union[str, dict]):
        if type(message) is str:
            message = json.loads(message)
        self.protocol: tp.Optional[str] = message.get("protocol")
        message.pop("protocol", None)
        self.data: dict = message


class LibP2P:
    def __init__(self, hass: HomeAssistant):
        self.hass: HomeAssistant = hass
        self.libp2p_proxy = LibP2PProxy(LIBP2P_WS_SERVER, self._set_peer_id)

    async def connect_to_websocket(self):
        await self.libp2p_proxy.subscribe_to_protocol(
            LIBP2P_LISTEN_PROTOCOL, self._run_command
        )

    def _run_command(self, data: LibP2PProxyMessage) -> None:
        message_entity_id = data.data["params"]["entity_id"]
        params = data.data["params"].copy()
        del params["entity_id"]
        if params == {}:
            params = None
        self.hass.async_create_task(
            self.hass.services.async_call(
                domain=data.data["platform"],
                service=data.data["name"],
                service_data=params,
                target={"entity_id": message_entity_id},
            )
        )

    def _set_peer_id(self, peer_id) -> None:
        self.hass.data[DOMAIN][PEER_ID_LOCAL] = peer_id

    async def send_states_to_websocket(self, data: str):
        await self.libp2p_proxy.send_message_to_libp2p(
            data, LIBP2P_SEND_STATES_PROTOCOL, save_data=True
        )

    async def close_connection(self) -> None:
        await self.libp2p_proxy.close_connection()


class LibP2PProxy:
    def __init__(
        self, proxy_server_url: str, peer_id_callback: tp.Optional[tp.Callable] = None
    ):
        self.webscoket = None
        self.callbacks = {}
        self.proxy_server_url: str = proxy_server_url
        self.peer_id: str = None
        self.peer_id_callback = peer_id_callback

    async def connect(self) -> None:
        #################################################################
        ######### Check if "protocol" field in received message #########
        #################################################################
        try:
            async with websockets.connect(
                self.proxy_server_url, ping_timeout=None
            ) as self.websocket:
                _LOGGER.debug(
                    f"Connected to WebSocket server at {self.proxy_server_url}"
                )
                while True:
                    response = await self.websocket.recv()
                    _LOGGER.debug(f"Received message from server: {response}")
                    message = json.loads(response)
                    if "peerId" in message:
                        self.peer_id = message["peerId"]
                        if self.peer_id_callback is not None:
                            self.peer_id_callback(message["peerId"])
                        continue
                    if message.get("protocol") in self.callbacks:
                        libp2p_message = LibP2PProxyMessage(message)
                        self.callbacks[message["protocol"]](libp2p_message)
        except websockets.exceptions.ConnectionClosedOK:
            _LOGGER.debug(f"Websockets connection closed")
        except Exception as e:
            _LOGGER.error(f"Websocket exception: {e}")
            await asyncio.sleep(5)
            asyncio.ensure_future(self.connect())

    async def _send_ws_message(self, data: str) -> None:
        if self.websocket is not None:
            await self.webscoket.send(data)
        else:
            async with websockets.connect(
                self.proxy_server_url, ping_timeout=None
            ) as websocket:
                await websocket.send(data)
        _LOGGER.debug(f"Sent message to libp2p {data}")

    async def send_message_to_libp2p(
        self,
        data: str,
        protocol: str,
        server_peer_id: str = "",
        save_data: bool = False,
    ) -> None:
        msg_to_ws = json.dumps(
            {
                "protocol": protocol,
                "serverPeerId": server_peer_id,
                "save_data": save_data,
                "data": data,
            }
        )
        await self._send_ws_message(msg_to_ws)

    async def subscribe_to_protocol(self, protocol: str, callback: tp.Callable) -> None:
        if self.webscoket is None:
            asyncio.ensure_future(self.connect())
            while self.webscoket is None:
                await asyncio.sleep(0.1)
        await self._send_ws_message(json.dumps({"protocols_to_listen": [protocol]}))

    async def close_connection(self) -> None:
        if self.websocket is not None:
            await self.websocket.close()
