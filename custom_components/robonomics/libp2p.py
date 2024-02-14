import asyncio
import websockets
import logging
import json
import os
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
)

_LOGGER = logging.getLogger(__name__)


class LibP2PProxyMessage:
    def __init__(self, message: tp.Union[str, dict]):
        if type(message) is str:
            message = json.loads(message)
        self.protocol: tp.Optional[str] = message.get("protocol")
        message_copy = message.copy()
        message_copy.pop("protocol", None)
        self.data: dict = message_copy


class LibP2P:
    def __init__(self, hass: HomeAssistant):
        self.hass: HomeAssistant = hass
        self.libp2p_proxy = LibP2PProxy(LIBP2P_WS_SERVER, self._set_peer_id)

    async def connect_to_websocket(self):
        await self.libp2p_proxy.subscribe_to_protocol(
            LIBP2P_LISTEN_COMMANDS_PROTOCOL, self._run_command
        )
        await self.libp2p_proxy.subscribe_to_protocol(
            LIBP2P_LISTEN_TOKEN_REQUEST_PROTOCOL, self._run_command
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

    async def send_token_to_libp2p(self, data: tp.Dict[str, str]) -> None:
        await self.libp2p_proxy.send_message_to_libp2p(
            json.dumps(data), LIBP2P_SEND_TOKEN_PROTOCOL, save_data=False
        )

    async def close_connection(self) -> None:
        await self.libp2p_proxy.close_connection()


class LibP2PProxy:
    def __init__(
        self, proxy_server_url: str, peer_id_callback: tp.Optional[tp.Callable] = None
    ):
        self.websocket = None
        self.callbacks = {}
        self.proxy_server_url: str = proxy_server_url
        self.peer_id: str = None
        self.peer_id_callback = peer_id_callback
        self.in_connect = False

    async def connect(self) -> None:
        try:
            _LOGGER.debug(f"In connect: {self.in_connect}")
            if self.in_connect:
               return
            self.in_connect = True
            async with websockets.connect(
                self.proxy_server_url, ping_timeout=None
            ) as websocket:
                self.websocket = websocket
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
                        self.callbacks[message.get('protocol')](libp2p_message)
        except websockets.exceptions.ConnectionClosedOK:
            self.in_connect = False
            _LOGGER.debug(f"Websockets connection closed")
        except Exception as e:
            self.in_connect = False
            _LOGGER.error(f"Websocket exception: {e}")
            await asyncio.sleep(5)
            await self._reconnect()

    async def _reconnect(self) -> None:
        _LOGGER.debug("Reconnect to websocket server")
        self.websocket = None
        asyncio.ensure_future(self.connect())
        while self.websocket is None:
            await asyncio.sleep(0.1)
            if not self.in_connect:
                return
        _LOGGER.debug(f"Callbacks to resubscribe: {self.callbacks}")
        for protocol in self.callbacks:
            _LOGGER.debug(f"Start resubscribing to protocol {protocol}")
            await self.subscribe_to_protocol(protocol, self.callbacks[protocol])

    async def _send_ws_message(self, data: str) -> None:
        if self.websocket is not None:
            await self.websocket.send(data)
        else:
            async with websockets.connect(
                self.proxy_server_url, ping_timeout=None
            ) as websocket:
                await websocket.send(data)
        _LOGGER.debug(f"Sent message to libp2p: {data[0:200]}")

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
        if self.websocket is None:
            asyncio.ensure_future(self.connect())
            while self.websocket is None:
                await asyncio.sleep(0.1)
        self.callbacks[protocol] = callback
        protocols = list(self.callbacks.keys())
        await self._send_ws_message(json.dumps({"protocols_to_listen": protocols}))

    async def close_connection(self) -> None:
        if self.websocket is not None:
            await self._send_ws_message(json.dumps({"protocols_to_listen": []}))
            await self.websocket.close()
