import asyncio
import websockets
import logging
import json
import typing as tp
from homeassistant.core import HomeAssistant

from .const import LIBP2P_WS_SERVER, WEBSOCKET, DOMAIN, PEER_ID_LOCAL, LIBP2P_LISTEN_PROTOCOL, LIBP2P_SEND_PROTOCOL

_LOGGER = logging.getLogger(__name__)

async def connect_to_websocket(hass: HomeAssistant):
    try:
        async with websockets.connect(LIBP2P_WS_SERVER, ping_timeout=None) as websocket:
            _LOGGER.debug(f"Connected to WebSocket server at {LIBP2P_WS_SERVER}")
            await websocket.send(json.dumps({"protocols_to_listen": [LIBP2P_LISTEN_PROTOCOL]}))
            hass.data[DOMAIN][WEBSOCKET] = websocket
            while True:
                response = await websocket.recv()
                _LOGGER.debug(f"Received message from server: {response}")
                message = json.loads(response)
                if "peerId" in message:
                    hass.data[DOMAIN][PEER_ID_LOCAL] = message["peerId"]
                    continue
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
    except websockets.exceptions.ConnectionClosedOK:
        _LOGGER.debug(f"Websockets connection closed")
    except Exception as e:
        _LOGGER.error(f"Websocket exception: {e}")
        await asyncio.sleep(5)
        asyncio.ensure_future(connect_to_websocket(hass))

async def send_message_to_websocket(hass: HomeAssistant, data: str):
    msg_to_ws = json.dumps({"protocol": LIBP2P_SEND_PROTOCOL, "serverPerrId": "", "save_data": True, "data": data})
    await hass.data[DOMAIN][WEBSOCKET].send(msg_to_ws)
    _LOGGER.debug(f"Sent message to ws protocol {LIBP2P_SEND_PROTOCOL}")