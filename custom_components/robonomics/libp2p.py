import websockets
import logging
import json
from homeassistant.core import HomeAssistant

from .const import LIBP2P_WS_SERVER, WEBSOCKET, DOMAIN, PEER_ID_LOCAL

_LOGGER = logging.getLogger(__name__)

async def connect_to_websocket(hass: HomeAssistant):
    try:
        async with websockets.connect(LIBP2P_WS_SERVER, ping_timeout=None) as websocket:
            _LOGGER.debug(f"Connected to WebSocket server at {LIBP2P_WS_SERVER}")
            await websocket.send("Hello, WebSocket Server!")
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
            