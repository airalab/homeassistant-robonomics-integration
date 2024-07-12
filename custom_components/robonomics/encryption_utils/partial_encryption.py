from substrateinterface import Keypair
from homeassistant.core import HomeAssistant
import typing as tp
import logging
import asyncio

_LOGGER = logging.getLogger(__name__)

PIECE_SIZE = 500000
encrypted_piece_size = (PIECE_SIZE + 40)*2

async def partial_encrypt(hass: HomeAssistant, message: tp.Union[bytes, str], sender_keypair: Keypair, recipient_public_key: bytes, filename: str) -> None:
    pieces_count = int(len(message) / PIECE_SIZE) + 1
    _LOGGER.debug(f"Start partial encrypt pieces count: {pieces_count}")
    await hass.async_add_executor_job(_clear_file, filename)
    # encrypted = ""
    for i in range(pieces_count):
        first_index = i*PIECE_SIZE
        last_index = (i+1)*PIECE_SIZE if i+1 != pieces_count else None
        data_piece = message[first_index:last_index]
        encrypted_piece = sender_keypair.encrypt_message(data_piece, recipient_public_key)
        _LOGGER.debug(f"{round(i*100/pieces_count)} - Piece size: {len(data_piece)}, encrypted piece size: {len(encrypted_piece.hex())}")
        await hass.async_add_executor_job(_write_data_to_file, encrypted_piece.hex(), filename)
        # encrypted += encrypted_piece.hex()
        # await asyncio.sleep(0)
    # return encrypted

async def partial_decrypt(encrypted_message: tp.Union[bytes, str], receiver_keypair: Keypair, sender_public_key: bytes) -> bytes:
    decrypted = bytearray()
    pieces_count = int(len(encrypted_message) / encrypted_piece_size) + 1
    for i in range(pieces_count):
        first_index = i*encrypted_piece_size
        last_index = (i+1)*encrypted_piece_size if i+1 != pieces_count else None
        encrypted_data_piece = encrypted_message[first_index:last_index]
        bytes_encrypted = bytes.fromhex(encrypted_data_piece)
        decrypted_piece = receiver_keypair.decrypt_message(bytes_encrypted, sender_public_key)
        decrypted.extend(bytearray(decrypted_piece))
        await asyncio.sleep(0)
    return decrypted
    
def _write_data_to_file(data: str, filename: str) -> None:
    with open(filename, "a") as f:
        f.write(data)
        
def _clear_file(filename: str) -> None:
    open(filename, "w").close()