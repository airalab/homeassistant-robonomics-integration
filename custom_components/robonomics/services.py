"""File with functions for Home Assistant services"""

import asyncio
import logging
import os
import tempfile
import time
import typing as tp
from pathlib import Path

from homeassistant.components.camera.const import DOMAIN as CAMERA_DOMAIN
from homeassistant.components.camera.const import SERVICE_RECORD
from homeassistant.core import HomeAssistant, ServiceCall
from robonomicsinterface import Account
from substrateinterface import Keypair, KeypairType

from .const import (
    DOMAIN,
    IPFS_MEDIA_PATH,
    ROBONOMICS,
    TWIN_ID,
)
from .ipfs import add_media_to_ipfs, get_ipfs_data
from .utils import encrypt_message, FileSystemUtils
from .ipfs_helpers.utils import IPFSLocalUtils

_LOGGER = logging.getLogger(__name__)


async def save_video(
    hass: HomeAssistant,
    target: tp.Dict[str, str],
    path: str,
    duration: int,
    sub_admin_acc: Account,
) -> None:
    """Record a video with given duration, save it in IPFS and Digital Twin

    :param hass: Home Assistant instance
    :param target: What should this service use as targeted areas, devices or entities. Usually it's camera entity ID.
    :param path: Path to save the video (must be also in configuration.yaml)
    :param duration: Duration of the recording in seconds
    :param sub_admin_acc: Controller account address
    """

    if path[-1] == "/":
        path = path[:-1]
    filename = f"video-{int(time.time())}.mp4"
    data = {"duration": duration, "filename": f"{path}/{filename}"}
    _LOGGER.debug(f"Started recording video {path}/{filename} for {duration} seconds")
    await hass.services.async_call(
        domain=CAMERA_DOMAIN,
        service=SERVICE_RECORD,
        service_data=data,
        target=target,
        blocking=True,
    )
    count = 0
    while not os.path.isfile(f"{path}/{filename}"):
        await asyncio.sleep(2)
        count += 1
        if count > 10:
            break
    if os.path.isfile(f"{path}/{filename}"):
        _LOGGER.debug(f"Start encrypt video {filename}")
        admin_keypair: Keypair = sub_admin_acc.keypair
        video_data = await FileSystemUtils(hass).read_file_data(f"{path}/{filename}", "rb")
        encrypted_data = encrypt_message(
            video_data, admin_keypair, admin_keypair.public_key
        )
        await FileSystemUtils(hass).write_file_data(f"{path}/{filename}", encrypted_data)
        await add_media_to_ipfs(hass, f"{path}/{filename}")
        folder_ipfs_hash = await IPFSLocalUtils(hass).get_folder_hash(IPFS_MEDIA_PATH)
        # delete file from system
        _LOGGER.debug(f"delete original video {filename}")
        os.remove(f"{path}/{filename}")
        await hass.data[DOMAIN][ROBONOMICS].set_media_topic(
            folder_ipfs_hash, hass.data[DOMAIN][TWIN_ID]
        )

