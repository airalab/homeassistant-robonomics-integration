from abc import ABC, abstractmethod
import typing as tp
import logging
from homeassistant.core import HomeAssistant
from dataclasses import dataclass
import typing as tp

_LOGGER = logging.getLogger(__name__)

@dataclass
class UnpinArgs:
    file_name: str
    last_file_naem: str
    last_file_hash: str
    path: str

@dataclass
class PinArgs:
    file_name: str
    file_size: int
    path: tp.Optional[str] = None


class Gateway(ABC):
    def __init__(self, hass: HomeAssistant, urls: tp.List[str] = None, websession = None) -> None:
        self.hass = hass
        self.urls = urls
        self.websession = websession


    @abstractmethod
    def pin(args: PinArgs) -> tp.Optional[str]:
        pass

    @abstractmethod
    def unpin(args: UnpinArgs) -> None:
        pass

    async def create_tasks_for_get(self, is_directory: bool, hash: str):
        tasks = []
        urls = self._format_urls_for_get(self.urls)
        if is_directory:
            url += "?format=tar"
        _LOGGER.debug(f"Request to {url}")
        for url in urls:
            tasks.append(self.websession.get(url))
        return tasks

    def _format_urls_for_get(self, urls) -> str:
        formatted_urls = []
        for url in urls:
            if url[-1] != "/":
                url += "/"
            if url[-5:] != "ipfs/":
                url += "ipfs/"
            url = f"{url}{self.ipfs_hash}"
            formatted_urls.append(url)
        return formatted_urls


