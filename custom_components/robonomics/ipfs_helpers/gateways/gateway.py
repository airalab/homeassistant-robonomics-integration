from abc import ABC, abstractmethod
import typing as tp
import logging
from homeassistant.core import HomeAssistant
import typing as tp

_LOGGER = logging.getLogger(__name__)


class Gateway(ABC):
    def __init__(self, hass: HomeAssistant, urls: tp.List[str] = None, websession = None) -> None:
        self.hass = hass
        self.urls = urls
        self.websession = websession

    @abstractmethod
    def add(filename: str, pin: bool, last_file_hash: tp.Optional[str] = None, file_size: tp.Optional[int] = None) -> tp.Tuple[tp.Optional[str], tp.Optional[int]]:
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


