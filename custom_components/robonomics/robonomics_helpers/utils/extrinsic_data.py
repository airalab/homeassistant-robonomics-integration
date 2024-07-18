from substrateinterface.utils.ss58 import is_valid_ss58_address
from robonomicsinterface import SubEvent

class ExtrinsicData:
    def __init__(self, extrinsic_type: SubEvent) -> None:
        self.extrinsic_type = extrinsic_type
        self.sender = None

    @staticmethod
    def check(data: list) -> bool:
        raise NotImplementedError

class DatalogData(ExtrinsicData):
    def __init__(self, data: list):
        super().__init__(SubEvent.NewRecord)
        self.sender: str = data[0]
        self.timestamp: float = data[1] / 1000
        self.data: str = data[2]

    @staticmethod
    def check(data: list) -> bool:
        arg1 = is_valid_ss58_address(data[0])
        arg2 = isinstance(data[1], int)
        arg3 = isinstance(data[2], str)
        return arg1 and arg2 and arg3

class LaunchData(ExtrinsicData):
    def __init__(self, data: list):
        super().__init__(SubEvent.NewLaunch)
        self.sender: str = data[0]
        self.receiver: str = data[1]
        self.data: str = data[2]

    @staticmethod
    def check(data: list) -> bool:
        arg1 = is_valid_ss58_address(data[0])
        arg2 = is_valid_ss58_address(data[1])
        arg3 = isinstance(data[2], str)
        return arg1 and arg2 and arg3
    
class TopicChangedData(ExtrinsicData):
    def __init__(self, data: list):
        super().__init__(SubEvent.TopicChanged)
        self.sender: str = data[0]
        self.twin_id: int = data[1]
        self.topic_name: str = data[2]
        self.topic_account: str = data[3]

    @staticmethod
    def check(data: list) -> bool:
        arg1 = is_valid_ss58_address(data[0])
        arg2 = isinstance(data[1], int)
        arg3 = isinstance(data[2], str)
        arg4 = is_valid_ss58_address(data[4])
        return arg1 and arg2 and arg3 and arg4
    
class NewDevicesData(ExtrinsicData):
    def __init__(self, data: list):
        super().__init__(SubEvent.NewDevices)
        self.sender: str = data[0]
        self.devices: list[str] = data[1]

    @staticmethod
    def check(data: list) -> bool:
        arg1 = is_valid_ss58_address(data[0])
        arg2 = isinstance(data[1], list)
        return arg1 and arg2