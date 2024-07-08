from robonomicsinterface import Account
from substrateinterface import KeypairType, Keypair


class RobonomicsAccounts:
    def __init__(
        self, controller_seed: str, owner_address: str, controller_type: KeypairType
    ) -> None:
        self.controller_account: Account = Account(
            controller_seed, crypto_type=controller_type
        )
        self.owner_address: str = owner_address
        self.controller_address: str = self.controller_account.get_address()
        self.controller_keypayr: Keypair = self.controller_account.keypair
        self._controller_seed = controller_seed
        self._controller_type = controller_type

    def change_account_wss(self, new_wss: str) -> None:
        self.controller_account = Account(
            self._controller_seed, crypto_type=self._controller_type, remote_ws=new_wss
        )
