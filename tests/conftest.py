"""MicroPython shims and shared fixtures for the Krux integration tests"""

import json
import random
import sys
import types
from collections import namedtuple
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

# Krux imports MicroPython modules at module level.
# Install stdlib stand-ins before any ``krux.*`` import
sys.modules.setdefault("urandom", random)
sys.modules.setdefault("ujson", json)
_board = types.ModuleType("board")
_board.config = {"type": "amigo", "board_info": {}, "krux": {"display": {}, "pins": {}}}
sys.modules.setdefault("board", _board)
for _name in ("ucryptolib", "qrcode"):
    sys.modules.setdefault(_name, MagicMock())

# pylint: disable=wrong-import-position
from bornal.daemon import free_port
from bornal.node import Backend, IntegrationTest
from bornal.plugins.bitcoind import BitcoindClient
from bornal.testing import create_wallet

from embit.descriptor import checksum
from embit.networks import NETWORKS
from embit.psbt import PSBT

from krux.key import Key, P2PKH, TYPE_SINGLESIG
from krux.psbt import PSBTSigner
from krux.qr import FORMAT_NONE
from krux.wallet import Wallet

TrezorVectors = namedtuple(
    "TrezorVectors",
    ["alice", "bob"],
    defaults=[
        " ".join(["abandon"] * 11 + ["about"]),
        " ".join(["zoo"] * 11 + ["wrong"]),
    ],
)


class Coordinator(BitcoindClient):
    """Simple coordinator bound to some bitcoind ``Backend``.`"""

    def __init__(self, backend: Backend, wallet_name: str | None = None):
        super().__init__(
            backend.daemon.host,
            backend.daemon.port,
            backend.daemon.rpc_user,
            backend.daemon.rpc_password,
        )
        self.wallet_name = wallet_name
        self.wallets: list[str] = []
        self.backend = Backend(backend.daemon, client=self)

    @property
    def url(self) -> str:
        """Get wallet url by its own name"""
        return self.get_url(self.wallet_name)

    def get_url(self, name: str | None = None) -> str:
        """Get wallet url by some name."""
        base = f"http://{self._host}:{self._port}"
        return base if name is None else f"{base}/wallet/{name}"

    def get_wallet(self, name: str) -> "Coordinator":
        """Coordinator is a wallet client itself. Return it"""
        if name not in self.wallets:
            raise ValueError(f"Unknown wallet '{name}', expected one of {self.wallets}")
        return Coordinator(self.backend, name)

    def import_watchonly_wallets(self, names: list[str], requests: list[dict]):
        """Import a xpub from some signer."""
        for name, req in zip(names, requests, strict=True):
            if not req.get("desc"):
                raise ValueError("Expected descriptor field on request")
            request = {
                "desc": req["desc"],
                "active": req.get("active", True),
                "timestamp": req.get("timestamp", "now"),
                "range": req.get("range", [0, 10]),
            }
            self.wallets.append(name)
            wallet = self.get_wallet(name)
            create_wallet(wallet.backend, name, watchonly=True, descriptors=[request])


@dataclass
class Signer:
    """An airgap Krux wallet built from a mnemonic"""

    wallet: Wallet

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: str,
        policy=TYPE_SINGLESIG,
        network=None,
        script=P2PKH,
    ) -> "Signer":
        """create a new krux based signer/wallet"""
        network = network or NETWORKS["regtest"]
        key = Key(mnemonic, policy, network, script_type=script)
        return cls(Wallet(key))

    def as_variant(self, policy, network, script) -> "Signer":
        """Return some variant."""
        return Signer.from_mnemonic(self.wallet.key.mnemonic, policy, network, script)

    def as_legacy(self) -> "Signer":
        """Return the P2PKH variant."""
        return self.as_variant(TYPE_SINGLESIG, NETWORKS["regtest"], P2PKH)

    def get_descriptor(self) -> str:
        """Get the wallet/signer xpub descriptor."""
        return checksum.add_checksum(self.wallet.descriptor.to_string())

    def get_pubkey(self, branch: int, index: int) -> bytes:
        """Get the pubkey at some branch/index."""
        return self.wallet.key.account.derive([branch, index]).key.sec()

    def as_signer(self, psbt: PSBT | str) -> PSBTSigner:
        """Get the PSBT signer for current wallet."""
        data = psbt.to_string() if isinstance(psbt, PSBT) else psbt
        return PSBTSigner(self.wallet, data, FORMAT_NONE)


class BaseTest(IntegrationTest):
    """Hot ``core`` node plus a ``coordinator`` node with one wallet per signer"""

    state: dict
    signers: dict[str, Signer]
    coordinator: Coordinator

    def set_test_params(self):
        """Declare the airgap signers and two listening ``bitcoin-core`` nodes"""
        self.state = {}

        # Prepare some 'airgap' wallets (regtest only)
        self.signers = {
            name: Signer.from_mnemonic(mnemonic)
            for (name, mnemonic) in TrezorVectors()._asdict().items()
        }

        # Initialized nodes. The first one will be a hot wallet managed
        # by bornal itself. The second will be watchonly that can load
        # multiple wallets from xpub and can be signed from some signer
        # in `self.signers`
        self.add_backend("bitcoin-core", p2p_port=free_port())
        self.add_backend("bitcoin-core", p2p_port=free_port())

    def run_test(self):
        """Backends are up: one watch-only wallet per signer on the second node"""
        # first create the hot wallet
        create_wallet(self.backends[0])

        # now create a watchonly coordinator with two reference xpubs
        # emulating what people do with Sparrow (but without sparrow here)
        names = []
        requests = []
        for name, airgap in self.signers.items():
            names.append(name)
            requests.append({"desc": airgap.as_legacy().get_descriptor()})
        self.coordinator = Coordinator(self.backends[1])
        self.coordinator.import_watchonly_wallets(names, requests)


@pytest.fixture(scope="module")
def test_factory():
    """``BaseTest`` for bornal's module-scoped ``integration_test``"""
    return BaseTest


@pytest.fixture
def core(integration_test):
    """Backend 0: hot ``bornal-wallet`` node that mines and funds"""
    return integration_test.backends[0]


@pytest.fixture
def state(integration_test):
    """Module-wide hand-off dict: ``address``, ``txid``, ``psbt``, ..."""
    return integration_test.state


@pytest.fixture
def coordinator(integration_test):
    """Backend 1 at node level; ``get_wallet(name)`` for one watch-only wallet"""
    return integration_test.coordinator


@pytest.fixture
def signer(integration_test):
    """``signer(name) -> Signer`` for one airgap signer"""

    def _wrapper(name: str):
        return integration_test.signers[name]

    return _wrapper
