"""MicroPython shims and shared fixtures for the Krux integration tests"""

import json
import random
import sys
import types
from collections import namedtuple
from dataclasses import dataclass
from decimal import Decimal
from functools import partial
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


SATOSHIS = 100_000_000
SEQUENCE_FINAL = 0xFFFFFFFF


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

    def account_path(self, address: str) -> str:
        """``<branch>/<index>`` of a wallet address"""
        return "/".join(self.get_address_info(address)["hdkeypath"].split("/")[-2:])

    def funded_psbt_v0(self, inputs: list, outputs: list, options: dict) -> str:
        """``walletcreatefundedpsbt`` as PSBTv0"""
        args = (inputs, outputs, 0, options, True, None, 0)
        return self.call("walletcreatefundedpsbt", *args)["psbt"]

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

    def sign_psbt(self, psbt: PSBT | str) -> str:
        """Sign with Krux and return exported PSBT"""
        krux = self.as_signer(psbt)
        krux.sign()
        return krux.psbt_qr()[0]


class BaseTest(IntegrationTest):
    """Hot ``core`` node plus a ``coordinator`` node with one wallet per signer"""

    state: dict
    signers: dict[str, Signer]
    coordinator: Coordinator

    def __init__(self, *args, script_type=P2PKH, **kwargs):
        super().__init__(*args, **kwargs)
        self.script_type = script_type

    def set_test_params(self):
        """Declare the airgap signers and two listening ``bitcoin-core`` nodes"""
        self.state = {}

        # Prepare some 'airgap' wallets (regtest only)
        self.signers = {
            name: Signer.from_mnemonic(mnemonic, script=self.script_type)
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
            requests.append({"desc": airgap.get_descriptor()})
        self.coordinator = Coordinator(self.backends[1])
        self.coordinator.import_watchonly_wallets(names, requests)


@pytest.fixture(scope="module")
def test_factory(script_type):
    """``BaseTest`` for bornal's module-scoped ``integration_test``."""
    return partial(BaseTest, script_type=script_type)


def pytest_configure(config):
    """Pytest marked for``core_version``"""
    config.addinivalue_line(
        "markers",
        'core_version(since="X.Y", before="X.Y"): '
        "run only on a Bitcoin Core in [since, before), skip otherwise",
    )


def _core_int(version: str) -> int:
    parts = version.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ValueError(f'core_version marker expects "X.Y", got {version!r}')
    major, minor = map(int, parts)
    return major * 10_000 + minor * 100


@pytest.fixture(scope="module")
def core_version(integration_test) -> int:
    """``getnetworkinfo`` version of the running Core (both backends share it)"""
    return integration_test.backends[0].client.call("getnetworkinfo")["version"]


@pytest.fixture(autouse=True)
def core_version_gate(request):
    """Skip a ``@pytest.mark.core_version`` test outside its Core range"""
    marker = request.node.get_closest_marker("core_version")
    if marker is None:
        return
    version = request.getfixturevalue("core_version")
    since, before = marker.kwargs.get("since"), marker.kwargs.get("before")
    if since is not None and version < _core_int(since):
        pytest.skip(f"needs Bitcoin Core >= {since} (running {version})")
    if before is not None and version >= _core_int(before):
        pytest.skip(f"needs Bitcoin Core < {before} (running {version})")


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


# PSBT, amount and text helpers
#
# Below this line some fixtures that could be used without importing embit
# or ``decimal`` again: conversions and text normalisation for assertions.
# -------------------------------------------------------------------------
@pytest.fixture
def rawtx_from_psbt():
    """hex of the transaction ``psbt`` carries, unsigned"""

    def _wrapper(psbt: str) -> str:
        return PSBT.from_string(psbt).tx.serialize().hex()

    return _wrapper


@pytest.fixture
def to_sats():
    """integer satoshis of a BTC amount decoded from Core"""

    def _wrapper(value) -> int:
        amount = Decimal(str(value)) * SATOSHIS
        if not amount.is_finite():
            raise ValueError(f"Invalid amount: {value}")

        if amount != amount.to_integral_value():
            raise ValueError(f"Not integral value: {amount}")
        return int(amount)

    return _wrapper


@pytest.fixture
def to_btc():
    """BTC ``float`` for a Core RPC amount argument"""

    def _wrapper(value: int) -> float:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"Expected integer satoshis: {value!r}")
        return float(Decimal(value) / SATOSHIS)

    return _wrapper


@pytest.fixture(name="to_formatted_btc")
def _to_formatted_btc():
    """Krux's review amount (``₿N.NNNNNNNN``) from integer sats"""

    def _wrapper(value: int) -> str:
        return f"₿{value // SATOSHIS}.{value % SATOSHIS:08d}"

    return _wrapper


@pytest.fixture
def to_full_summary(to_formatted_btc):
    """Krux's review summary"""

    def _wrapper(input_sats, payment_sats, change_sats, percent):
        fee_sats = input_sats - payment_sats - change_sats
        satvb = Decimal(fee_sats) / 141
        return (
            f"Inputs(1):{to_formatted_btc(input_sats)}"
            f"Spend(1):{to_formatted_btc(payment_sats)}"
            f"Self-transferorChange(1):{to_formatted_btc(change_sats)}"
            f"Fee:{to_formatted_btc(fee_sats)}({percent}%)~{satvb:.1f}sat/vB"
        )

    return _wrapper


@pytest.fixture
def compact_text():
    """drop layout whitespace, keep labels and digits"""

    def _wrapper(text: str) -> str:
        return "".join(text.split())

    return _wrapper


@pytest.fixture
def unsigned_tx():
    """unsigned tx of a ``decodepsbt`` result (for before and after core v32)"""

    def _wrapper(decoded: dict) -> dict:
        # PSBT v0
        if decoded["psbt_version"] == 0:
            return decoded["tx"]
        if decoded["psbt_version"] != 2:
            raise ValueError(f"Unknown PSBT version: {decoded['psbt_version']}")

        # PSBTv2
        for inp in decoded["inputs"]:
            if "time_locktime" in inp or "height_locktime" in inp:
                raise NotImplementedError("PSBTv2 input requires a locktime")

        return {
            "version": decoded["tx_version"],
            # BIP 370: an omitted PSBT_GLOBAL_FALLBACK_LOCKTIME is 0
            "locktime": decoded.get("fallback_locktime", 0),
            "vin": [
                {
                    "txid": inp["previous_txid"],
                    "vout": inp["previous_vout"],
                    # BIP 370: an omitted PSBT_IN_SEQUENCE is final
                    "sequence": inp.get("sequence", SEQUENCE_FINAL),
                }
                for inp in decoded["inputs"]
            ],
            "vout": [
                {"value": out["amount"], "n": n, "scriptPubKey": out["script"]}
                for n, out in enumerate(decoded["outputs"])
            ],
        }

    return _wrapper
