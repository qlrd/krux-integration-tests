"""MicroPython shims and shared fixtures for the Krux integration tests"""

import json
import os
import random
import sys
import time
import types
from collections import namedtuple
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
from bornal.client import ClientError
from bornal.daemon import free_port
from bornal.node import IntegrationTest, env_data_dir
from bornal.testing import assert_wallet_roundtrip
from embit.descriptor import checksum
from embit.networks import NETWORKS
from embit.psbt import PSBT
from krux.wallet import Wallet
from krux.key import Key, P2PKH, TYPE_SINGLESIG
from krux.psbt import PSBTSigner
from krux.qr import FORMAT_NONE

TREZOR_BIP39_VECTOR = tuple(
    [
        " ".join(["abandon"] * 11 + ["about"]),
        " ".join(["zoo"] * 11 + ["wrong"]),
    ]
)
SMALL_FUNDING = 0.001


@pytest.fixture
def tdata():
    """Reference vectors and amounts shared by the chains, like Krux's ``tdata``"""
    return namedtuple("tdata", ["TREZOR_BIP39_VECTOR", "SMALL_FUNDING"])(
        TREZOR_BIP39_VECTOR, SMALL_FUNDING
    )


class BaseTest(IntegrationTest):
    """Two ``bitcoin-core`` regtest nodes plus the Krux-side helpers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._signers: list[tuple[Wallet, str]] = []
        self._p2p_ports: list[int] = []
        self.state: dict = {}

    @property
    def signers(self):
        """``(krux wallet, output script descriptor)`` pairs, set once"""
        return self._signers

    @signers.setter
    def signers(self, value: list[tuple[Wallet, str]]):
        if len(self._signers) == 0:
            self._signers = value
        else:
            raise ValueError("Signers already set")

    def set_test_params(self):
        """Declare two listening ``bitcoin-core`` nodes on free p2p ports"""
        for _ in range(2):
            p = free_port()
            self._p2p_ports.append(p)
            self.log.info(f"p2p port {p}")
            self.add_backend("bitcoin-core", ["-listen=1", f"-bind=127.0.0.1:{p}"])

    def run_test(self):
        raise NotImplementedError("Implement please the test")

    def connect_p2p(self, i, j, timeout: int = 30):
        """``addnode`` backend ``j`` from backend ``i`` and wait for both to sync"""
        src = self.backends[i]
        dest = self.backends[j]
        src_addr = f"{src.daemon.host}:{self._p2p_ports[i]}"
        p2p_addr = f"{dest.daemon.host}:{self._p2p_ports[j]}"

        rpc_s = src.client.call

        res = rpc_s("addnode", p2p_addr, "onetry")
        assert res is None
        self.log.info(f"Connected {src_addr} to {p2p_addr}")
        self.sync_blocks(i, j, timeout)

    def sync_blocks(self, i, j, timeout: int = 30):
        """Wait until backends ``i`` and ``j`` report the same block count"""
        rpc_s = self.backends[i].client.call
        rpc_d = self.backends[j].client.call
        src_addr = f"{self.backends[i].daemon.host}:{self._p2p_ports[i]}"
        p2p_addr = f"{self.backends[j].daemon.host}:{self._p2p_ports[j]}"

        die = time.monotonic() + timeout
        while time.monotonic() < die:
            if rpc_s("getblockcount") == rpc_d("getblockcount"):
                self.log.info(f"Synced {p2p_addr} with {src_addr}")
                return
            time.sleep(0.25)
        raise AssertionError(f"Nodes did not sync in '{timeout}'")

    def mine_blocks(self):
        """Create ``bornal-wallet`` on backend 0 and mine past coinbase maturity"""
        self.log.info("Creating 'bornal-wallet' and mining 101 blocks on backend 0")
        assert_wallet_roundtrip(self.backends[0])
        rpc = self.backends[0].client.call
        if rpc("listwallets") != ["bornal-wallet"]:
            raise AssertionError("'bornal-wallet' not created")
        self.log.info("default bornal-wallet created")

    def create_watchonly_wallet(
        self,
        backend,
        name,
        descriptor: str | None = None,
    ):
        """``createwallet`` with private keys disabled + ``importdescriptors``"""
        rpc = backend.client.call
        if descriptor is None:
            raise ValueError("output script descriptor cannot be None")
        res = rpc("createwallet", name, True, True)
        self.log.info(f"Wallet {name} created.")
        if res["name"] != name:
            raise AssertionError(f"Invalid '{res['name']}' wallet")

        self.log.info(f"Importing '{descriptor}'")
        res = rpc(
            "importdescriptors",
            [
                {
                    "desc": descriptor,
                    "active": True,
                    "timestamp": "now",
                    "range": [0, 10],
                }
            ],
        )

        if not all(r["success"] for r in res):
            raise AssertionError(f"Invalid response: {res}")

    def stop_backends(self):
        """Stop every backend, then re-raise the first failure (if any)"""
        errors = []
        for backend in self.backends:
            try:
                backend.stop()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)
        self.backends = []
        if errors:
            raise errors[0]


# scope="session" don't refresh tests at each session
@pytest.fixture(scope="session")
def _running_tests():
    tests = {}
    yield tests
    for ps in tests.values():
        if ps["test"] is not None:
            ps["test"].stop_backends()


@pytest.fixture
def base_test(_running_tests):
    """A started ``BaseTest``; its backends are stopped on teardown"""

    def _start(tag: str, stop: bool = True):
        ps = _running_tests.setdefault(tag, {"test": None, "stop": stop})
        ps["stop"] = stop
        if ps["test"] is None:
            test = BaseTest(data_dir=os.path.join(env_data_dir(), tag))
            test.set_test_params()
            test.setup_backends()
            ps["test"] = test
        return ps["test"]

    yield _start

    for ps in _running_tests.values():
        if ps["stop"] and ps["test"] is not None:
            ps["test"].stop_backends()
            ps["test"] = None


@pytest.fixture
def output_script_descriptor():
    """Checksummed ``tpub`` descriptor of a Krux wallet (watch-only)"""

    def _wrapper(wallet: Wallet, watch_only: bool = True):
        if wallet.descriptor is None:
            raise ValueError(f"invalid null descriptor for {wallet.key.script_type}")
        desc = wallet.descriptor.to_string()
        if not watch_only:
            key = wallet.key
            tprv = key.root.derive(key.derivation).to_base58(key.network["xprv"])
            desc = desc.replace(key.xpub(), tprv)
        return checksum.add_checksum(desc)

    return _wrapper


@pytest.fixture
def airgap_wallet():
    """Build a Krux ``Wallet`` from a mnemonic"""

    def _wrapper(mnemonic: str, policy: int, network: str, script_type: int):
        key = Key(mnemonic, policy, network, script_type=script_type)
        wallet = Wallet(key)
        return wallet

    return _wrapper


@pytest.fixture
# pylint: disable-next=redefined-outer-name
def p2pkh_signers(airgap_wallet, output_script_descriptor, tdata):
    """``(wallet, descriptor)`` for each reference mnemonic, regtest p2pkh"""
    wallets = []
    for v in tdata.TREZOR_BIP39_VECTOR:
        wallet = airgap_wallet(v, TYPE_SINGLESIG, NETWORKS["regtest"], P2PKH)
        descrp = output_script_descriptor(wallet)
        wallets.append((wallet, descrp))
    return wallets


@pytest.fixture
def getpubkey():
    """Compressed pubkey (``sec``) of ``signer`` at ``<account>/branch/index``"""

    def _wrapper(signer, branch, index):
        return signer.key.account.derive([branch, index]).key.sec()

    return _wrapper


@pytest.fixture
def psbtcopy():
    """Convert the psbt from a str to ``krux.psbt.PSBT`` instace."""

    def _wrapper(psbt: str):
        return PSBT.from_string(psbt)

    return _wrapper


@pytest.fixture
def psbtsigner():
    """Get the ``krux.psbt.PSBTSigner`` from a given wallet and arbitrary ``krux.psbt.PSBT``."""

    def _wrapper(wallet: Wallet, psbt: PSBT | str) -> PSBTSigner:
        data = psbt.to_string() if isinstance(psbt, PSBT) else psbt
        return PSBTSigner(wallet, data, FORMAT_NONE)

    return _wrapper


@pytest.fixture
def assert_finalizable():
    """Core finalizes ``psbt`` and the mempool would accept it."""

    def _wrapper(backend, psbt: str):
        rpc = backend.client.call
        finalized = rpc("finalizepsbt", psbt)
        assert finalized["complete"]
        accepted = rpc("testmempoolaccept", [finalized["hex"]])[0]
        assert accepted["allowed"], accepted.get("reject-reason")
        return finalized

    return _wrapper


# add to bornal
@pytest.fixture
def assert_unbroadcastable():
    """Check if core cannot finalize and the mempool rejects the unsigned tx"""

    def _wrapper(
        backend,
        psbt: str,
        role: str = "signer",
        rejectreason: str = "mempool-script-verify-flag-failed",
    ):
        rpc = backend.client.call
        finalized = rpc("finalizepsbt", psbt)
        assert not finalized["complete"]
        assert "hex" not in finalized

        analysis = rpc("analyzepsbt", psbt)
        assert analysis["next"] == role

        unsigned = PSBT.from_string(psbt).tx.serialize().hex()
        with pytest.raises(ClientError, match=rejectreason):
            rpc("sendrawtransaction", unsigned)

    return _wrapper
