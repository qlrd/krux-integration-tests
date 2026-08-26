"""MicroPython shims and shared fixtures for the Krux integration tests"""

import json
import random
import sys
import time
import types
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

# pylint: disable=wrong-import-position  # must follow the shims above
from embit.descriptor import checksum
from embit.networks import NETWORKS
from krux.wallet import Wallet
from krux.key import Key, TYPE_SINGLESIG, P2PKH

_VECTORS = (
    " ".join(["abandon"] * 11 + ["about"]),
    " ".join(["zoo"] * 11 + ["wrong"]),
)


@pytest.fixture
def output_script_descriptor(monkeypatch):
    def _wrapper(wallet: Wallet, watch_only: bool = True, key_type="p2pkh"):
        if wallet.descriptor is None:
            raise ValueError(
                "invalid null descriptor for {}".format(wallet.key.script_type)
            )
        desc = wallet.descriptor.to_string()
        if not watch_only:
            key = wallet.key
            tprv = key.root.derive(key.derivation).to_base58(key.network["xprv"])
            desc = desc.replace(key.xpub(), tprv)
        return checksum.add_checksum(desc)

    return _wrapper


@pytest.fixture
def airgap_wallet():
    def _wrapper(mnemonic: str, policy: int, network: str, script_type: int):
        key = Key(mnemonic, policy, network, script_type=script_type)
        wallet = Wallet(key)
        return wallet

    return _wrapper

@pytest.fixture
def krux_p2pkh_wallets(airgap_wallet, output_script_descriptor):
    wallets = []
    for v in _VECTORS:
        wallet = airgap_wallet(v, TYPE_SINGLESIG, NETWORKS["regtest"], P2PKH)
        descrp = output_script_descriptor(wallet)
        wallets.append((wallet, descrp))
    return wallets
