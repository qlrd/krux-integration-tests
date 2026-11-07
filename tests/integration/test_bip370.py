# The MIT License (MIT)
#
# Copyright (c) 2026 selfcustody
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
# Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
test_bip370.py

    summary:
        Model a krux and bitcoin-core interaction with a PSBTv2 (BIP-370). Same
        2 nodes as ``test_p2pkh.py``: ``core`` (hot ``bornal-wallet``: mines and
        funds) and ``watchonly`` (Krux's ``tpub`` descriptors, no private keys).
        Core creates the PSBTv2, embit parses it, Krux validates and signs it,
        Core finalizes and broadcasts. Run the whole module, not a single test.

    targets:
        - bitcoin-core on regtest (PSBTv2 ``psbt_version`` RPC argument).
        - embit.psbt (PSBTv2 parsing, validation and tx reconstruction).
        - krux.psbt module

    strategy:
        - uses the Trezor BIP-39 vectors as ``alice`` (abandon) and ``bob`` (zoo)
        - fund ``alice`` and ask core for an explicit PSBTv2 (and a PSBTv0 to
          compare), to bornal's ``UNSPENDABLE_ADDRESS``
        - embit and core must agree on every v2 global, input and output field
        - negative tests: v2 fields in v0, v0 fields in v2, missing required v2
          fields, broken framing; embit, krux and core refuse all of them
        - non-standard sighashes on a v2 psbt: krux refuses to sign
        - krux signs untrimmed (stays v2) and trimmed (the device path, which
          krux rebuilds as PSBTv0); core finalizes and accepts both
        - the ``core`` node sees the krux tx in a block

Build the daemon and run this test with the bornal's ``pytest`` plugin::

    pytest --build-bitcoin latest --wallet tests/integration/test_bip370.py
"""

import re
from base64 import b64decode, b64encode
from io import BytesIO

from pytest import raises

from bornal.client import ClientError
from bornal.plugins.bitcoind import UNSPENDABLE_ADDRESS
from bornal.testing import (
    BASE_COINBASE_SUBSIDY,
    COINBASE_MATURITY,
    assert_block_count,
    assert_chain,
    assert_finalized,
    assert_mempool_accepts,
    assert_next_role,
    assert_not_finalized,
    assert_send_rawtx_accepts,
    assert_send_rawtx_rejects,
    connect_p2p,
    generate_to_address,
    get_new_address,
    sync_blocks,
)

from embit import compact
from embit.networks import NETWORKS
from embit.psbt import PSBT, PSBTError

from krux.qr import FORMAT_NONE

ALICE = "alice"
BOB = "bob"
FUNDING = 1.5
PAYMENT = 1.0
LOCKTIME = 0
TX_VERSION = 2
PSBT_V0 = 0
PSBT_V2 = 2
OPTIONS = {"change_type": "legacy", "fee_rate": 1}

# BIP-174 / BIP-370 key types
PSBT_GLOBAL_UNSIGNED_TX = b"\x00"
PSBT_GLOBAL_TX_VERSION = b"\x02"
PSBT_GLOBAL_FALLBACK_LOCKTIME = b"\x03"
PSBT_GLOBAL_INPUT_COUNT = b"\x04"
PSBT_GLOBAL_OUTPUT_COUNT = b"\x05"
PSBT_IN_PREVIOUS_TXID = b"\x0e"
PSBT_IN_OUTPUT_INDEX = b"\x0f"
PSBT_OUT_AMOUNT = b"\x03"
PSBT_OUT_SCRIPT = b"\x04"

GLOBAL = 0
INPUT = 1
OUTPUT = 2  # one input in this module, so the first output map is the third


def unsigned_hex(psbt: str) -> str:
    """Raw hex of the transaction ``psbt`` carries, signatures left out"""
    return PSBT.from_string(psbt).tx.serialize().hex()


def funded_psbt(wallet, psbt_version: int) -> dict:
    # bornal's ``wallet_create_funded_psbt`` has no ``psbt_version`` argument:
    # (inputs, outputs, locktime, options, bip32derivs, version, psbt_version)
    return wallet.backend.client.call(
        "walletcreatefundedpsbt",
        [],
        [{UNSPENDABLE_ADDRESS: PAYMENT}],
        LOCKTIME,
        OPTIONS,
        True,
        TX_VERSION,
        psbt_version,
    )


def split_maps(psbt: str) -> list[list[tuple[bytes, bytes]]]:
    stream = BytesIO(b64decode(psbt)[len(PSBT.MAGIC) :])
    maps, current = [], []
    while stream.read(1):
        stream.seek(-1, 1)
        keylen = compact.read_from(stream)
        if keylen == 0:
            maps.append(current)
            current = []
            continue
        key = stream.read(keylen)
        current.append((key, stream.read(compact.read_from(stream))))
    return maps


def join_maps(maps: list[list[tuple[bytes, bytes]]]) -> bytes:
    raw = PSBT.MAGIC
    for kvs in maps:
        for key, value in kvs:
            raw += compact.to_bytes(len(key)) + key
            raw += compact.to_bytes(len(value)) + value
        raw += b"\x00"
    return raw


def with_field(psbt: str, index: int, key: bytes, value: bytes) -> bytes:
    maps = split_maps(psbt)
    maps[index].append((key, value))
    return join_maps(maps)


def without_field(psbt: str, index: int, key: bytes) -> bytes:
    """Raw ``psbt`` with ``key`` removed from map ``index``"""
    maps = split_maps(psbt)
    maps[index] = [(k, v) for k, v in maps[index] if k != key]
    return join_maps(maps)


def assert_all_reject(coordinator, signer, raw: bytes, embit_err: str, core_err: str):
    with raises(PSBTError, match=re.escape(embit_err)):
        PSBT.parse(raw)

    # krux swallows the parser error, the user only sees "invalid PSBT"
    with raises(ValueError, match="invalid PSBT"):
        signer(ALICE).as_signer(b64encode(raw).decode())

    with raises(ClientError, match=re.escape(f"TX decode failed {core_err}")):
        coordinator.backend.client.decode_psbt(b64encode(raw).decode())


def test_000_start(core, coordinator):
    assert_chain(core, "regtest")
    assert_chain(coordinator.backend, "regtest")
    assert_block_count(core, 0)
    assert_block_count(coordinator.backend, 0)


def test_001_init_network(core, coordinator):
    connect_p2p(core, coordinator.backend)
    assert core.client.get_connection_count() == 1
    assert coordinator.backend.client.get_connection_count() == 1


def test_002_watchonly_wallets(coordinator):
    assert coordinator.wallets == [ALICE, BOB]
    assert sorted(coordinator.backend.client.list_wallets()) == [ALICE, BOB]


def test_003_mine(core, coordinator):
    address = get_new_address(core, "coinbase", "legacy")
    generate_to_address(core, address, COINBASE_MATURITY + 1)
    sync_blocks(core, coordinator.backend)

    assert_block_count(coordinator.backend, COINBASE_MATURITY + 1)
    assert core.client.get_balance() >= BASE_COINBASE_SUBSIDY


def test_004_send_to_alice(core, coordinator, signer, state):
    alice = coordinator.get_wallet(ALICE)
    addr = alice.backend.client.get_new_address("", "legacy")
    assert addr == next(signer(ALICE).wallet.obtain_addresses())

    txid = core.client.call("sendtoaddress", addr, FUNDING)
    assert txid in core.client.get_raw_mempool()

    state["address"] = addr
    state["txid"] = txid


def test_005_confirm(core, coordinator, state):
    generate_to_address(core, UNSPENDABLE_ADDRESS, 1)
    sync_blocks(core, coordinator.backend)
    assert_block_count(coordinator.backend, COINBASE_MATURITY + 2)

    alice = coordinator.get_wallet(ALICE)
    assert alice.backend.client.get_balance() == FUNDING
    (utxo,) = alice.backend.client.list_unspent()
    assert (utxo["txid"], utxo["address"]) == (state["txid"], state["address"])


def test_006_create_psbts(coordinator, state):
    alice = coordinator.get_wallet(ALICE)
    state["psbt_v0"] = funded_psbt(alice, PSBT_V0)["psbt"]

    res = funded_psbt(alice, PSBT_V2)
    assert 0 < res["fee"] < 0.0001
    assert res["changepos"] != -1

    state["psbt"] = res["psbt"]
    state["changepos"] = res["changepos"]
    state["fee"] = res["fee"]


def test_007_core_decodes_v2(coordinator, state):
    v0 = coordinator.backend.client.decode_psbt(state["psbt_v0"])
    assert v0["psbt_version"] == PSBT_V0
    assert "tx" in v0
    assert "input_count" not in v0

    # PSBTv2 has no global unsigned tx, the fields live in the maps
    v2 = coordinator.backend.client.decode_psbt(state["psbt"])
    assert v2["psbt_version"] == PSBT_V2
    assert "tx" not in v2
    assert v2["tx_version"] == TX_VERSION
    assert v2["fallback_locktime"] == LOCKTIME
    assert (v2["input_count"], v2["output_count"]) == (1, 2)

    (inp,) = v2["inputs"]
    assert {"previous_txid", "previous_vout", "sequence", "non_witness_utxo"} <= set(
        inp
    )
    for out in v2["outputs"]:
        assert {"amount", "script"} <= set(out)


def test_008_embit_parses_v2(state):
    psbt = PSBT.from_string(state["psbt"])
    assert psbt.version == PSBT_V2
    assert psbt.tx_version == TX_VERSION
    assert psbt.locktime == LOCKTIME
    assert psbt.determine_locktime() == LOCKTIME
    assert psbt.tx_modifiable_flags is None

    # a valid v2 psbt round-trips byte for byte
    assert psbt.to_string() == state["psbt"]

    assert PSBT.from_string(state["psbt_v0"]).version is None


def test_009_embit_reconstructs_tx(coordinator, state):
    decoded = coordinator.backend.client.decode_psbt(state["psbt"])
    tx = PSBT.from_string(state["psbt"]).tx

    assert (tx.version, tx.locktime) == (TX_VERSION, LOCKTIME)

    (vin,) = tx.vin
    (inp,) = decoded["inputs"]
    assert vin.txid.hex() == inp["previous_txid"] == state["txid"]
    assert vin.vout == inp["previous_vout"]
    assert vin.sequence == inp["sequence"]

    regtest = NETWORKS["regtest"]
    assert [(o.script_pubkey.address(regtest), o.value) for o in tx.vout] == [
        (o["script"]["address"], round(o["amount"] * 1e8)) for o in decoded["outputs"]
    ]
    assert (
        tx.vout[1 - state["changepos"]].script_pubkey.address(regtest)
        == UNSPENDABLE_ADDRESS
    )


def test_010_krux_accepts_v2(coordinator, signer, state):
    psbt = state["psbt"]
    assert signer(ALICE).as_signer(psbt).path_mismatch() == ""

    assert coordinator.backend.client.analyze_psbt(psbt)["fee"] == state["fee"]
    assert_not_finalized(coordinator.backend, psbt)
    assert_next_role(coordinator.backend, psbt, "signer")
    assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(psbt))


def test_011_v2_fields_in_v0(coordinator, signer, state):
    cases = [
        (PSBT_GLOBAL_TX_VERSION, TX_VERSION, "PSBT_GLOBAL_TX_VERSION"),
        (PSBT_GLOBAL_FALLBACK_LOCKTIME, LOCKTIME, "PSBT_GLOBAL_FALLBACK_LOCKTIME"),
    ]

    for key, value, name in cases:
        raw = with_field(state["psbt_v0"], GLOBAL, key, value.to_bytes(4, "little"))
        assert_all_reject(
            coordinator,
            signer,
            raw,
            "PSBTv2 global field is not allowed in PSBTv0",
            f"{name} is not allowed in PSBTv0",
        )


def test_012_unsigned_tx_in_v2(coordinator, signer, state):
    tx = PSBT.from_string(state["psbt"]).tx.serialize()
    raw = with_field(state["psbt"], GLOBAL, PSBT_GLOBAL_UNSIGNED_TX, tx)
    assert_all_reject(
        coordinator,
        signer,
        raw,
        "Global TX field is not allowed in PSBTv2",
        "PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2",
    )


def test_013_v2_missing_required(coordinator, signer, state):
    missing = "Missing required PSBTv2 global field"
    cases = [
        (GLOBAL, PSBT_GLOBAL_TX_VERSION, missing, "PSBT_GLOBAL_TX_VERSION is"),
        (GLOBAL, PSBT_GLOBAL_INPUT_COUNT, missing, "PSBT_GLOBAL_INPUT_COUNT is"),
        (GLOBAL, PSBT_GLOBAL_OUTPUT_COUNT, missing, "PSBT_GLOBAL_OUTPUT_COUNT is"),
        (
            INPUT,
            PSBT_IN_PREVIOUS_TXID,
            "PSBTv2 input 0 missing required PSBT_IN_PREVIOUS_TXID (0x0e)",
            "Previous TXID is",
        ),
        (
            INPUT,
            PSBT_IN_OUTPUT_INDEX,
            "PSBTv2 input 0 missing required PSBT_IN_OUTPUT_INDEX (0x0f)",
            "Previous output's index is",
        ),
        (
            OUTPUT,
            PSBT_OUT_AMOUNT,
            "PSBTv2 output 0 missing required PSBT_OUT_AMOUNT (0x03)",
            "Output amount is",
        ),
        (
            OUTPUT,
            PSBT_OUT_SCRIPT,
            "PSBTv2 output 0 missing required PSBT_OUT_SCRIPT (0x04)",
            "Output script is",
        ),
    ]

    for index, key, embit_err, core_err in cases:
        raw = without_field(state["psbt"], index, key)
        assert_all_reject(
            coordinator, signer, raw, embit_err, f"{core_err} required in PSBTv2"
        )


def test_014_v2_framing(coordinator, signer, state):
    raw = b64decode(state["psbt"])
    magic = len(PSBT.MAGIC)
    tx_version = (TX_VERSION).to_bytes(4, "little")
    cases = [
        (
            with_field(state["psbt"], GLOBAL, PSBT_GLOBAL_TX_VERSION, tx_version),
            "Duplicated global key: 02",
            'Duplicate Key, global key "02" already provided',
        ),
        (raw + b"\x00", "Unexpected extra bytes", "extra data after PSBT"),
        (
            # the first key length (1) re-encoded as a 3-byte compact size
            raw[:magic] + b"\xfd\x01\x00" + raw[magic + 1 :],
            "Non-canonical compact int encoding",
            "non-canonical ReadCompactSize()",
        ),
        (
            raw[:-1],
            "Can't read one byte from the stream",
            "Separator is missing at the end of an output map",
        ),
    ]

    for malformed, embit_err, core_err in cases:
        assert_all_reject(coordinator, signer, malformed, embit_err, core_err)


def test_015_v2_sighash(coordinator, signer, state):
    alice = signer(ALICE)
    alice_wallet = coordinator.get_wallet(ALICE)
    cases = [("NONE", "0x02"), ("SINGLE", "0x03"), ("ALL|ANYONECANPAY", "0x81")]

    for sighash, _hex in cases:
        req = alice_wallet.backend.client.wallet_process_psbt(
            state["psbt"], False, sighash
        )
        decoded = coordinator.backend.client.decode_psbt(req["psbt"])
        assert decoded["psbt_version"] == PSBT_V2
        assert decoded["inputs"][0]["sighash"] == sighash

        _krux = alice.as_signer(req["psbt"])
        with raises(ValueError, match=f"Input 0 has non-standard sighash type: {_hex}"):
            _krux.sign()

        unsigned = _krux.psbt.to_string()
        assert_not_finalized(coordinator.backend, unsigned)
        assert_next_role(coordinator.backend, unsigned, "updater")
        assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(unsigned))


def test_016_sign_untrimmed(coordinator, signer, state):
    # without trimming krux keeps the PSBTv2 and embit records the signer's
    # SIGHASH_ALL in PSBT_GLOBAL_TX_MODIFIABLE (inputs and outputs locked)
    alice_signer = signer(ALICE).as_signer(state["psbt"])
    alice_signer.sign(trim=False)
    assert alice_signer.psbt.version == PSBT_V2
    assert alice_signer.psbt.tx_modifiable_flags == 0

    signed = alice_signer.psbt.to_string()
    assert coordinator.backend.client.decode_psbt(signed)["psbt_version"] == PSBT_V2
    assert_next_role(coordinator.backend, signed, "finalizer")

    hextx = assert_finalized(coordinator.backend, signed)
    assert_mempool_accepts(coordinator.backend, hextx)
    state["untrimmed"] = hextx


def test_017_sign(coordinator, signer, state):
    alice = signer(ALICE)
    alice_signer = alice.as_signer(state["psbt"])
    assert alice_signer.path_mismatch() == ""
    alice_signer.sign()

    # krux trims the signed psbt into ``PSBT(self.psbt.tx)``: a PSBTv0
    assert alice_signer.psbt.version is None
    (inp,) = alice_signer.psbt.inputs
    assert [pub.sec() for pub in inp.partial_sigs] == [alice.get_pubkey(0, 0)]

    signed, fmt = alice_signer.psbt_qr()
    assert fmt == FORMAT_NONE
    assert coordinator.backend.client.decode_psbt(signed)["psbt_version"] == PSBT_V0
    assert_next_role(coordinator.backend, signed, "finalizer")

    # the downgrade does not touch the transaction: same tx as untrimmed
    hextx = assert_finalized(coordinator.backend, signed)
    assert hextx == state["untrimmed"]
    assert_mempool_accepts(coordinator.backend, hextx)
    state["signed"] = hextx


def test_018_broadcast(core, coordinator, state):
    alice = coordinator.get_wallet(ALICE)
    txid = assert_send_rawtx_accepts(alice.backend, state["signed"])
    assert alice.backend.client.get_raw_mempool() == [txid]

    (blockhash,) = generate_to_address(alice.backend, UNSPENDABLE_ADDRESS, 1)
    sync_blocks(alice.backend, core)
    assert_block_count(core, COINBASE_MATURITY + 3)
    assert txid in core.client.call("getblock", blockhash)["tx"]

    change = round(FUNDING - PAYMENT - state["fee"], 8)
    assert alice.backend.client.get_transaction(txid)["confirmations"] == 1
    assert alice.backend.client.get_balance() == change
