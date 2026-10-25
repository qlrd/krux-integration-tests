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

"""Native SegWit PSBT review, signing and confirmation against Bitcoin Core.

Fund a BIP84 watch-only wallet, check Krux's recipient/change/fee review
against Core's transaction data using integer satoshis, then sign and export
the PSBT through Krux. Core finalizes, accepts and confirms the transaction.
Unsigned and output-tampering controls must be rejected by Core.

Run the whole module: its ordered tests share the bornal lab and state.
"""

from decimal import ROUND_CEILING, Decimal

import pytest
from bornal.testing import (
    COINBASE_MATURITY,
    assert_chain,
    assert_finalized,
    assert_mempool_accepts,
    assert_mempool_rejects,
    assert_not_finalized,
    connect_p2p,
    generate_to_address,
    get_new_address,
    sync_blocks,
)
from embit.psbt import PSBT
from embit.transaction import Transaction
from krux.key import P2WPKH
from krux.qr import FORMAT_NONE

SATOSHIS = 100_000_000
FUNDING_SATS = 150_000_123
PAYMENT_SATS = 100_000_017


def _sats(value):
    """Convert Core's JSON BTC value exactly, without float arithmetic."""
    amount = Decimal(str(value)) * SATOSHIS
    assert amount.is_finite() and amount == amount.to_integral_value()
    return int(amount)


def _btc(sats):
    """Independent expected review amount, before locale whitespace."""
    return f"₿{sats // SATOSHIS}.{sats % SATOSHIS:08d}"


def _compact(text):
    """Ignore layout whitespace while retaining labels, addresses and digits."""
    return "".join(text.split())


@pytest.fixture(scope="module")
def script_type():
    """BIP84 signers for this module."""
    return P2WPKH


def test_000_watchonly_segwit(core, coordinator, signer):
    assert_chain(core, "regtest")
    assert_chain(coordinator.backend, "regtest")
    alice = coordinator.get_wallet("alice").backend.client
    info = alice.get_wallet_info()
    assert info["private_keys_enabled"] is False
    assert info["descriptors"] is True
    assert signer("alice").wallet.key.derivation == "m/84h/1h/0h"
    descriptors = alice.call("listdescriptors")["descriptors"]
    assert len(descriptors) == 2
    assert {desc["internal"] for desc in descriptors} == {False, True}
    assert all(desc["desc"].startswith("wpkh(") for desc in descriptors)


def test_001_fund(core, coordinator, signer, state):
    connect_p2p(core, coordinator.backend)
    mining_address = get_new_address(core, "mining", "bech32")
    generate_to_address(core, mining_address, COINBASE_MATURITY + 1)
    sync_blocks(core, coordinator.backend)

    alice = coordinator.get_wallet("alice").backend.client
    address = alice.get_new_address("funding", "bech32")
    # Compare the receive address on the coordinator and signer before funding.
    assert address == next(signer("alice").wallet.obtain_addresses())
    # The pinned bornal client has no send_to_address wrapper.
    state["funding_txid"] = core.client.call(
        "sendtoaddress", address, FUNDING_SATS / SATOSHIS
    )
    generate_to_address(core, mining_address, 1)
    sync_blocks(core, coordinator.backend)
    (utxo,) = alice.list_unspent()
    assert utxo["txid"] == state["funding_txid"]
    assert utxo["confirmations"] == 1
    assert _sats(utxo["amount"]) == FUNDING_SATS
    state["utxo"] = utxo
    state["mining_address"] = mining_address


def test_002_create_psbt(core, coordinator, signer, state):
    alice = coordinator.get_wallet("alice").backend.client
    recipient = get_new_address(core, "recipient", "bech32")
    utxo = state["utxo"]
    funded = alice.wallet_create_funded_psbt(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [{recipient: PAYMENT_SATS / SATOSHIS}],
        0,
        {"change_type": "bech32", "fee_rate": 1},
    )
    decoded = alice.decode_psbt(funded["psbt"])
    assert len(decoded["inputs"]) == 1
    assert len(decoded["tx"]["vout"]) == 2
    (vin,) = decoded["tx"]["vin"]
    assert (vin["txid"], vin["vout"]) == (utxo["txid"], utxo["vout"])
    assert _sats(decoded["inputs"][0]["witness_utxo"]["amount"]) == FUNDING_SATS
    assert funded["changepos"] in (0, 1)
    change = decoded["tx"]["vout"][funded["changepos"]]
    change_address = change["scriptPubKey"]["address"]
    assert change_address == next(
        signer("alice").wallet.obtain_addresses(branch_index=1)
    )
    assert alice.get_address_info(change_address)["ischange"] is True
    fee = FUNDING_SATS - sum(_sats(out["value"]) for out in decoded["tx"]["vout"])
    assert 0 < fee < 10_000
    assert fee == _sats(funded["fee"]) == _sats(decoded["fee"])
    state.update(
        psbt=funded["psbt"],
        recipient=recipient,
        change=change_address,
        change_sats=_sats(change["value"]),
        fee_sats=fee,
        unsigned_tx=decoded["tx"],
    )


def test_003_review(signer, state):
    messages, fee_percent = signer("alice").as_signer(state["psbt"]).outputs()
    assert len(messages) == 3
    summary, spend, change = map(_compact, messages)
    # Fee as a percentage of total outputs, rounded up to one decimal place.
    expected_percent = max(
        Decimal("0.1"),
        (
            Decimal(state["fee_sats"]) * 100 / (FUNDING_SATS - state["fee_sats"])
        ).quantize(Decimal("0.1"), rounding=ROUND_CEILING),
    )
    assert summary.startswith(
        f"Inputs(1):{_btc(FUNDING_SATS)}"
        f"Spend(1):{_btc(PAYMENT_SATS)}"
        f"Self-transferorChange(1):{_btc(state['change_sats'])}"
        f"Fee:{_btc(state['fee_sats'])}({expected_percent}%)"
    )
    assert spend == f"1.Spend:{state['recipient']}{_btc(PAYMENT_SATS)}"
    assert change == f"1.Change:{state['change']}{_btc(state['change_sats'])}"
    assert Decimal(str(fee_percent)) == expected_percent


def test_004_unsigned_control(coordinator, state):
    decoded = coordinator.backend.client.decode_psbt(state["psbt"])
    (inp,) = decoded["inputs"]
    assert not inp.get("partial_signatures")
    assert "final_scriptwitness" not in inp
    assert_not_finalized(coordinator.backend, state["psbt"])
    unsigned_hex = PSBT.from_string(state["psbt"]).tx.serialize().hex()
    assert_mempool_rejects(coordinator.backend, unsigned_hex)


def test_005_sign_export(coordinator, signer, state):
    krux = signer("alice").as_signer(state["psbt"])
    assert krux.path_mismatch() == ""
    krux.sign()
    exported, qr_format = krux.psbt_qr()
    assert qr_format == FORMAT_NONE
    decoded = coordinator.backend.client.decode_psbt(exported)
    (inp,) = decoded["inputs"]
    assert list(inp["partial_signatures"]) == [signer("alice").get_pubkey(0, 0).hex()]
    assert decoded["tx"] == state["unsigned_tx"]
    assert _sats(decoded["fee"]) == state["fee_sats"]
    state["exported"] = exported


def test_006_core_accepts(coordinator, state):
    # finalizepsbt has no signing capability: only Krux supplied signatures.
    hextx = assert_finalized(coordinator.backend, state["exported"])
    accepted = assert_mempool_accepts(coordinator.backend, hextx)
    assert _sats(accepted["fees"]["base"]) == state["fee_sats"]

    # A one-satoshi output change breaks the signature even with a higher fee.
    tampered = Transaction.parse(bytes.fromhex(hextx))
    tampered.vout[0].value -= 1
    assert_mempool_rejects(coordinator.backend, tampered.serialize().hex())
    state["signed_hex"] = hextx
    state["txid"] = accepted["txid"]


def test_007_broadcast_confirm(core, coordinator, state):
    alice = coordinator.get_wallet("alice").backend.client
    assert alice.send_raw_transaction(state["signed_hex"]) == state["txid"]
    (blockhash,) = generate_to_address(coordinator.backend, state["mining_address"], 1)
    sync_blocks(core, coordinator.backend)
    assert state["txid"] in core.client.call("getblock", blockhash)["tx"]
    assert alice.get_transaction(state["txid"])["confirmations"] == 1
    assert _sats(alice.get_balance()) == state["change_sats"]
    assert _sats(alice.get_received_by_address(state["change"])) == state["change_sats"]
    assert (
        _sats(core.client.get_received_by_address(state["recipient"])) == PAYMENT_SATS
    )
