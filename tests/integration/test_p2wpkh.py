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

from decimal import Decimal

import pytest
from bornal.testing import (
    COINBASE_MATURITY,
    assert_chain,
    assert_finalized,
    assert_mempool_accepts,
    assert_mempool_rejects,
    assert_next_role,
    assert_not_finalized,
    assert_send_rawtx_accepts,
    assert_wallet_info,
    connect_p2p,
    generate_to_address,
    get_new_address,
    sync_blocks,
)
from embit.hashes import hash160
from embit.transaction import Transaction
from krux.key import P2WPKH
from krux.qr import FORMAT_NONE

FUNDING_SATS = 150_000_123
PAYMENT_SATS = 100_000_017


@pytest.fixture(scope="module")
def script_type():
    """BIP84 signers for this module."""
    return P2WPKH


@pytest.fixture(name="expected_summary")
def fixture_expected_summary(to_formatted_btc):
    """Complete review text for one P2WPKH input and two P2WPKH outputs."""

    def _wrapper(input_sats, payment_sats, change_sats, percent):
        fee_sats = input_sats - payment_sats - change_sats
        # 113 base bytes plus 110 witness bytes (72-byte signature): 562 WU, 141 vB.
        satvb = Decimal(fee_sats) / 141
        return (
            f"Inputs(1):{to_formatted_btc(input_sats)}"
            f"Spend(1):{to_formatted_btc(payment_sats)}"
            f"Self-transferorChange(1):{to_formatted_btc(change_sats)}"
            f"Fee:{to_formatted_btc(fee_sats)}({percent}%)~{satvb:.1f}sat/vB"
        )

    return _wrapper


def test_000_watchonly_segwit(core, coordinator, signer):
    assert_chain(core, "regtest")
    assert_chain(coordinator.backend, "regtest")
    wallet = coordinator.get_wallet("alice").backend
    assert_wallet_info(wallet, "alice", watchonly=True)
    alice = wallet.client
    assert signer("alice").wallet.key.derivation == "m/84h/1h/0h"
    # Core uses separate public descriptors for receiving addresses
    # (internal=False) and change addresses (internal=True).
    descriptors = alice.call("listdescriptors")["descriptors"]
    assert len(descriptors) == 2
    assert {desc["internal"] for desc in descriptors} == {False, True}
    assert all(desc["desc"].startswith("wpkh(") for desc in descriptors)


def test_001_fund(core, coordinator, signer, state, to_btc, to_sats):
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
        "sendtoaddress", address, to_btc(FUNDING_SATS)
    )
    generate_to_address(core, mining_address, 1)
    sync_blocks(core, coordinator.backend)
    (utxo,) = alice.list_unspent()
    assert utxo["txid"] == state["funding_txid"]
    assert utxo["confirmations"] == 1
    assert to_sats(utxo["amount"]) == FUNDING_SATS
    state["utxo"] = utxo
    state["mining_address"] = mining_address


def test_002_create_psbt(core, coordinator, signer, state, to_btc, to_sats):
    alice = coordinator.get_wallet("alice").backend.client
    recipient = get_new_address(core, "recipient", "bech32")
    utxo = state["utxo"]
    funded = alice.wallet_create_funded_psbt(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [{recipient: to_btc(PAYMENT_SATS)}],
        0,
        {"change_type": "bech32", "fee_rate": 1},
    )
    decoded = alice.decode_psbt(funded["psbt"])
    assert len(decoded["inputs"]) == 1
    assert len(decoded["tx"]["vout"]) == 2
    (vin,) = decoded["tx"]["vin"]
    assert (vin["txid"], vin["vout"]) == (utxo["txid"], utxo["vout"])
    assert to_sats(decoded["inputs"][0]["witness_utxo"]["amount"]) == FUNDING_SATS
    assert funded["changepos"] in (0, 1)
    change = decoded["tx"]["vout"][funded["changepos"]]
    change_address = change["scriptPubKey"]["address"]
    assert change_address == next(
        signer("alice").wallet.obtain_addresses(branch_index=1)
    )
    assert alice.get_address_info(change_address)["ischange"] is True
    fee = FUNDING_SATS - sum(to_sats(out["value"]) for out in decoded["tx"]["vout"])
    assert 0 < fee < 10_000
    assert fee == to_sats(funded["fee"]) == to_sats(decoded["fee"])
    state.update(
        psbt=funded["psbt"],
        recipient=recipient,
        change=change_address,
        change_sats=to_sats(change["value"]),
        fee_sats=fee,
        unsigned_tx=decoded["tx"],
    )


def test_003_review(signer, state, compact_text, expected_summary, to_formatted_btc):
    messages, _ = signer("alice").as_signer(state["psbt"]).outputs()
    assert len(messages) == 3
    summary, spend, change = map(compact_text, messages)
    # This low-fee transaction exercises the 0.1% display minimum.
    assert summary == expected_summary(
        FUNDING_SATS, PAYMENT_SATS, state["change_sats"], "0.1"
    )
    assert spend == f"1.Spend:{state['recipient']}{to_formatted_btc(PAYMENT_SATS)}"
    assert change == (
        f"1.Change:{state['change']}{to_formatted_btc(state['change_sats'])}"
    )


def test_004_unsigned_control(coordinator, signer, state, rawtx_from_psbt):
    decoded = coordinator.backend.client.decode_psbt(state["psbt"])
    (inp,) = decoded["inputs"]
    assert not inp.get("partial_signatures")
    assert "final_scriptwitness" not in inp
    analysis = assert_next_role(coordinator.backend, state["psbt"], "signer")
    (inp_analysis,) = analysis["inputs"]
    assert inp_analysis["has_utxo"] is True
    assert inp_analysis["is_final"] is False
    assert inp_analysis["next"] == "signer"
    assert inp_analysis["missing"] == {
        "signatures": [hash160(signer("alice").get_pubkey(0, 0)).hex()]
    }
    assert_not_finalized(coordinator.backend, state["psbt"])
    assert_mempool_rejects(
        coordinator.backend,
        rawtx_from_psbt(state["psbt"]),
        rejectreason=(
            r"^(?:mandatory|mempool)-script-verify-flag-failed "
            r"\(Witness program hash mismatch\)$"
        ),
    )


def test_005_sign_export(coordinator, signer, state, to_sats):
    krux = signer("alice").as_signer(state["psbt"])
    assert krux.path_mismatch() == ""
    krux.sign()
    exported, qr_format = krux.psbt_qr()
    assert qr_format == FORMAT_NONE
    decoded = coordinator.backend.client.decode_psbt(exported)
    (inp,) = decoded["inputs"]
    assert list(inp["partial_signatures"]) == [signer("alice").get_pubkey(0, 0).hex()]
    assert decoded["tx"] == state["unsigned_tx"]
    assert to_sats(decoded["fee"]) == state["fee_sats"]
    state["exported"] = exported


def test_006_core_accepts(coordinator, state, to_sats):
    # finalizepsbt has no signing capability: only Krux supplied signatures.
    hextx = assert_finalized(coordinator.backend, state["exported"])
    accepted = assert_mempool_accepts(coordinator.backend, hextx)
    assert to_sats(accepted["fees"]["base"]) == state["fee_sats"]

    # A one-satoshi output change breaks the signature even with a higher fee.
    tampered = Transaction.parse(bytes.fromhex(hextx))
    tampered.vout[0].value -= 1
    assert_mempool_rejects(
        coordinator.backend,
        tampered.serialize().hex(),
        # Core 29 and Core 30/31 report this failed signature differently.
        rejectreason=(
            r"^(?:mandatory-script-verify-flag-failed \(Script evaluated without error "
            r"but finished with a false/empty top stack element\)"
            r"|mempool-script-verify-flag-failed "
            r"\(Signature must be zero for failed CHECK\(MULTI\)SIG operation\))$"
        ),
    )
    state["signed_hex"] = hextx
    state["txid"] = accepted["txid"]


def test_007_broadcast_confirm(core, coordinator, state, to_sats):
    alice = coordinator.get_wallet("alice").backend.client
    assert (
        assert_send_rawtx_accepts(coordinator.backend, state["signed_hex"])
        == state["txid"]
    )
    (blockhash,) = generate_to_address(coordinator.backend, state["mining_address"], 1)
    sync_blocks(core, coordinator.backend)
    assert state["txid"] in core.client.call("getblock", blockhash)["tx"]
    assert alice.get_transaction(state["txid"])["confirmations"] == 1
    assert to_sats(alice.get_balance()) == state["change_sats"]
    assert (
        to_sats(alice.get_received_by_address(state["change"])) == state["change_sats"]
    )
    assert (
        to_sats(core.client.get_received_by_address(state["recipient"])) == PAYMENT_SATS
    )


@pytest.fixture(name="review_case")
def fixture_review_case(core, coordinator, state, fee_case, to_btc, to_sats):
    """Fund a fresh UTXO and let Core populate an unsigned PSBT's wallet data."""
    fee_sats, output_sats, expected = fee_case
    alice = coordinator.get_wallet("alice").backend.client
    input_sats = output_sats + fee_sats
    funding_txid = core.client.call(
        "sendtoaddress",
        alice.get_new_address("fee-rounding", "bech32"),
        to_btc(input_sats),
    )
    generate_to_address(core, state["mining_address"], 1)
    sync_blocks(core, coordinator.backend)
    (utxo,) = [u for u in alice.list_unspent() if u["txid"] == funding_txid]
    assert to_sats(utxo["amount"]) == input_sats

    recipient = get_new_address(core, "fee-rounding", "bech32")
    change = alice.call("getrawchangeaddress", "bech32")
    psbt = alice.create_psbt(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [{recipient: to_btc(output_sats - 10_000)}, {change: to_btc(10_000)}],
    )
    return {
        "psbt": alice.wallet_process_psbt(psbt, sign=False)["psbt"],
        "input_sats": input_sats,
        "output_sats": output_sats,
        "payment_sats": output_sats - 10_000,
        "change_sats": 10_000,
        "fee_sats": fee_sats,
        "percent": expected,
        "recipient": recipient,
        "change": change,
    }


@pytest.mark.parametrize(
    "fee_case",
    [
        (0, 1_000_000, "0.1"),
        (100, 1_000_000, "0.1"),
        (1_000, 1_000_000, "0.1"),
        (1_005, 1_000_000, "0.1"),
        (141, 140_000, "0.1"),
        (1_099, 1_000_000, "0.1"),
        (1_100, 1_000_000, "0.2"),
        (2_005, 1_000_000, "0.2"),
        (2_100, 1_000_000, "0.3"),
    ],
)
def test_008_review_fee_rounding(
    coordinator,
    signer,
    review_case,
    to_sats,
    compact_text,
    expected_summary,
    to_formatted_btc,
):
    case = review_case
    decoded = coordinator.backend.client.decode_psbt(case["psbt"])
    assert to_sats(decoded["fee"]) == case["fee_sats"]
    assert (
        sum(to_sats(out["value"]) for out in decoded["tx"]["vout"])
        == case["output_sats"]
    )
    # Only the displayed summary is asserted.
    # Krux's second result is for the high-fee warning.
    messages, _ = signer("alice").as_signer(case["psbt"]).outputs()
    assert list(map(compact_text, messages)) == [
        expected_summary(
            case["input_sats"],
            case["payment_sats"],
            case["change_sats"],
            case["percent"],
        ),
        f"1.Spend:{case['recipient']}{to_formatted_btc(case['payment_sats'])}",
        f"1.Change:{case['change']}{to_formatted_btc(case['change_sats'])}",
    ]
