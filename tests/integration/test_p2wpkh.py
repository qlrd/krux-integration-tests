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

import pytest
from bornal.client import ClientError
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
from embit.networks import NETWORKS
from embit.psbt import PSBT
from embit.transaction import Transaction
from krux.key import (
    P2PKH,
    P2SH,
    P2SH_P2WSH,
    P2TR,
    P2WPKH,
    P2WSH,
    TYPE_MINISCRIPT,
    TYPE_MULTISIG,
    TYPE_SINGLESIG,
)
from krux.qr import FORMAT_NONE

FUNDING_SATS = 150_000_123
PAYMENT_SATS = 100_000_017
NO_WITNESS = (
    r"^(?:mandatory|mempool)-script-verify-flag-failed "
    r"\(Witness program hash mismatch\)$"
)
BAD_SIGNATURE = (
    r"^(?:mandatory-script-verify-flag-failed \(Script evaluated without error "
    r"but finished with a false/empty top stack element\)"
    r"|mempool-script-verify-flag-failed "
    r"\(Signature must be zero for failed CHECK\(MULTI\)SIG operation\))$"
)


@pytest.fixture(scope="module")
def script_type():
    """BIP84 signers for this module."""
    return P2WPKH


def test_000_watchonly_segwit(core, coordinator, signer):
    assert_chain(core, "regtest")
    assert_chain(coordinator.backend, "regtest")
    wallet = coordinator.get_wallet("alice").backend
    assert_wallet_info(wallet, "alice", watchonly=True)
    alice = wallet.client
    assert signer("alice").wallet.key.derivation == "m/84h/1h/0h"
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


def test_002_create_psbt(
    core, coordinator, signer, state, to_btc, to_sats, unsigned_tx
):
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
    tx = unsigned_tx(decoded)
    assert len(decoded["inputs"]) == 1
    assert len(tx["vout"]) == 2
    assert [(vin["txid"], vin["vout"]) for vin in tx["vin"]] == [
        (utxo["txid"], utxo["vout"])
    ]
    assert to_sats(decoded["inputs"][0]["witness_utxo"]["amount"]) == FUNDING_SATS
    assert funded["changepos"] in (0, 1)
    change = tx["vout"][funded["changepos"]]
    change_address = change["scriptPubKey"]["address"]
    assert change_address == next(
        signer("alice").wallet.obtain_addresses(branch_index=1)
    )
    assert alice.get_address_info(change_address)["ischange"] is True
    fee = FUNDING_SATS - sum(to_sats(out["value"]) for out in tx["vout"])
    assert 0 < fee < 10_000
    assert fee == to_sats(funded["fee"]) == to_sats(decoded["fee"])
    state.update(
        psbt=funded["psbt"],
        psbt_version=decoded["psbt_version"],
        recipient=recipient,
        change=change_address,
        change_path=alice.account_path(change_address),
        change_sats=to_sats(change["value"]),
        fee_sats=fee,
        unsigned_tx=tx,
    )


def test_003_review(signer, state, compact_text, to_full_summary, to_formatted_btc):
    messages, _ = signer("alice").as_signer(state["psbt"]).outputs()
    assert len(messages) == 3
    summary, spend, change = map(compact_text, messages)
    # This low-fee transaction exercises the 0.1% display minimum.
    assert summary == to_full_summary(
        FUNDING_SATS, PAYMENT_SATS, state["change_sats"], "0.1"
    )
    assert spend == f"1.Spend:{state['recipient']}{to_formatted_btc(PAYMENT_SATS)}"
    assert change == (
        f"1.Change:{state['change_path']}{state['change']}"
        f"{to_formatted_btc(state['change_sats'])}"
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
        coordinator.backend, rawtx_from_psbt(state["psbt"]), rejectreason=NO_WITNESS
    )


def test_005_wrong_signer(coordinator, signer, state, rawtx_from_psbt):
    krux = signer("bob").as_signer(state["psbt"])
    assert krux.path_mismatch() == ""
    with pytest.raises(ValueError, match="cannot sign"):
        krux.sign()

    unsigned = krux.psbt.to_string()
    assert_not_finalized(coordinator.backend, unsigned)
    assert_next_role(coordinator.backend, unsigned, "signer")
    assert_mempool_rejects(
        coordinator.backend, rawtx_from_psbt(unsigned), rejectreason=NO_WITNESS
    )


def test_006_not_a_psbt(coordinator, signer, state):
    rawtx = coordinator.backend.client.create_raw_transaction(
        [], [{state["recipient"]: 1}]
    )
    with pytest.raises(ValueError, match="invalid PSBT"):
        signer("alice").as_signer(rawtx)
    with pytest.raises(ClientError, match="TX decode failed"):
        coordinator.backend.client.finalize_psbt(rawtx)


@pytest.mark.parametrize(
    "network, script",
    [
        ("regtest", P2PKH),  # right net, wrong purpose: 44h
        ("regtest", P2TR),  # right net, wrong purpose: 86h
        ("main", P2WPKH),  # wrong net, right purpose: 84h/0h
    ],
)
def test_007_path_mismatch(
    coordinator, signer, state, rawtx_from_psbt, network, script
):
    variant = signer("alice").as_variant(TYPE_SINGLESIG, NETWORKS[network], script)
    krux = variant.as_signer(state["psbt"])
    assert krux.path_mismatch() == "m/84h/1h/0h"

    # Using `to_string()` to simulate a declining "Proceed?" so the `warning`
    # leaves the PSBT unsigned
    unsigned = krux.psbt.to_string()
    assert_not_finalized(coordinator.backend, unsigned)
    assert_next_role(coordinator.backend, unsigned, "signer")
    assert_mempool_rejects(
        coordinator.backend, rawtx_from_psbt(unsigned), rejectreason=NO_WITNESS
    )


@pytest.mark.parametrize(
    "policy, script, error",
    [
        (TYPE_MULTISIG, P2SH, "Not a multisig PSBT"),
        (TYPE_MULTISIG, P2SH_P2WSH, "Not a multisig PSBT"),
        (TYPE_MULTISIG, P2WSH, "Not a multisig PSBT"),
        (TYPE_MINISCRIPT, P2WSH, "Not a miniscript PSBT"),
        (TYPE_MINISCRIPT, P2TR, "Not a miniscript PSBT"),
    ],
)
def test_008_wrong_policy(
    coordinator, signer, state, rawtx_from_psbt, policy, script, error
):
    variant = signer("alice").as_variant(policy, NETWORKS["regtest"], script)
    with pytest.raises(ValueError, match=f"Invalid PSBT: {error}"):
        variant.as_signer(state["psbt"])

    assert_not_finalized(coordinator.backend, state["psbt"])
    assert_next_role(coordinator.backend, state["psbt"], "signer")
    assert_mempool_rejects(
        coordinator.backend, rawtx_from_psbt(state["psbt"]), rejectreason=NO_WITNESS
    )


def test_009_missing_utxo(coordinator, signer, state, rawtx_from_psbt, to_btc):
    alice = coordinator.get_wallet("alice").backend.client
    node = coordinator.backend.client

    # 1) The coordinator attaches no UTXO data at all and Krux cannot tell the
    # input is segwit and asks for the previous transaction.
    bare = alice.create_psbt(
        [{"txid": state["utxo"]["txid"], "vout": state["utxo"]["vout"]}],
        [{state["recipient"]: to_btc(PAYMENT_SATS)}],
    )
    with pytest.raises(ValueError, match="Invalid PSBT: missing non_witness_utxo"):
        signer("alice").as_signer(bare)
    (analysis,) = node.analyze_psbt(bare)["inputs"]
    assert analysis["has_utxo"] is False
    assert_not_finalized(coordinator.backend, bare)
    assert_next_role(coordinator.backend, bare, "updater")
    assert_mempool_rejects(
        coordinator.backend, rawtx_from_psbt(bare), rejectreason=NO_WITNESS
    )

    # 2) Unlike a legacy input, the node's UTXO set is enough to declare the
    # amount, but without the key origin Krux finds no key of its own.
    updated = node.call("utxoupdatepsbt", bare)
    (inp,) = node.decode_psbt(updated)["inputs"]
    assert "witness_utxo" in inp
    assert "non_witness_utxo" not in inp
    assert "bip32_derivs" not in inp
    krux = signer("alice").as_signer(updated)
    assert krux.path_mismatch() == ""
    with pytest.raises(ValueError, match="cannot sign"):
        krux.sign()
    assert_not_finalized(coordinator.backend, updated)
    assert_next_role(coordinator.backend, updated, "updater")
    assert_mempool_rejects(
        coordinator.backend, rawtx_from_psbt(updated), rejectreason=NO_WITNESS
    )

    # 3) Only the watch-only wallet can add the derivation Krux signs with.
    repaired = alice.wallet_process_psbt(updated, sign=False)
    assert repaired["complete"] is False
    (inp,) = node.decode_psbt(repaired["psbt"])["inputs"]
    (deriv,) = inp["bip32_derivs"]
    assert deriv["pubkey"] == signer("alice").get_pubkey(0, 0).hex()
    assert signer("alice").as_signer(repaired["psbt"]).path_mismatch() == ""
    assert_not_finalized(coordinator.backend, repaired["psbt"])
    assert_next_role(coordinator.backend, repaired["psbt"], "signer")
    assert_mempool_rejects(
        coordinator.backend, rawtx_from_psbt(repaired["psbt"]), rejectreason=NO_WITNESS
    )
    state["no_change_psbt"] = repaired["psbt"]


def test_010_no_change_fee(
    coordinator, signer, state, compact_text, to_formatted_btc, to_sats
):
    # createpsbt adds no change output, so everything above the payment is fee.
    fee_sats = FUNDING_SATS - PAYMENT_SATS
    krux = signer("alice").as_signer(state["no_change_psbt"])

    # Krux shows that fee and reports 50%, above the 10% of its high-fee warning.
    messages, fee_percent = krux.outputs()
    assert list(map(compact_text, messages)) == [
        f"Inputs(1):{to_formatted_btc(FUNDING_SATS)}"
        f"Spend(1):{to_formatted_btc(PAYMENT_SATS)}"
        # 110 vB: one P2WPKH input and one P2WPKH output
        f"Fee:{to_formatted_btc(fee_sats)}(50.0%)~{fee_sats / 110:.1f}sat/vB",
        f"1.Spend:{state['recipient']}{to_formatted_btc(PAYMENT_SATS)}",
    ]
    assert fee_percent == 50.0

    # Core finalizes it and only refuses the fee rate (a wallet safety limit
    # with maxfeerate)
    krux.sign()
    exported, _ = krux.psbt_qr()
    hextx = assert_finalized(coordinator.backend, exported)
    assert_mempool_rejects(
        coordinator.backend, hextx, rejectreason=r"^max-fee-exceeded$"
    )
    (accepted,) = coordinator.backend.client.call("testmempoolaccept", [hextx], 0)
    assert accepted["allowed"] is True
    assert accepted["vsize"] == 110
    assert to_sats(accepted["fees"]["base"]) == fee_sats


def test_011_witness_utxo_only(coordinator, signer, state, to_sats):
    # BIP143 commits to the amount of the input being signed, so with a single
    # input the previous transaction is optional. K
    copied = PSBT.from_string(state["psbt"])
    (inp,) = copied.inputs
    assert inp.witness_utxo is not None
    inp.non_witness_utxo = None

    exported = signer("alice").sign_psbt(copied)
    accepted = assert_mempool_accepts(
        coordinator.backend, assert_finalized(coordinator.backend, exported)
    )
    assert to_sats(accepted["fees"]["base"]) == state["fee_sats"]


def test_012_fake_prev_tx(coordinator, signer, state):
    # A previous transaction that pays half the real amount no longer hashes
    # to the outpoint being spent.
    copied = PSBT.from_string(state["psbt"])
    (inp,) = copied.inputs
    fake_prev = Transaction.parse(inp.non_witness_utxo.serialize())
    fake_prev.vout[inp.vout].value //= 2
    inp.non_witness_utxo = fake_prev

    with pytest.raises(ValueError, match="Invalid PSBT: Previous txid doesn't match"):
        signer("alice").as_signer(copied)
    with pytest.raises(
        ClientError, match="Non-witness UTXO does not match outpoint hash"
    ):
        coordinator.backend.client.decode_psbt(copied.to_string())


@pytest.mark.parametrize("delta", [-1, 1])
def test_013_fake_input_amount(
    coordinator, signer, state, compact_text, to_full_summary, delta
):
    # The coordinator lies about the amount being spent, by one satoshi.
    copied = PSBT.from_string(state["psbt"])
    (inp,) = copied.inputs
    inp.witness_utxo.value += delta

    # 1) With the previous transaction attached Krux catches the lie.
    with pytest.raises(
        ValueError, match="Invalid PSBT: Witness utxo doesn't match non_witness_utxo"
    ):
        signer("alice").as_signer(copied)

    # 2) Without it there is nothing to compare against: Krux reviews and signs
    # the declared amount.
    inp.non_witness_utxo = None
    krux = signer("alice").as_signer(copied)
    messages, _ = krux.outputs()
    assert compact_text(messages[0]) == to_full_summary(
        FUNDING_SATS + delta, PAYMENT_SATS, state["change_sats"], "0.1"
    )
    krux.sign()
    exported, _ = krux.psbt_qr()

    # 3) Core finalizes against the same declared amount, but the signature
    # commits to it (BIP143) and the real UTXO makes it invalid.
    hextx = assert_finalized(coordinator.backend, exported)
    assert_mempool_rejects(coordinator.backend, hextx, rejectreason=BAD_SIGNATURE)


def test_014_outputs_exceed_inputs(coordinator, signer, state, rawtx_from_psbt, to_btc):
    alice = coordinator.get_wallet("alice").backend.client
    with pytest.raises(ClientError, match="Insufficient funds"):
        alice.wallet_create_funded_psbt(
            [],
            [{state["recipient"]: to_btc(FUNDING_SATS + PAYMENT_SATS)}],
            0,
            {"change_type": "bech32", "fee_rate": 1},
        )

    # Krux refuses to even build the signer.
    copied = PSBT.from_string(state["psbt"])
    (payment,) = [out for out in copied.outputs if out.value == PAYMENT_SATS]
    payment.value = FUNDING_SATS + 1
    with pytest.raises(ValueError, match="Invalid PSBT: outputs exceed inputs"):
        signer("alice").as_signer(copied)

    # Core computes the negative fee and consensus rejects the transaction.
    tampered = copied.to_string()
    assert coordinator.backend.client.analyze_psbt(tampered)["fee"] < 0
    assert_not_finalized(coordinator.backend, tampered)
    assert_next_role(coordinator.backend, tampered, "signer")
    assert_mempool_rejects(
        coordinator.backend,
        rawtx_from_psbt(tampered),
        rejectreason=r"^bad-txns-in-belowout$",
    )


@pytest.mark.parametrize(
    "sighash, flag",
    [("NONE", 0x02), ("SINGLE", 0x03), ("ALL|ANYONECANPAY", 0x81)],
)
def test_015_sighash(
    coordinator, signer, state, rawtx_from_psbt, core_version, sighash, flag
):
    alice = coordinator.get_wallet("alice").backend.client
    # Core 29 does not add the requested sighash when sign=False.
    # Put it in the PSBT explicitly so all versions review the same input.
    modified = PSBT.from_string(state["psbt"])
    modified.inputs[0].sighash_type = flag
    processed = alice.wallet_process_psbt(modified.to_string(), False, sighash)
    assert processed["complete"] is False
    (inp,) = coordinator.backend.client.decode_psbt(processed["psbt"])["inputs"]
    assert inp["sighash"] == sighash

    # Krux builds the signer, but refuses to sign.
    krux = signer("alice").as_signer(processed["psbt"])
    with pytest.raises(
        ValueError, match=f"Input 0 has non-standard sighash type: 0x{flag:02x}"
    ):
        krux.sign()

    # Core 29 reports these unsigned inputs as signer-ready; 30+ reports updater.
    next_role = "signer" if core_version < 300000 else "updater"
    unsigned = krux.psbt.to_string()
    assert_not_finalized(coordinator.backend, unsigned)
    assert_next_role(coordinator.backend, unsigned, next_role)
    assert_mempool_rejects(
        coordinator.backend, rawtx_from_psbt(unsigned), rejectreason=NO_WITNESS
    )


def test_016_sign_export(coordinator, signer, state, to_sats, unsigned_tx):
    krux = signer("alice").as_signer(state["psbt"])
    assert krux.path_mismatch() == ""
    krux.sign()
    exported, qr_format = krux.psbt_qr()
    assert qr_format == FORMAT_NONE
    decoded = coordinator.backend.client.decode_psbt(exported)
    (inp,) = decoded["inputs"]
    assert list(inp["partial_signatures"]) == [signer("alice").get_pubkey(0, 0).hex()]
    assert decoded["psbt_version"] == state["psbt_version"]
    assert unsigned_tx(decoded) == state["unsigned_tx"]
    assert to_sats(decoded["fee"]) == state["fee_sats"]
    state["exported"] = exported


@pytest.mark.core_version(since="32.0")
def test_016_psbt_v2_signer(coordinator, signer, state):
    flags = ("inputs_modifiable", "outputs_modifiable", "has_sighash_single")
    psbt = PSBT.from_string(state["psbt"])
    psbt.set_tx_modifiable(0b011)
    decoded = coordinator.backend.client.decode_psbt(psbt.to_string())
    assert [decoded[flag] for flag in flags] == [True, True, False]

    krux = signer("alice").as_signer(psbt)
    krux.sign()
    exported, _ = krux.psbt_qr()
    decoded = coordinator.backend.client.decode_psbt(exported)
    assert [decoded[flag] for flag in flags] == [False, False, False]


@pytest.mark.core_version(since="32.0")
def test_016_psbt_v0_on_core_32(coordinator, signer, state, to_btc):
    alice = coordinator.get_wallet("alice")
    psbt = alice.funded_psbt_v0(
        [{"txid": state["utxo"]["txid"], "vout": state["utxo"]["vout"]}],
        [{state["recipient"]: to_btc(PAYMENT_SATS)}],
        {"change_type": "bech32", "fee_rate": 1},
    )
    exported = signer("alice").sign_psbt(psbt)
    signed = alice.decode_psbt(exported)
    assert (signed["psbt_version"], signed["tx"]) == (0, alice.decode_psbt(psbt)["tx"])
    assert list(signed["inputs"][0]["partial_signatures"]) == [
        signer("alice").get_pubkey(0, 0).hex()
    ]
    assert_mempool_accepts(alice.backend, assert_finalized(alice.backend, exported))


def test_017_core_accepts(coordinator, state, to_sats):
    # finalizepsbt has no signing capability: only Krux supplied signatures.
    hextx = assert_finalized(coordinator.backend, state["exported"])
    accepted = assert_mempool_accepts(coordinator.backend, hextx)
    assert to_sats(accepted["fees"]["base"]) == state["fee_sats"]

    # A one-satoshi output change breaks the signature even with a higher fee.
    tampered = Transaction.parse(bytes.fromhex(hextx))
    tampered.vout[0].value -= 1
    assert_mempool_rejects(
        coordinator.backend, tampered.serialize().hex(), rejectreason=BAD_SIGNATURE
    )
    state["signed_hex"] = hextx
    state["txid"] = accepted["txid"]


def test_018_broadcast_confirm(core, coordinator, state, to_sats):
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
    psbt = alice.wallet_process_psbt(psbt, sign=False)["psbt"]
    return {
        "psbt": psbt,
        "decoded": alice.decode_psbt(psbt),
        "input_sats": input_sats,
        "output_sats": output_sats,
        "payment_sats": output_sats - 10_000,
        "change_sats": 10_000,
        "fee_sats": fee_sats,
        "percent": expected,
        "recipient": recipient,
        "change": change,
        "change_path": alice.account_path(change),
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
def test_019_review_fee_rounding(
    signer,
    review_case,
    to_sats,
    compact_text,
    to_full_summary,
    to_formatted_btc,
    unsigned_tx,
):
    case = review_case
    decoded = case["decoded"]
    assert to_sats(decoded["fee"]) == case["fee_sats"]
    assert (
        sum(to_sats(out["value"]) for out in unsigned_tx(decoded)["vout"])
        == case["output_sats"]
    )
    # Only the displayed summary is asserted.
    # Krux's second result is for the high-fee warning.
    messages, _ = signer("alice").as_signer(case["psbt"]).outputs()
    assert list(map(compact_text, messages)) == [
        to_full_summary(
            case["input_sats"],
            case["payment_sats"],
            case["change_sats"],
            case["percent"],
        ),
        f"1.Spend:{case['recipient']}{to_formatted_btc(case['payment_sats'])}",
        f"1.Change:{case['change_path']}{case['change']}"
        f"{to_formatted_btc(case['change_sats'])}",
    ]
