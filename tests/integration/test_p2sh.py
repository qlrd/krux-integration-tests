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


"""Legacy P2SH round trip using the shared Trezor mnemonics.

Run the whole module: the numbered tests share a regtest transaction.
"""

from pytest import fixture, raises

from bornal.client import ClientError
from bornal.testing import (
    COINBASE_MATURITY,
    assert_finalized,
    assert_mempool_accepts,
    assert_not_finalized,
    connect_p2p,
    generate_to_address,
    get_new_address,
    sync_blocks,
)
from embit.networks import NETWORKS
from embit.psbt import PSBT
from embit.script import address_to_scriptpubkey

from krux.key import P2SH
from krux.qr import FORMAT_NONE

FUNDING_SATS = 150_000_000
PAYMENT_SATS = 100_000_000


@fixture(scope="module")
def script_type():
    """Select the legacy multisig lab."""
    return P2SH


def test_000_watch_only(coordinator, state):
    alice = coordinator.get_wallet("alice").backend.client
    assert alice.get_wallet_info()["private_keys_enabled"] is False
    state["receive"] = alice.get_new_address("funding", "legacy")


def test_001_alice_receive(signer, state):
    wallet = signer("alice").wallet
    assert wallet.key.derivation == "m/45h"
    assert state["receive"] == next(wallet.obtain_addresses())


def test_002_bob_receive(signer, state):
    wallet = signer("bob").wallet
    assert wallet.key.derivation == "m/45h"
    assert state["receive"] == next(wallet.obtain_addresses())


def test_003_fund(core, coordinator, state, to_btc, to_sats):
    connect_p2p(core, coordinator.backend)
    mining = get_new_address(core, "mining")
    generate_to_address(core, mining, COINBASE_MATURITY + 1)
    sync_blocks(core, coordinator.backend)
    txid = core.client.call("sendtoaddress", state["receive"], to_btc(FUNDING_SATS))
    generate_to_address(core, mining, 1)
    sync_blocks(core, coordinator.backend)
    alice = coordinator.get_wallet("alice").backend.client
    (utxo,) = [u for u in alice.list_unspent() if u["txid"] == txid]
    assert to_sats(utxo["amount"]) == FUNDING_SATS
    state.update(utxo=utxo, mining=mining)


def test_004_create_psbt(core, coordinator, state, to_btc):
    alice = coordinator.get_wallet("alice").backend.client
    recipient = get_new_address(core, "recipient", "legacy")
    utxo = state["utxo"]
    funded = alice.wallet_create_funded_psbt(
        inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}],
        outputs=[{recipient: to_btc(PAYMENT_SATS)}],
        options={"change_type": "legacy", "fee_rate": 1},
    )
    unsigned = PSBT.from_string(funded["psbt"])
    (entry,) = unsigned.inputs
    assert entry.non_witness_utxo is not None
    assert entry.witness_utxo is None
    assert entry.redeem_script is not None
    assert not entry.partial_sigs
    state.update(unsigned=unsigned, funded=funded, recipient=recipient)


def test_005_check_outputs(state, to_sats):
    funded = state["funded"]
    changepos = funded["changepos"]
    assert changepos in (0, 1)
    outputs = state["unsigned"].tx.vout
    assert len(outputs) == 2
    change = outputs[changepos]
    payment = outputs[1 - changepos]
    assert payment.script_pubkey.address(NETWORKS["regtest"]) == state["recipient"]
    assert payment.value == PAYMENT_SATS
    fee_sats = FUNDING_SATS - sum(out.value for out in outputs)
    assert fee_sats == to_sats(funded["fee"])
    state.update(
        change=change.script_pubkey.address(NETWORKS["regtest"]),
        change_sats=change.value,
        fee_sats=fee_sats,
    )


def test_006_alice_review(signer, state, compact_text, to_formatted_btc):
    assert state["change"] == next(
        signer("alice").wallet.obtain_addresses(branch_index=1)
    )
    messages, _ = signer("alice").as_signer(state["unsigned"]).outputs()
    # 10 header bytes, a 260-byte 2-of-2 input, and 34/32-byte outputs.
    assert list(map(compact_text, messages)) == [
        f"Inputs(1):{to_formatted_btc(FUNDING_SATS)}"
        f"Spend(1):{to_formatted_btc(PAYMENT_SATS)}"
        f"Self-transferorChange(1):{to_formatted_btc(state['change_sats'])}"
        f"Fee:{to_formatted_btc(state['fee_sats'])}(0.1%)"
        f"~{state['fee_sats'] / 336:.1f}sat/vB",
        f"1.Spend:{state['recipient']}{to_formatted_btc(PAYMENT_SATS)}",
        f"1.Change:1/0{state['change']}{to_formatted_btc(state['change_sats'])}",
    ]


def test_007_unsigned_control(coordinator, state):
    assert_not_finalized(coordinator.backend, state["unsigned"].to_string())


def test_008_sign_alice(signer, state):
    alice = signer("alice")
    krux = alice.as_signer(state["unsigned"])
    assert krux.policy == alice.wallet.policy
    assert krux.policy["type"] == P2SH
    krux.sign()
    exported, fmt = krux.psbt_qr()
    assert fmt == FORMAT_NONE
    partial = PSBT.from_string(exported)
    assert partial.tx.serialize() == state["unsigned"].tx.serialize()
    assert {pub.sec() for pub in partial.inputs[0].partial_sigs} == {
        alice.get_pubkey(0, 0)
    }
    state["alice_partial"] = exported


def test_009_combine_alice(coordinator, signer, state):
    combined = coordinator.backend.client.call(
        "combinepsbt", [state["unsigned"].to_string(), state["alice_partial"]]
    )
    partial = PSBT.from_string(combined)
    assert partial.tx.serialize() == state["unsigned"].tx.serialize()
    assert {pub.sec() for pub in partial.inputs[0].partial_sigs} == {
        signer("alice").get_pubkey(0, 0)
    }
    assert_not_finalized(coordinator.backend, combined)
    state["combined"] = combined


def test_010_bob_review(signer, state, compact_text, to_formatted_btc):
    assert state["change"] == next(
        signer("bob").wallet.obtain_addresses(branch_index=1)
    )
    messages, _ = signer("bob").as_signer(state["combined"]).outputs()
    assert list(map(compact_text, messages)) == [
        f"Inputs(1):{to_formatted_btc(FUNDING_SATS)}"
        f"Spend(1):{to_formatted_btc(PAYMENT_SATS)}"
        f"Self-transferorChange(1):{to_formatted_btc(state['change_sats'])}"
        f"Fee:{to_formatted_btc(state['fee_sats'])}(0.1%)"
        f"~{state['fee_sats'] / 336:.1f}sat/vB",
        f"1.Spend:{state['recipient']}{to_formatted_btc(PAYMENT_SATS)}",
        f"1.Change:1/0{state['change']}{to_formatted_btc(state['change_sats'])}",
    ]


def test_011_tampered_recipient(
    core, coordinator, signer, state, compact_text, to_formatted_btc
):
    tampered = PSBT.from_string(state["combined"])
    replacement = get_new_address(core, "swapped-recipient", "legacy")
    payment_index = 1 - state["funded"]["changepos"]
    tampered.outputs[payment_index].script_pubkey = address_to_scriptpubkey(replacement)
    krux = signer("bob").as_signer(tampered)
    messages, _ = krux.outputs()
    assert (
        compact_text(messages[1])
        == f"1.Spend:{replacement}{to_formatted_btc(PAYMENT_SATS)}"
    )
    assert state["recipient"] not in "".join(map(compact_text, messages))
    krux.sign()
    exported, fmt = krux.psbt_qr()
    assert fmt == FORMAT_NONE
    assert {pub.sec() for pub in PSBT.from_string(exported).inputs[0].partial_sigs} == {
        signer("alice").get_pubkey(0, 0),
        signer("bob").get_pubkey(0, 0),
    }
    with raises(ClientError, match="different transactions"):
        coordinator.backend.client.call("combinepsbt", [state["combined"], exported])
    # Both signatures are present, but Alice's no longer commits to these outputs.
    assert_not_finalized(coordinator.backend, exported)


def test_012_sign_bob(signer, state):
    bob = signer("bob")
    krux = bob.as_signer(state["combined"])
    assert krux.policy == bob.wallet.policy
    assert krux.policy["type"] == P2SH
    krux.sign()
    exported, fmt = krux.psbt_qr()
    assert fmt == FORMAT_NONE
    partial = PSBT.from_string(exported)
    assert partial.tx.serialize() == state["unsigned"].tx.serialize()
    assert {pub.sec() for pub in partial.inputs[0].partial_sigs} == {
        signer("alice").get_pubkey(0, 0),
        bob.get_pubkey(0, 0),
    }
    alice_signature = PSBT.from_string(state["combined"]).inputs[0].partial_sigs
    assert all(
        partial.inputs[0].partial_sigs[pub] == sig
        for pub, sig in alice_signature.items()
    )
    state["bob_partial"] = exported


def test_013_finalize(coordinator, state):
    state["hextx"] = assert_finalized(coordinator.backend, state["bob_partial"])


def test_014_broadcast_confirm(core, coordinator, state):
    hextx = state["hextx"]
    accepted = assert_mempool_accepts(coordinator.backend, hextx)
    txid = coordinator.backend.client.send_raw_transaction(hextx)
    assert txid == accepted["txid"]
    sync_blocks(core, coordinator.backend)
    block = generate_to_address(coordinator.backend, state["mining"], 1)[0]
    assert txid in coordinator.backend.client.call("getblock", block)["tx"]
