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
test_p2pkh.py

    summary:
        Model a basic interaction between krux and bitcoin-core. 2 bitcoin nodes
        are used: ``core`` (hot ``bornal-wallet``: mines and funds) and
        ``watchonly`` (Krux's ``tpub`` descriptor, no private keys). bornal's
        module-scoped ``integration_test`` keeps both up until the module's
        last test, so the tests are small, ordered by name and hand data to
        the next one through the ``state`` dict. Run the whole module, not a
        single test. Test should be small and auto-explainable most as
        possible.

    targets:
        - bitcoin-core on regtest.
        - krux.wallet module

    strategy:
        - uses the Trezor BIP-39 vectors as ``alice`` (abandon) and ``bob`` (zoo)
        - load each ``tpub`` descriptor into its own watch-only wallet on one node
        - create a core wallet to send coins to krux
        - krux should be able to inspect coins
        - create an unsigned tx (psbt) with core, from ``alice`` to bornal's
          ``UNSPENDABLE_ADDRESS``, and keep it in temporary memory
        - negative tests: wrong purpose, wrong network, wrong policy (not
          broadcastable, rejectable)
        - malformed and malicious psbt: with or without fabricated tx or
          non-standard sighashes, outputs above inputs
        - krux signs the valid psbt; core finalizes and broadcasts it
        - the ``core`` node sees the krux tx in a block

Build the daemon and run this test with the bornal's ``pytest`` plugin::

    pytest --build-bitcoin latest --wallet tests/integration/test_p2pkh.py
"""

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

from krux.qr import FORMAT_NONE
from krux.key import (
    P2PKH,
    P2WPKH,
    P2SH,
    P2SH_P2WSH,
    P2WSH,
    P2TR,
    TYPE_SINGLESIG,
    TYPE_MULTISIG,
    TYPE_MINISCRIPT,
)

ALICE = "alice"
BOB = "bob"
FUNDING = 1.5
PAYMENT = 1.0
MISMATCHED = [
    (NETWORKS["regtest"], P2WPKH),  # right net, wrong purpose: 84h
    (NETWORKS["regtest"], P2TR),  # right net, wrong purpose: 86h
    (NETWORKS["main"], P2PKH),  # wrong net, right purpose: 0h
]


def unsigned_hex(psbt: str) -> str:
    """Raw hex of the transaction ``psbt`` carries, signatures left out"""
    return PSBT.from_string(psbt).tx.serialize().hex()


def test_000_start(core, coordinator):
    assert_chain(core, "regtest")
    assert_chain(coordinator.backend, "regtest")
    assert_block_count(core, 0)
    assert_block_count(coordinator.backend, 0)


def test_001_init_network(core, coordinator):
    connect_p2p(core, coordinator.backend)
    assert core.client.get_connection_count() == 1
    assert coordinator.backend.client.get_connection_count() == 1
    assert_block_count(core, 0)
    assert_block_count(coordinator.backend, 0)


def test_002_hot_wallet(core):
    assert_wallet_info(core, "bornal-wallet")
    assert core.client.get_balance() == 0


def test_003_watchonly_wallet(coordinator):
    # both airgap wallets were imported by ``BaseTest.run_test``
    assert coordinator.wallets == [ALICE, BOB]
    assert sorted(coordinator.backend.client.list_wallets()) == [ALICE, BOB]


def test_004_check_wallet_core(coordinator):
    alice = coordinator.get_wallet(ALICE)
    assert_wallet_info(alice.backend, ALICE, watchonly=True)
    info = alice.backend.client.get_wallet_info()
    assert info["descriptors"] is True
    assert info["private_keys_enabled"] is False
    assert alice.backend.client.get_balance() == 0


def test_005_check_bob(coordinator):
    bob = coordinator.get_wallet(BOB)
    assert_wallet_info(bob.backend, BOB, watchonly=True)
    info = bob.backend.client.get_wallet_info()
    assert info["descriptors"] is True
    assert info["private_keys_enabled"] is False
    assert bob.backend.client.get_balance() == 0


def test_006_mine(core, coordinator):
    address = get_new_address(core, "coinbase", "legacy")
    generate_to_address(core, address, COINBASE_MATURITY + 1)
    sync_blocks(core, coordinator.backend)

    assert_block_count(core, COINBASE_MATURITY + 1)
    assert_block_count(coordinator.backend, COINBASE_MATURITY + 1)
    assert core.client.get_balance() >= BASE_COINBASE_SUBSIDY
    for name in coordinator.wallets:
        assert coordinator.get_wallet(name).backend.client.get_balance() == 0


def test_007_receive_address_first(coordinator, signer):
    for name in coordinator.wallets:
        core_addr = coordinator.get_wallet(name).backend.client.get_new_address(
            "", "legacy"
        )
        krux_addr = next(signer(name).wallet.obtain_addresses())
        assert core_addr == krux_addr


def test_008_change_addresses(coordinator, signer):
    for name in coordinator.wallets:
        wallet = coordinator.get_wallet(name)
        airgap = signer(name)
        (internal,) = [
            d
            for d in wallet.backend.client.call("listdescriptors")["descriptors"]
            if d["internal"]
        ]
        assert internal["active"] is True
        assert internal["next"] == 0

        core_addrs = wallet.backend.client.call(
            "deriveaddresses", internal["desc"], [0, 9]
        )
        krux_addrs = [
            next(airgap.wallet.obtain_addresses(i=i, branch_index=1)) for i in range(10)
        ]
        assert core_addrs == krux_addrs

        derivation = airgap.wallet.key.derivation
        for i, addr in enumerate(krux_addrs):
            info = wallet.backend.client.get_address_info(addr)
            assert info["ismine"] is True
            assert info["ischange"] is True
            assert info["hdkeypath"].replace("'", "h") == derivation + f"/1/{i}"


def test_009_send_to_alice(core, coordinator, signer, state):
    alice = coordinator.get_wallet(ALICE)
    addr = alice.backend.client.get_new_address("", "legacy")
    assert addr == next(signer("alice").wallet.obtain_addresses(i=1))

    txid = core.client.call("sendtoaddress", addr, FUNDING)
    assert txid in core.client.get_raw_mempool()
    assert alice.backend.client.get_balance() == 0

    state["address"] = addr
    state["txid"] = txid


def test_010_confirm(core, coordinator, state):
    generate_to_address(core, UNSPENDABLE_ADDRESS, 1)
    sync_blocks(core, coordinator.backend)
    assert_block_count(core, COINBASE_MATURITY + 2)
    assert_block_count(coordinator.backend, COINBASE_MATURITY + 2)
    assert core.client.get_raw_mempool() == []

    alice = coordinator.get_wallet(ALICE)
    assert alice.backend.client.get_transaction(state["txid"])["confirmations"] == 1
    assert coordinator.get_wallet(BOB).backend.client.get_balance() == 0


def test_011_balance(coordinator, state):
    alice = coordinator.get_wallet(ALICE)
    addr, txid = state["address"], state["txid"]

    assert alice.backend.client.get_balance() == FUNDING
    assert alice.backend.client.get_received_by_address(addr) == FUNDING
    unspent = alice.backend.client.list_unspent()
    assert [
        (u["txid"], u["address"], u["amount"], u["confirmations"]) for u in unspent
    ] == [(txid, addr, FUNDING, 1)]


def test_012_create_unsigned_psbt(coordinator, state):
    alice = coordinator.get_wallet(ALICE)
    res = alice.backend.client.wallet_create_funded_psbt(
        [],
        [{UNSPENDABLE_ADDRESS: PAYMENT}],
        0,
        {"change_type": "legacy", "fee_rate": 1},
    )
    assert 0 < res["fee"] < 0.0001
    assert res["changepos"] != -1

    state["psbt"] = res["psbt"]
    state["changepos"] = res["changepos"]
    state["fee"] = res["fee"]


def test_013_check_spends_utxo(coordinator, state):
    decoded = coordinator.backend.client.decode_psbt(state["psbt"])

    (utxo,) = coordinator.get_wallet(ALICE).backend.client.list_unspent()
    (vin,) = decoded["tx"]["vin"]
    assert (vin["txid"], vin["vout"]) == (utxo["txid"], utxo["vout"])

    (inp,) = decoded["inputs"]
    prevout = inp["non_witness_utxo"]["vout"][utxo["vout"]]
    assert inp["non_witness_utxo"]["txid"] == state["txid"]
    assert prevout["value"] == FUNDING
    assert prevout["scriptPubKey"]["address"] == state["address"]


def test_014_psbt_change_address(coordinator, signer, state):
    alice = signer("alice")
    decoded = coordinator.backend.client.decode_psbt(state["psbt"])

    changepos = state["changepos"]
    core_change = decoded["tx"]["vout"][changepos]["scriptPubKey"]["address"]
    krux_change = next(alice.wallet.obtain_addresses(branch_index=1))
    assert core_change == krux_change

    info = coordinator.get_wallet(ALICE).backend.client.get_address_info(core_change)
    hdkeypath = info["hdkeypath"].replace("'", "h")
    assert info["ismine"] is True
    assert info["ischange"] is True
    assert hdkeypath == alice.wallet.key.derivation + "/1/0"

    state["change"] = core_change


def test_015_psbt_outputs(coordinator, state):
    decoded = coordinator.backend.client.decode_psbt(state["psbt"])

    outs = {o["scriptPubKey"]["address"]: o["value"] for o in decoded["tx"]["vout"]}
    assert set(outs) == {UNSPENDABLE_ADDRESS, state["change"]}
    assert outs[UNSPENDABLE_ADDRESS] == PAYMENT
    assert round(sum(outs.values()) + state["fee"], 8) == FUNDING


def test_016_psbt_input_derivation(coordinator, signer, state):
    alice = signer("alice")
    key = alice.wallet.key
    decoded = coordinator.backend.client.decode_psbt(state["psbt"])

    (inp,) = decoded["inputs"]
    (deriv,) = inp["bip32_derivs"]
    assert deriv["pubkey"] == alice.get_pubkey(0, 1).hex()
    assert deriv["master_fingerprint"] == key.fingerprint_hex_str()
    assert deriv["path"].replace("'", "h") == key.derivation + "/0/1"


def test_017_psbt_unsigned(coordinator, signer, state):
    alice = signer("alice")
    psbt = state["psbt"]

    (inp,) = coordinator.backend.client.decode_psbt(psbt)["inputs"]
    assert "partial_signatures" not in inp
    assert "final_scriptSig" not in inp

    pkh = hash160(alice.get_pubkey(0, 1)).hex()
    analysis = coordinator.backend.client.analyze_psbt(psbt)
    assert analysis["next"] == "signer"
    for inp_analysis in analysis["inputs"]:
        assert inp_analysis["has_utxo"]
        assert not inp_analysis["is_final"]
        assert inp_analysis["next"] == "signer"
        assert inp_analysis["missing"] == {"signatures": [pkh]}

    assert_not_finalized(coordinator.backend, psbt)
    assert_next_role(coordinator.backend, psbt, "signer")
    assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(psbt))


def test_018_psbt_wrong_signer(coordinator, signer, state):
    signer_krux = signer("bob").as_signer(state["psbt"])

    assert signer_krux.path_mismatch() == ""
    with raises(ValueError, match="cannot sign"):
        signer_krux.sign()

    unsigned = signer_krux.psbt.to_string()
    assert_not_finalized(coordinator.backend, unsigned)
    assert_next_role(coordinator.backend, unsigned, "signer")
    assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(unsigned))


def test_019_psbt_invalid(coordinator, signer):
    rawtx = coordinator.backend.client.create_raw_transaction(
        [], [{UNSPENDABLE_ADDRESS: 1}]
    )

    with raises(ValueError, match="invalid PSBT"):
        signer("alice").as_signer(rawtx)

    with raises(ClientError, match="TX decode failed"):
        coordinator.backend.client.finalize_psbt(rawtx)


def test_020_psbt_mismatch(coordinator, signer, state):
    alice = signer("alice")
    psbt = state["psbt"]
    assert alice.as_signer(psbt).path_mismatch() == ""

    for net, purpose in MISMATCHED:
        tmpsigner = alice.as_variant(TYPE_SINGLESIG, net, purpose).as_signer(psbt)
        assert tmpsigner.path_mismatch() == "m/44h/1h/0h"

        # Mimic the behaviour where a user declines "Proceed?" on the warning,
        # so Krux signs nothing, and user try to broadcast eitherway
        # the mismatch is a UX warning from core
        unsigned = tmpsigner.psbt.to_string()
        assert_not_finalized(coordinator.backend, unsigned)
        assert_next_role(coordinator.backend, unsigned, "signer")
        assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(unsigned))


def test_021_psbt_wrong_policy(coordinator, signer, state):
    alice = signer("alice")
    psbt = state["psbt"]
    cases = [
        (TYPE_MULTISIG, P2SH, "Not a multisig PSBT"),
        (TYPE_MULTISIG, P2SH_P2WSH, "Not a multisig PSBT"),
        (TYPE_MULTISIG, P2WSH, "Not a multisig PSBT"),
        (TYPE_MINISCRIPT, P2WSH, "Not a miniscript PSBT"),
        (TYPE_MINISCRIPT, P2TR, "Not a miniscript PSBT"),
    ]

    for policy, purpose, err in cases:
        variant = alice.as_variant(policy, NETWORKS["regtest"], purpose)
        with raises(ValueError, match=f"Invalid PSBT: {err}"):
            variant.as_signer(psbt)

    assert_not_finalized(coordinator.backend, psbt)
    assert_next_role(coordinator.backend, psbt, "signer")
    assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(psbt))


def test_022_psbt_mismatch_sign(coordinator, signer, state):
    # A path mismatch is a UX warning only. Krux signs and the same seed produces
    # a valid signature that Core accepts.
    alice = signer("alice")

    for net, purpose in MISMATCHED:
        tmpsigner = alice.as_variant(TYPE_SINGLESIG, net, purpose).as_signer(
            state["psbt"]
        )
        assert tmpsigner.path_mismatch() == "m/44h/1h/0h"

        # Mimic the user tapping "Proceed?" on the warning at a krux device
        tmpsigner.sign()
        signed, fmt = tmpsigner.psbt_qr()
        assert fmt == FORMAT_NONE

        # It isn't recommended to do `sendrawtransaction` as pedagogical approach;
        # instead, we call `finalizepsbt` and `testmempoolaccept` as a dry
        # run and never broadcast.
        hextx = assert_finalized(coordinator.backend, signed)
        assert_mempool_accepts(coordinator.backend, hextx)


def test_023_psbt_rejects_without_prev_tx(coordinator, signer, state):
    alice = signer("alice")
    alice_wallet = coordinator.get_wallet(ALICE)
    err = "Invalid PSBT: missing non_witness_utxo on a legacy input"

    # 1) coordinator attaches no UTXO data at all
    (utxo,) = alice_wallet.backend.client.list_unspent()
    barepsbt = alice_wallet.backend.client.create_psbt(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [{UNSPENDABLE_ADDRESS: PAYMENT}],
    )
    with raises(ValueError, match=err):
        alice.as_signer(barepsbt)

    (analysis,) = coordinator.backend.client.analyze_psbt(barepsbt)["inputs"]
    assert not analysis["has_utxo"]
    assert_not_finalized(coordinator.backend, barepsbt)
    assert_next_role(coordinator.backend, barepsbt, "updater")
    assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(barepsbt))

    # 2) only coordinator could repair the psbt
    updated = coordinator.backend.client.call("utxoupdatepsbt", barepsbt)
    (inp,) = coordinator.backend.client.decode_psbt(updated)["inputs"]
    assert "non_witness_utxo" not in inp

    repaired = alice_wallet.backend.client.wallet_process_psbt(updated, False)
    (inp,) = coordinator.backend.client.decode_psbt(repaired["psbt"])["inputs"]
    assert not repaired["complete"]
    assert "non_witness_utxo" in inp
    assert alice.as_signer(repaired["psbt"]).path_mismatch() == ""

    # 3) amount through witness_utxo instead of proving it with the previous tx
    # and krux will refuse and core will wanna updated psbt
    copied = PSBT.from_string(state["psbt"])
    (inp,) = copied.inputs
    inp.witness_utxo = inp.non_witness_utxo.vout[inp.vout]
    inp.non_witness_utxo = None
    with raises(ValueError, match=err):
        alice.as_signer(copied)
    declared = copied.to_string()
    analysis = coordinator.backend.client.analyze_psbt(declared)
    assert analysis["inputs"][0]["has_utxo"]
    assert analysis["fee"] == state["fee"]
    assert_not_finalized(coordinator.backend, declared)
    assert_next_role(coordinator.backend, declared, "updater")
    assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(declared))


def test_024_psbt_malicious_prev_tx(coordinator, signer, state):
    # supose that coordinator lies in the previous tx
    # (name, real val, malicious coordinator val)
    # this could happen:
    # | desc                | real chain | fake on real chain       |
    # | ------------------- | ---------- | ------------------------ |
    # | spent               | 1.5        | 1.00000235               |
    # | outputs             | 1.0        | 1.0                      |
    # | fee on krux display | 0.5        | 0.00000235               |

    # an attacker could consider that the signature is still valid on krux
    # (sighash never included amount). If faked, the aim is to half coins go to
    # miner and the device show nothing. Krux will refuse to even start the
    # signature procedure.
    copied = PSBT.from_string(state["psbt"])
    fake_prev = Transaction.parse(copied.inputs[0].non_witness_utxo.serialize())
    fake_prev.vout[copied.inputs[0].vout].value //= 2
    copied.inputs[0].non_witness_utxo = fake_prev
    with raises(ValueError, match="Invalid PSBT: Previous txid doesn't match"):
        signer("alice").as_signer(copied)

    # Core refuses to parse too
    with raises(ClientError, match="Non-witness UTXO does not match outpoint hash"):
        coordinator.backend.client.decode_psbt(copied.to_string())


def test_025_psbt_outputs_exceeds_inputs(coordinator, signer, state):
    # Try to spend more than what is capable
    with raises(ClientError, match="Insufficient funds"):
        coordinator.get_wallet(ALICE).backend.client.wallet_create_funded_psbt(
            [],
            [{UNSPENDABLE_ADDRESS: FUNDING + PAYMENT}],
            0,
            {"change_type": "legacy", "fee_rate": 1},
        )

    # modify the payment
    # krux should be able to refuse to even create signer
    copied = PSBT.from_string(state["psbt"])
    copied.outputs[1 - state["changepos"]].value = copied.inputs[0].utxo.value + 1
    with raises(ValueError, match="Invalid PSBT: outputs exceed inputs"):
        signer("alice").as_signer(copied)

    # Core also check the negative fee applied and will ask for signer to check again
    modified = copied.to_string()
    assert coordinator.backend.client.analyze_psbt(modified)["fee"] < 0
    assert_not_finalized(coordinator.backend, modified)
    assert_next_role(coordinator.backend, modified, "signer")
    assert_send_rawtx_rejects(
        coordinator.backend, unsigned_hex(modified), "bad-txns-in-belowout"
    )


def test_026_psbt_sighash(coordinator, signer, state):
    # similar to mitm above, change the sighash
    alice = signer("alice")
    alice_wallet = coordinator.get_wallet(ALICE)
    cases = [("NONE", "0x02"), ("SINGLE", "0x03"), ("ALL|ANYONECANPAY", "0x81")]

    # for each sighash, check in both krux and core the signs of malicious psbt
    for sighash, _hex in cases:
        req = alice_wallet.backend.client.wallet_process_psbt(
            state["psbt"], False, sighash
        )
        (inputs,) = coordinator.backend.client.decode_psbt(req["psbt"])["inputs"]
        assert not req["complete"]
        assert inputs["sighash"] == sighash

        # Krux will able to create the signer, but will refuse to sign
        _krux = alice.as_signer(req["psbt"])
        with raises(ValueError, match=f"Input 0 has non-standard sighash type: {_hex}"):
            _krux.sign()

        # Core does not see it as signer's work done yet
        unsigned = _krux.psbt.to_string()
        assert_not_finalized(coordinator.backend, unsigned)
        assert_next_role(coordinator.backend, unsigned, "updater")
        assert_send_rawtx_rejects(coordinator.backend, unsigned_hex(unsigned))


def test_027_psbt_sign(coordinator, signer, state):
    # Check if all well before sign
    alice_coord = coordinator.get_wallet(ALICE)
    psbt = state["psbt"]
    assert alice_coord.backend.client.analyze_psbt(psbt)["fee"] == state["fee"]
    assert_not_finalized(alice_coord.backend, psbt)
    assert_next_role(alice_coord.backend, psbt, "signer")

    # sign it
    alice = signer("alice")
    alice_signer = alice.as_signer(psbt)
    assert alice_signer.path_mismatch() == ""
    alice_signer.sign()

    # krux adds one signature from the key core asked for in test_017
    (inp,) = alice_signer.psbt.inputs
    assert [pub.sec() for pub in inp.partial_sigs] == [alice.get_pubkey(0, 1)]

    # check if was correctly signed (core shows "finalized")
    signed, fmt = alice_signer.psbt_qr()
    assert fmt == FORMAT_NONE
    assert_next_role(alice_coord.backend, signed, "finalizer")

    # check signed and if is acceptable by mempool
    hextx = assert_finalized(alice_coord.backend, signed)
    assert_mempool_accepts(alice_coord.backend, hextx)

    state["signed"] = hextx


def test_028_broadcast(core, coordinator, state):
    # Once signed say to coordinator to broadcast it
    # assert_send_rawtx_accepts try to send it and check for correct values
    alice = coordinator.get_wallet(ALICE)
    txid = assert_send_rawtx_accepts(alice.backend, state["signed"])
    assert alice.backend.client.get_raw_mempool() == [txid]
    assert alice.backend.client.get_transaction(txid)["confirmations"] == 0

    # Mine a little to be confirmed by regtest network
    (blockhash,) = generate_to_address(alice.backend, UNSPENDABLE_ADDRESS, 1)
    sync_blocks(alice.backend, core)
    assert_block_count(core, COINBASE_MATURITY + 3)
    assert_block_count(alice.backend, COINBASE_MATURITY + 3)
    assert txid in core.client.call("getblock", blockhash)["tx"]
    assert coordinator.backend.client.get_raw_mempool() == []

    # Check the fees on coordinator
    change = round(FUNDING - PAYMENT - state["fee"], 8)
    assert alice.backend.client.get_transaction(txid)["confirmations"] == 1
    assert alice.backend.client.get_balance() == change
    assert alice.backend.client.get_received_by_address(state["change"]) == change
