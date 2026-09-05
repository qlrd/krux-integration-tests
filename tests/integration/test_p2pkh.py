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
        Model a basic interaction betwenn krux and bitcoin-core. 2 bitcoin nodes
        will be used, one as krux coordinator and another to inspect krux
        signed txs.  The tests are are one and are chainable through a ordered
        names and each and with the same pair of nodes
        (``base_test("p2pkh", stop=False)``) that hands data to the next one.
        Only the last test passes ``stop=True``. Run the whole module,
        not a single test. Test should be small and auto-explainable most as
        possible.

    targets:
        - bitcoin-core on regtest.
        - krux.wallet module

    strategy:
        - uses ``*(["abandon"] * 11) + ["about"])`` mnemonic
        - load its ``tpub`` descriptor through ``importdescriptor`` in core
        - create a core wallet to send coins to krux
        - krux should be able to inspect coins
        - create an unsigned tx (psbt) with core, from ``krux-0`` to bornal's
          ``UNSPENDABLE_ADDRESS``, and keep it in temporary memory
        - negative tests: wrong purpose, wrong network, wrong policy (not
          broadcastable, rejectable)
        - malformed and malicious psbt: with or without fabricated tx or
          non-standard sighashes
    todo:
        - krux must sign valid psbt
        - core imports signed psbt and broadcast
        - another core node should see krux tx

Build the daemon and run this test with the bornal's ``pytest`` plugin::

    pytest --build-bitcoin latest --wallet tests/integration/test_p2pkh.py

SECURITY NOTE -- keep the Core side of the airgap wallet WATCH-ONLY.

``output_script_descriptor(wallet)`` defaults to ``watch_only=True`` and hands
Core a descriptor that carries only the ``tpub``. Passing ``watch_only=False``
swaps the ``tpub`` for the ``tprv`` (see ``tests/conftest.py::output_script_descriptor``),
i.e. it gives Core the private key. Do not do that here, for three reasons:

1. Logging. bornal's RPC client logs every call *with its parameters* at DEBUG
level (``bornal/client.py``: ``"$ rpc %s %s", method, params``), and pytest
captures that log. A ``tprv`` descriptor passed to ``importdescriptors`` would
land verbatim in the captured log, ``-o log_cli`` output and any CI artifact
that keeps it.

2. Persistence. Core writes imported keys to
``$INTEGRATION_TEMP_DIR/data/bitcoin-core<N>/regtest/wallets/`` and bornal
reuses those datadirs between runs, so the key would outlive the test on disk.

3. Fidelity. Krux is an air-gapped signer: Core must only ever see the public
descriptor and receive signatures through a PSBT round-trip. Letting Core hold
the ``tprv`` would let a test "pass" without Krux signing anything.

The ``krux`` wallet above is created with ``disable_private_keys=True``, so
Core itself refuses a private-key import ("Cannot import private keys to a wallet
with private keys disabled") -- keep that flag as a guard. All of this is tolerable
in a scratch test only because ``MNEMONIC`` is the public BIP-39 reference vector;
never combine ``watch_only=False`` with any other mnemonic.
"""

from pytest import raises
from bornal.client import ClientError
from bornal.plugins.bitcoind import UNSPENDABLE_ADDRESS
from bornal.testing import (
    BASE_COINBASE_SUBSIDY,
    COINBASE_MATURITY,
    assert_block_count,
    assert_chain,
    generate_to_address,
)
from embit.hashes import hash160
from embit.networks import NETWORKS
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

TAG = "p2pkh"
WALLET = f"{TAG}-krux-0"
FUNDING = 1.5
PAYMENT = 1.0
LOG = "(test_p2pkh::{}) {}"
MISMATCHED = [
    (NETWORKS["regtest"], P2WPKH),  # right net, wrong purpose: 84h
    (NETWORKS["regtest"], P2TR),  # right net, wrong purpose: 86h
    (NETWORKS["main"], P2PKH),  # wrong net, right purpose: 0h
]


def test_000_start(base_test, p2pkh_signers):
    test = base_test(TAG, stop=False)
    test.signers = p2pkh_signers
    for b in test.backends:
        assert_chain(b, "regtest")
        assert_block_count(b, 0)
    assert len(test.signers) == 2


def test_001_mine(base_test):
    test = base_test(TAG, stop=False)
    test.mine_blocks()
    assert_block_count(test.backends[0], COINBASE_MATURITY + 1)
    assert test.backends[0].client.call("getbalance") >= BASE_COINBASE_SUBSIDY

    # node 1 is not connected yet
    assert_block_count(test.backends[1], 0)


def test_002_connect(base_test):
    test = base_test(TAG, stop=False)
    test.connect_p2p(0, 1)
    for b in test.backends:
        assert len(b.client.call("getpeerinfo")) == 1
        assert_block_count(b, COINBASE_MATURITY + 1)


def test_003_create_watchonly_wallet(base_test):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    test.create_watchonly_wallet(test.backends[1], WALLET, test.signers[0][1])
    assert WALLET in rpc_krux("listwallets")
    info = rpc_krux("getwalletinfo")
    test.log.info(LOG.format("test_003_create_watchonly_wallet", info))
    assert info["walletname"] == WALLET
    assert info["descriptors"] is True
    assert info["private_keys_enabled"] is False
    assert rpc_krux("getbalance") == 0


def test_004_receive_address_first(base_test):
    test = base_test(TAG, stop=False)
    core_addr = test.backends[1].client.call("getnewaddress", "", "legacy")
    krux_addr = next(test.signers[0][0].obtain_addresses())
    test.log.info(
        LOG.format("test_004_receive_address", {"core": core_addr, "krux": krux_addr})
    )
    assert core_addr == krux_addr


def test_005_change_addresses(base_test):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    signer = test.signers[0][0]

    (internal,) = [
        d for d in rpc_krux("listdescriptors")["descriptors"] if d["internal"]
    ]
    test.log.info(LOG.format("test_005_change_address", internal))
    assert internal["active"] is True
    assert internal["next"] == 0

    core_addrs = rpc_krux("deriveaddresses", internal["desc"], [0, 9])
    krux_addrs = [next(signer.obtain_addresses(i=i, branch_index=1)) for i in range(10)]
    test.log.info(
        LOG.format("test_005_change_address", {"core": core_addrs, "krux": krux_addrs})
    )
    assert core_addrs == krux_addrs

    for i, addr in enumerate(krux_addrs):
        info = rpc_krux("getaddressinfo", addr)
        assert info["ismine"] is True
        assert info["ischange"] is True
        assert info["hdkeypath"].replace("'", "h") == signer.key.derivation + f"/1/{i}"


def test_006_send_to_watchonly(base_test):
    test = base_test(TAG, stop=False)
    rpc_core = test.backends[0].client.call
    rpc_krux = test.backends[1].client.call

    addr = rpc_krux("getnewaddress", "", "legacy")
    assert addr == next(test.signers[0][0].obtain_addresses(i=1))

    txid = rpc_core("sendtoaddress", addr, FUNDING)
    test.log.info(
        LOG.format(
            "test_006_send_to_watchonly",
            {"funding": FUNDING, "addr": addr, "txid": txid},
        )
    )
    assert txid in rpc_core("getrawmempool")
    assert rpc_krux("getbalance") == 0

    test.state["address"] = addr
    test.state["txid"] = txid


def test_007_confirm(base_test):
    test = base_test(TAG, stop=False)
    rpc_core = test.backends[0].client.call
    rpc_krux = test.backends[1].client.call

    generate_to_address(test.backends[0], 1)
    test.sync_blocks(0, 1)
    for b in test.backends:
        assert_block_count(b, COINBASE_MATURITY + 2)
    assert rpc_core("getrawmempool") == []
    assert rpc_krux("gettransaction", test.state["txid"])["confirmations"] == 1


def test_008_balance(base_test):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    addr, txid = test.state["address"], test.state["txid"]

    assert rpc_krux("getbalance") == FUNDING
    assert rpc_krux("getreceivedbyaddress", addr) == FUNDING
    unspent = rpc_krux("listunspent")
    test.log.info(LOG.format("test_008_balance", unspent))
    assert [
        (u["txid"], u["address"], u["amount"], u["confirmations"]) for u in unspent
    ] == [(txid, addr, FUNDING, 1)]


def test_009_create_unsigned_psbt(base_test):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call

    res = rpc_krux(
        "walletcreatefundedpsbt",
        [],
        [{UNSPENDABLE_ADDRESS: PAYMENT}],
        0,
        {"change_type": "legacy", "fee_rate": 1},
    )
    test.log.info(LOG.format("test_009_create_unsigned_psbt", res))
    assert 0 < res["fee"] < 0.0001
    assert res["changepos"] != -1

    test.state["psbt"] = res["psbt"]
    test.state["changepos"] = res["changepos"]
    test.state["fee"] = res["fee"]


def test_010_psbt_spends_utxo(base_test):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    decoded = rpc_krux("decodepsbt", test.state["psbt"])

    (utxo,) = rpc_krux("listunspent")
    (vin,) = decoded["tx"]["vin"]
    assert (vin["txid"], vin["vout"]) == (utxo["txid"], utxo["vout"])

    (inp,) = decoded["inputs"]
    prevout = inp["non_witness_utxo"]["vout"][utxo["vout"]]
    assert inp["non_witness_utxo"]["txid"] == test.state["txid"]
    assert prevout["value"] == FUNDING
    assert prevout["scriptPubKey"]["address"] == test.state["address"]


def test_011_psbt_change_address(base_test):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    signer = test.signers[0][0]
    decoded = rpc_krux("decodepsbt", test.state["psbt"])

    changepos = test.state["changepos"]
    core_change = decoded["tx"]["vout"][changepos]["scriptPubKey"]["address"]
    krux_change = next(signer.obtain_addresses(branch_index=1))
    test.log.info(LOG.format("test_011_psbt_change_address", core_change))
    assert core_change == krux_change

    info = rpc_krux("getaddressinfo", core_change)
    hdkeypath = info["hdkeypath"].replace("'", "h")
    assert info["ismine"] is True
    assert info["ischange"] is True
    assert hdkeypath == signer.key.derivation + "/1/0"

    test.state["change"] = core_change


def test_012_psbt_outputs(base_test):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    decoded = rpc_krux("decodepsbt", test.state["psbt"])

    outs = {o["scriptPubKey"]["address"]: o["value"] for o in decoded["tx"]["vout"]}
    test.log.info(LOG.format("test_012_psbt_outputs", outs))
    assert set(outs) == {UNSPENDABLE_ADDRESS, test.state["change"]}
    assert outs[UNSPENDABLE_ADDRESS] == PAYMENT
    assert round(sum(outs.values()) + test.state["fee"], 8) == FUNDING


def test_013_psbt_input_derivation(base_test, getpubkey):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    signer = test.signers[0][0]
    decoded = rpc_krux("decodepsbt", test.state["psbt"])

    (inp,) = decoded["inputs"]
    (deriv,) = inp["bip32_derivs"]
    test.log.info(LOG.format("test_013_psbt_input_derivation", deriv))
    assert deriv["pubkey"] == getpubkey(signer, 0, 1).hex()
    assert deriv["master_fingerprint"] == signer.key.fingerprint_hex_str()
    assert deriv["path"].replace("'", "h") == signer.key.derivation + "/0/1"


def test_014_psbt_unsigned(base_test, getpubkey, assert_unbroadcastable):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    signer = test.signers[0][0]
    psbt = test.state["psbt"]

    (inp,) = rpc_krux("decodepsbt", psbt)["inputs"]
    assert "partial_signatures" not in inp
    assert "final_scriptSig" not in inp

    pkh = hash160(getpubkey(signer, 0, 1)).hex()
    analysis = rpc_krux("analyzepsbt", psbt)
    test.log.info(LOG.format("test_014_psbt_unsigned", analysis))
    assert analysis["next"] == "signer"
    for inp_analysis in analysis["inputs"]:
        assert inp_analysis["has_utxo"]
        assert not inp_analysis["is_final"]
        assert inp_analysis["next"] == "signer"
        assert inp_analysis["missing"] == {"signatures": [pkh]}
    assert_unbroadcastable(test.backends[1], psbt)
    test.log.info(
        LOG.format(
            "test_014_psbt_unsigned", {"message": "Not broadcastable", "psbt": psbt}
        )
    )


def test_015_psbt_wrong_signer(base_test, psbtcopy, psbtsigner, assert_unbroadcastable):
    test = base_test(TAG, stop=False)
    wrong_signer = test.signers[1][0]
    copied = psbtcopy(test.state["psbt"])
    signer_krux = psbtsigner(wrong_signer, copied)
    test.log.info(LOG.format("test_015_psbt_wrong_signer", signer_krux))

    assert signer_krux.path_mismatch() == ""
    with raises(ValueError, match="cannot sign"):
        signer_krux.sign()

    unsigned = signer_krux.psbt.to_string()
    assert_unbroadcastable(test.backends[1], unsigned)
    test.log.info(
        LOG.format(
            "test_015_psbt_wrong_signer",
            {"message": "Not broadcastable", "psbt": unsigned},
        )
    )


def test_016_psbt_invalid(base_test, psbtsigner):
    test = base_test(TAG, stop=False)
    rpc_krux = test.backends[1].client.call
    wrong_signer = test.signers[0][0]
    rawtx = rpc_krux("createrawtransaction", [], [{UNSPENDABLE_ADDRESS: 1}])

    test.log.info(LOG.format("test_016_psbt_invalid", rawtx))
    with raises(ValueError, match="invalid PSBT"):
        psbtsigner(wrong_signer, rawtx)

    with raises(ClientError, match="TX decode failed"):
        rpc_krux("finalizepsbt", rawtx)


def test_017_psbt_mismatch(
    base_test, airgap_wallet, psbtcopy, psbtsigner, assert_unbroadcastable
):
    test = base_test(TAG, stop=False)
    signer = test.signers[0][0]
    assert psbtsigner(signer, test.state["psbt"]).path_mismatch() == ""

    for net, purpose in MISMATCHED:
        tmpwallet = airgap_wallet(signer.key.mnemonic, TYPE_SINGLESIG, net, purpose)
        tmpsigner = psbtsigner(tmpwallet, psbtcopy(test.state["psbt"]))
        test.log.info(LOG.format("test_017_psbt_mismatch", tmpwallet.key.derivation))
        assert tmpsigner.path_mismatch() == "m/44h/1h/0h"

        # Mimic the behaviour where a user declines "Proceed?" on the warning,
        # so Krux signs nothing, and user try to broadcast eitherway
        # the mismatch is a UX warning from core
        unsigned = tmpsigner.psbt.to_string()
        assert_unbroadcastable(test.backends[1], unsigned)
        test.log.info(
            LOG.format(
                "test_017_psbt_mismatch",
                {"message": "Not broadcastable", "psbt": unsigned},
            )
        )


def test_018_psbt_wrong_policy(
    base_test, airgap_wallet, psbtsigner, assert_unbroadcastable
):
    test = base_test(TAG, stop=False)
    signer = test.signers[0][0]
    cases = [
        (TYPE_MULTISIG, P2SH, "Not a multisig PSBT"),
        (TYPE_MULTISIG, P2SH_P2WSH, "Not a multisig PSBT"),
        (TYPE_MULTISIG, P2WSH, "Not a multisig PSBT"),
        (TYPE_MINISCRIPT, P2WSH, "Not a miniscript PSBT"),
        (TYPE_MINISCRIPT, P2TR, "Not a miniscript PSBT"),
    ]

    for policy, purpose, err in cases:
        tmpwallet = airgap_wallet(
            signer.key.mnemonic, policy, NETWORKS["regtest"], purpose
        )
        test.log.info(
            LOG.format("test_018_psbt_wrong_policy", tmpwallet.key.derivation)
        )

        with raises(ValueError, match=f"Invalid PSBT: {err}"):
            psbtsigner(tmpwallet, test.state["psbt"])

    assert_unbroadcastable(test.backends[1], test.state["psbt"])
    test.log.info(
        LOG.format(
            "test_018_psbt_wrong_policy",
            {"message": "Not broadcastable", "psbt": test.state["psbt"]},
        )
    )


def test_019_psbt_mismatch_sign(
    base_test, airgap_wallet, psbtcopy, psbtsigner, assert_finalizable
):
    # A path mismatch is a UX warning only. Krux signs and the same seed produces
    # a valid signature that Core accepts.
    test = base_test(TAG, stop=False)
    signer = test.signers[0][0]

    for net, purpose in MISMATCHED:
        tmpwallet = airgap_wallet(signer.key.mnemonic, TYPE_SINGLESIG, net, purpose)
        tmpsigner = psbtsigner(tmpwallet, psbtcopy(test.state["psbt"]))
        assert tmpsigner.path_mismatch() == "m/44h/1h/0h"

        # Mimic the user tapping "Proceed?" on the warning at a krux device
        tmpsigner.sign()
        signed, fmt = tmpsigner.psbt_qr()
        assert fmt == FORMAT_NONE

        # It isn't recommended to do `sendrawtransaction` as pedagogical approach;
        # instead, we call `finalizepsbt` and `testmempoolaccept` as a dry
        # run and never broadcast.
        finalized = assert_finalizable(test.backends[1], signed)
        test.log.info(
            LOG.format(
                "test_019_psbt_mismatch_still_signs",
                {"derivation": tmpwallet.key.derivation, "finalized": finalized},
            )
        )


# pylint: disable=too-many-locals
def test_020_psbt_rejects_without_prev_tx(
    base_test, psbtcopy, psbtsigner, assert_unbroadcastable
):
    test = base_test(TAG, stop=False)
    backend = test.backends[1]
    rpc_krux = backend.client.call
    signer = test.signers[0][0]
    err = "Invalid PSBT: missing non_witness_utxo on a legacy input"

    # 1) coordinator attaches no UTXO data at all
    (utxo,) = rpc_krux("listunspent")
    barepsbt = rpc_krux(
        "createpsbt",
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [{UNSPENDABLE_ADDRESS: PAYMENT}],
    )
    test.log.info(LOG.format("test_020_psbt_rejects_without_prev_tx", barepsbt))
    with raises(ValueError, match=err):
        psbtsigner(signer, barepsbt)

    (analysis,) = rpc_krux("analyzepsbt", barepsbt)["inputs"]
    assert not analysis["has_utxo"]
    assert_unbroadcastable(backend, barepsbt, role="updater")

    # 2) only coordinator could repair the psbt
    updated = rpc_krux("utxoupdatepsbt", barepsbt)
    (inp,) = rpc_krux("decodepsbt", updated)["inputs"]
    assert "non_witness_utxo" not in inp

    repaired = rpc_krux("walletprocesspsbt", updated, False)
    (inp,) = rpc_krux("decodepsbt", repaired["psbt"])["inputs"]
    assert not repaired["complete"]
    assert "non_witness_utxo" in inp
    assert psbtsigner(signer, repaired["psbt"]).path_mismatch() == ""

    # 3) amount through witness_utxo instead of proving it with the previous tx
    # and krux will refuse and core will wanna updated psbt
    copied = psbtcopy(test.state["psbt"])
    (inp,) = copied.inputs
    inp.witness_utxo = inp.non_witness_utxo.vout[inp.vout]
    inp.non_witness_utxo = None
    with raises(ValueError, match=err):
        psbtsigner(signer, copied)
    declared = copied.to_string()
    analysis = rpc_krux("analyzepsbt", declared)
    test.log.info(LOG.format("test_020_psbt_rejects_without_prev_tx", analysis))
    assert analysis["inputs"][0]["has_utxo"]
    assert analysis["fee"] == test.state["fee"]
    assert_unbroadcastable(backend, declared, role="updater")
    test.log.info(
        LOG.format(
            "test_020_psbt_rejects_without_prev_tx",
            {
                "message": "Not broadcastable",
                "psbt": {"raw": declared, "analysis": analysis},
            },
        )
    )


def test_021_psbt_malicious_prev_tx(base_test, psbtcopy, psbtsigner):
    # supose that coordinator lies in the previous tx
    # (name, real val, malicious coordinator val)
    # this could happen:
    # | desc                | real chain | fake on real chain       |
    # | ------------------- | ---------- | ------------------------ |
    # | spent               | 1.5        | 1.00000235               |
    # | outputs             | 1.0        | 1.0                      |
    # | fee on krux display | 0.5        | 0.00000235               |
    test = base_test(TAG, stop=True)
    signer = test.signers[0][0]
    rpc_krux = test.backends[1].client.call

    # an attacker could consider that the signature is still valid on krux
    # (sighash never included amount). If faked, the aim is to half coins go to
    # miner and the device show nothing. Krux will refuse to even start the
    # signature procedure.
    copied = psbtcopy(test.state["psbt"])
    fake_prev = Transaction.parse(copied.inputs[0].non_witness_utxo.serialize())
    fake_prev.vout[copied.inputs[0].vout].value //= 2
    copied.inputs[0].non_witness_utxo = fake_prev
    with raises(ValueError, match="Invalid PSBT: Previous txid doesn't match"):
        psbtsigner(signer, copied)

    # Core refuses to parse too
    declared = copied.to_string()
    with raises(ClientError, match="Non-witness UTXO does not match outpoint hash"):
        rpc_krux("decodepsbt", declared)

    test.log.info(
        LOG.format(
            "test_021_psbt_malicious_prev_tx",
            {"message": "Not broadcastable", "psbt": declared},
        )
    )
