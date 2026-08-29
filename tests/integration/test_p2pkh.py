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
        signed txs.

    targets:
        - bitcoin-core on regtest.
        - krux.wallet module

    strategy:
        - uses ``*(["abandon"] * 11) + ["about"])`` mnemonic
        - load its ``tpub`` descriptor through ``importdescriptor`` in core

    todo:
        - create a core wallet to send coins to krux
        - krux should be able to inspect coins
        - create a tx/unsigened tx with core
        - krux must sign the psbt
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

2. Persistence. Core writes imported keys to ``$INTEGRATION_TEMP_DIR/data/bitcoin-core<N>/regtest/wallets/``
and bornal reuses those datadirs between runs, so the key would outlive the test
on disk.

3. Fidelity. Krux is an air-gapped signer: Core must only ever see the public
descriptor and receive signatures through a PSBT round-trip. Letting Core hold
the ``tprv`` would let a test "pass" without Krux signing anything.

The ``krux`` wallet above is created with ``disable_private_keys=True``, so
Core itself refuses a private-key import ("Cannot import private keys to a wallet
with private keys disabled") -- keep that flag as a guard. All of this is tolerable
in a scratch test only because ``MNEMONIC`` is the public BIP-39 reference vector;
never combine ``watch_only=False`` with any other mnemonic.
"""

from bornal.testing import (
    assert_block_count,
    assert_chain,
    generate_to_address,
)


def test_create(base_test, p2pkh_signers):
    test = base_test("p2pkh", stop=False)
    test.signers = p2pkh_signers

    for b in test.backends:
        assert_chain(b, "regtest")

    test.mine_blocks()
    test.connect_p2p(0, 1)
    for b in test.backends[1:]:
        assert_block_count(b, 101)

    test.create_watchonly_wallet(test.backends[1], "krux-0", test.signers[0][1])

    # test addresses
    rpc = test.backends[1].client.call
    core_addr = rpc("getnewaddress", "", "legacy")
    krux_addr = next(test.signers[0][0].obtain_addresses())
    test.log.info(
        "(test_p2pkh::test_create) Bitcoin-core 'Watch-only' address: {}".format(
            core_addr
        )
    )
    test.log.info(
        "(test_p2pkh::test_create) Krux 'Signer' address:             {}".format(
            krux_addr
        )
    )
    assert core_addr == krux_addr


def test_receive(base_test):
    test = base_test("p2pkh", stop=True)
    rpc_core = test.backends[0].client.call
    rpc_krux = test.backends[1].client.call

    assert rpc_krux("getbalance") == 0

    # get some new address  on core, copare with krux
    addr = rpc_krux("getnewaddress", "", "legacy")
    krux_addr = next(test.signers[0][0].obtain_addresses(i=1))
    test.log.info(
        "(test_p2pkh::test_receive) Bitcoin-core 'Watch-only' address: {}".format(addr)
    )
    test.log.info(
        "(test_p2pkh::test_receive) Krux 'Signer' address:             {}".format(
            krux_addr
        )
    )
    assert addr == krux_addr

    # send some amount from bornal-wallet to this address
    amount = 1.5
    txid = rpc_core("sendtoaddress", addr, amount)
    test.log.info(
        "(test_p2pkh::test_receive) Sent {} BTC to {} in {}".format(amount, addr, txid)
    )

    # Generate more blocks so we can check balance
    generate_to_address(test.backends[0], 1)
    test.sync_blocks(0, 1)
    assert_block_count(test.backends[1], 102)

    # check balance on bitcoin-core watch-only wallet
    assert rpc_krux("getbalance") == amount
    assert rpc_krux("getreceivedbyaddress", addr) == amount
    unspent = rpc_krux("listunspent")
    assert [
        (u["txid"], u["address"], u["amount"], u["confirmations"]) for u in unspent
    ] == [(txid, addr, amount, 1)]
    test.log.info(
        "(test_p2pkh::test_receive) Watch-only balance: {} BTC".format(
            rpc_krux("getbalance")
        )
    )
