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
"""

import pytest

from bornal.daemon import free_port
from bornal.testing import (
    assert_wallet_roundtrip,
    assert_block_count,
    assert_chain,
)
from embit.networks import NETWORKS
from krux.key import TYPE_SINGLESIG, P2PKH

MNEMONIC = " ".join(["abandon"] * 11 + ["about"])


@pytest.fixture
def setup(backend, connect, airgap_wallet, output_script_descriptor):
    """Create 3 nodes, the first will initialize network, the second will be a
    coordinator to krux and a third another node to interact to."""
    cores = [backend("bitcoin-core", p2p_port=free_port()) for _ in range(3)]

    # this create a dummy unspendable coins with 101 blocks)
    assert_wallet_roundtrip(cores[0])
    rpc = cores[0].client.call
    res = rpc("listwallets")
    assert len(res) == 1
    assert res[0] == "bornal-wallet"

    # connect the nodes
    assert_chain(cores[0], "regtest")
    assert_chain(cores[1], "regtest")
    connect(cores[0], cores[1])
    connect(cores[1], cores[2])
    connect(cores[0], cores[2])
    assert_block_count(cores[1], 101)
    assert_block_count(cores[2], count=101)

    # now create a "airgap" wallet and import to 2nd core
    wallet = airgap_wallet(MNEMONIC, TYPE_SINGLESIG, NETWORKS["regtest"], P2PKH)
    rpc = cores[1].client.call
    res = rpc("createwallet", "krux", True, True)
    assert res["name"] == "krux"
    res = rpc(
        "importdescriptors",
        [
            {
                "desc": output_script_descriptor(wallet),
                "active": True,
                "timestamp": "now",
                "range": [0, 10],
            }
        ],
    )
    assert all(r["success"] for r in res)

    # now create a third wallet to interact with both
    rpc = cores[2].client.call
    res = rpc("createwallet", "test")
    assert res["name"] == "test"

    return (cores, wallet)


def test_getnewadresses(setup):
    """Comparation between imported descriptor and actual device on deriv 0"""
    cores, airgap_wallet = setup
    rpc = cores[1].client.call
    addr = rpc("getnewaddress", "", "legacy")
    assert addr == next(airgap_wallet.obtain_addresses())
