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

import time

from bornal.daemon import free_port
from bornal.plugins.bitcoind import UNSPENDABLE_ADDRESS
from bornal.testing import (
    assert_wallet_roundtrip,
    assert_block_count,
    assert_chain,
)

# pylint: disable=wrong-import-position  # must follow the shims above
from bornal.node import IntegrationTest
from krux.wallet import Wallet


class p2pkhTest(IntegrationTest):
    _signers: list[tuple[Wallet, str]] = []

    @property
    def signers(self):
        return self._signers

    @signers.setter
    def signers(self, value: list[tuple[Wallet, str]]):
        if len(self._signers) == 0:
            self._signers = value
        else:
            raise ValueError("Signers already set")

    def set_test_params(self):
        """Connect nodes throug a triangle network"""
        self._p2p_ports = []
        for _ in range(2):
            p = free_port()
            self._p2p_ports.append(p)
            self.log.info(p)
            self.add_backend(
                "bitcoin-core", ["-listen=1", "-bind=127.0.0.1:{}".format(p)]
            )

    def run_test(self):
        for b in self.backends:
            assert_chain(b, "regtest")

        self.mine_blocks()
        self.connect_p2p(0, 1)
        for b in self.backends[1:]:
            assert_block_count(b, 101)

        self.create_wallet(self.backends[0], "core-0", watch_only=False)
        self.create_wallet(self.backends[1], "krux-0", self.signers[0][1], True)

        # test addresses
        rpc = self.backends[1].client.call
        addr = rpc("getnewaddress", "", "legacy")
        self.log.info("Bitcoin-core 'Watch-only' address: {}".format(addr))
        self.log.info("Krux 'Signer' address:             {}".format(addr))
        assert addr == next(self.signers[0][0].obtain_addresses())

    def connect_p2p(self, i, j, timeout: int = 30):
        src = self.backends[i]
        dest = self.backends[j]
        src_addr = "{}:{}".format(src.daemon.host, self._p2p_ports[i])
        p2p_addr = "{}:{}".format(dest.daemon.host, self._p2p_ports[j])

        rpc_s = src.client.call
        rpc_d = dest.client.call

        res = rpc_s("addnode", p2p_addr, "onetry")
        assert res is None
        self.log.info("Connected {} to {}".format(src_addr, p2p_addr))

        die = time.monotonic() + timeout
        while time.monotonic() < die:
            if rpc_s("getblockcount") == rpc_d("getblockcount"):
                self.log.info("Synced {} with {}".format(p2p_addr, src_addr))
                return
            time.sleep(0.25)
        raise AssertionError("Nodes did not sync in '{}'".format(timeout))

    def mine_blocks(self):
        self.log.info("Mining 101 blocks to {}".format(UNSPENDABLE_ADDRESS))
        assert_wallet_roundtrip(self.backends[0])
        rpc = self.backends[0].client.call
        assert rpc("listwallets") == ["bornal-wallet"]
        self.log.info("default bornal-wallet created")

    def create_wallet(
        self,
        backend,
        name,
        output_script_descriptor: str | None = None,
        watch_only=True,
    ):
        rpc = backend.client.call
        if watch_only:
            if output_script_descriptor is None:
                raise ValueError("output script descriptor cannot be None")
            res = rpc("createwallet", name, True, True)
            self.log.info("Wallet {} created. Importing descriptor...".format(name))
            assert res["name"] == name
            res = rpc(
                "importdescriptors",
                [
                    {
                        "desc": output_script_descriptor,
                        "active": True,
                        "timestamp": "now",
                        "range": [0, 10],
                    }
                ],
            )

            assert all(r["success"] for r in res)
            self.log.info("Descriptor {} imported".format(output_script_descriptor))


def test_p2pkh(krux_p2pkh_wallets):
    test = p2pkhTest()
    test.signers = krux_p2pkh_wallets
    test.main()
