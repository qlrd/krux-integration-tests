# SECURITY

> WARNING: keep the Core side of the airgap wallet WATCH-ONLY.

``output_script_descriptor(wallet)`` defaults to ``watch_only=True`` and hands
Core a descriptor that carries only the ``tpub``. Passing ``watch_only=False``
swaps the ``tpub`` for the ``tprv``
(see ``tests/conftest.py::output_script_descriptor``), i.e. it gives Core the
private key. Do not do that here, for three reasons:

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
Core itself refuses a private-key import ("Cannot import private keys to a
wallet with private keys disabled") -- keep that flag as a guard. All of this is
tolerable in a scratch test only because ``MNEMONIC`` is the public BIP-39
reference vector; never combine ``watch_only=False`` with any other mnemonic.

If you find any sensible issue, please report to [qlrddev@proton.me](mailto:qlrddev@proton.me).
I will try to respond fast as possible within 7 days and patch a fix within 90 days.
