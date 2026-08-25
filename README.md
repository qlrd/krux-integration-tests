# krux-integration-tests

Integration tests for the [Krux](https://github.com/selfcustody/krux)
ecosystem.

## Summary

Integration tests are a important part of any project and maybe sits between
basic tests and fuzz tests. This one is to check if krux correctly (we expect so!)
with `bitcoin-core` (with or without `electrs` -- testing a basic setup of a
ideal `sparrow`), `florestad`, `utreexod` and `lianad` (TODO: maybe SP on regtest too?).

## Structure

Tests lives under `tests/integration/` drive real Bitcoin daemons
(`bitcoind`, `electrs` -- TODO, ...) on **regtest**.

Implementations are built from source, cached and handed to the tests as
fixtures by the [`bornal`](https://github.com/qlrd/bornal) pytest plugin **unless**
you provide your own bitcoin implementations.

## Setup

- Build deps for bitcoin-core and electrs
- python 3.12 (`.python-version`)
- [`uv`](https://docs.astral.sh/uv/)

### Installing

```sh
# Krux uses a lot of submodules, accelerate it with `--jobs`
git clone --recurse-submodules --jobs 8 <this-repo>
# or, in an existing clone:
git submodule update --init --recursive --jobs 8
uv sync --frozen
```

Optional, for the C `secp256k1` backend embit's tests expect
(pure-Python fallback otherwise):

```sh
cd vendor/krux
uv run poe secp256k1-build
uv run poe secp256k1-check
```

## Running tests

If you wanna to use your own daemon, add it to `BORNAL_TEMP_DIR`. First run
builds the backends into `BORNAL_TEMP_DIR` (default `$HOME/.cache/bornal/krux-integration-tests`,
see `bornal/paths.py`).

The compilation was made to separate from your own bitcoin-core binaries, logs
and data folders.

Later runs reuse it (so will not recompile):

```sh
uv run pytest --build-bitcoin latest --wallet tests     # it build bitcoind (with wallet) then run
uv run pytest tests                                     # reuse the cached build
uv run pytest --build-bitcoin 30.2 --nproc 8 tests      # pin a release, set compile parallelism
```

Flags such as `--force-build` / `--preserve-data` are documented in
`bornal`'s README.
