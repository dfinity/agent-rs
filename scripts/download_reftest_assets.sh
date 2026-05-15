#!/usr/bin/env bash
# Exit on error, treat unset variables as errors, and fail pipelines on the
# first non-zero exit. IFS reset avoids surprising word-splitting on spaces.
set -euo pipefail
IFS=$'\n\t'

# Run from the repo root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

# Pin the pocket-ic binary and universal_canister.wasm to the same IC commit as
# the pocket-ic crate dependency in the root Cargo.toml, so the server binary
# and client library stay in sync.
ic_commit=$(sed -n 's/^pocket-ic = .*rev = "\([a-f0-9]\{40\}\)".*/\1/p' Cargo.toml)
if [ -z "$ic_commit" ]; then
    echo "Failed to extract pocket-ic rev from Cargo.toml" >&2
    exit 1
fi
wallet_ver=20230530

case $(uname -s) in
    Linux*)     os="linux";;
    Darwin*)    os="darwin";;
    *)          echo "Unsupported OS"; exit 1;;
esac
case $(uname -m) in
    x86_64*)    arch="x86_64";;
    arm64*)     arch="arm64";;
    *)          echo "Unsupported architecture"; exit 1;;
esac
curl -L --fail "https://download.dfinity.systems/ic/${ic_commit}/binaries/${arch}-${os}/pocket-ic.gz" -o ref-tests/assets/pocket-ic.gz
gunzip -f ref-tests/assets/pocket-ic.gz
chmod a+x ref-tests/assets/pocket-ic
curl -L --fail "https://download.dfinity.systems/ic/${ic_commit}/canisters/universal_canister.wasm.gz" -o ref-tests/assets/universal-canister.wasm.gz
curl -L --fail "https://github.com/dfinity/cycles-wallet/releases/download/${wallet_ver}/wallet.wasm" -o ref-tests/assets/cycles-wallet.wasm
