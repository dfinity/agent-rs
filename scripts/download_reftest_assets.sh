#!/bin/bash
set -e
cd "$(dirname "$0")/.."

ic_commit_for_pic=3c7938320bad1a690f617836d8b799f3998cf3ac
ic_commit_for_universal_canister=44e6a4830a03f05101a33d7baeb1f92c5c8093bc
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
curl -L --fail "https://download.dfinity.systems/ic/${ic_commit_for_pic}/binaries/${arch}-${os}/pocket-ic.gz" -o ref-tests/assets/pocket-ic.gz
gunzip -f ref-tests/assets/pocket-ic.gz
curl -L --fail "https://download.dfinity.systems/ic/${ic_commit_for_universal_canister}/canisters/universal_canister.wasm.gz" -o ref-tests/assets/universal-canister.wasm.gz
curl -L --fail "https://github.com/dfinity/cycles-wallet/releases/download/${wallet_ver}/wallet.wasm" -o ref-tests/assets/cycles-wallet.wasm
