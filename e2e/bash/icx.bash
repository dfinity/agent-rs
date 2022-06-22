#!/usr/bin/env bats

# shellcheck disable=SC1090
source "$BATS_SUPPORT"/load.bash

load util/assertions

setup() {
    cd "$(mktemp -d -t icx-e2e-XXXXXXXX)" || exit 1
    dfx new --no-frontend e2e_project
    cd e2e_project || exit 1
    dfx start --background
    dfx deploy
}

teardown() {
    echo teardown
    dfx stop
}

# this test does not work, and is not run in CI
@test "sign update" {
  "$ICX" --pem "$HOME"/.config/dfx/identity/default/identity.pem update --serialize rwlgt-iiaaa-aaaaa-aaaaa-cai greet '("everyone")' > output.txt
  head -n 1 output.txt > update.json
  tail -n 1 output.txt > request_status.json
  "$ICX" send <update.json
  "$ICX" send <request_status.json
}
