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

@test "sign update" {
  assert_command "$ICX" --pem "$HOME"/.config/dfx/identity/default/identity.pem --fetch-root-key update --serialize rwlgt-iiaaa-aaaaa-aaaaa-cai greet '("everyone")' > output.txt
  head -n 1 output.txt > update.json
  tail -n 1 output.txt > request_status.json
  assert_command cat update.json | "$ICX" send
  assert_command cat request_status.json | "$ICX" --fetch-root-key send
}
