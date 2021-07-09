#!/usr/bin/env bats

source $BATS_SUPPORT/load.bash

#load util/_
#load util/assert

setup() {
    cd $(mktemp -d -t icx-asset-e2e-XXXXXXXX)
    dfx new e2e_project
    cd e2e_project
    dfx start --background
    dfx deploy
}

teardown() {
    echo teardown
    dfx stop
}

@test "no-nop test" {
    echo pass
}
