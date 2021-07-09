#!/usr/bin/env bats

source $BATS_SUPPORT/load.bash

#load util/_
#load util/assert

setup() {
    cd $(mktemp -d -t icx-asset-e2e-XXXXXXXX)
}

teardown() {
    echo teardown
}

@test "no-nop test" {
    echo pass
}
