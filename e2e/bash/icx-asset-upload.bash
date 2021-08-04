#!/usr/bin/env bats

# shellcheck disable=SC1090
source "$BATS_SUPPORT"/load.bash

load util/assertions

setup() {
      # We want to work from a different temporary directory for every test.
    x=$(mktemp -d -t icx-asset-e2e-XXXXXXXX)
    export DFX_CONFIG_ROOT="$x"
    cd "$DFX_CONFIG_ROOT" || exit

    dfx new --no-frontend e2e_project
    cd e2e_project || exit 1
    dfx start --background
    dfx deploy
}

teardown() {
    dfx stop
    rm -rf "$DFX_CONFIG_ROOT"
}

icx_asset_sync() {
  CANISTER_ID=$(dfx canister id e2e_project_assets)
  assert_command "$ICX_ASSET" --pem "$DFX_CONFIG_ROOT"/.config/dfx/identity/default/identity.pem sync "$CANISTER_ID" src/e2e_project_assets/assets
}

icx_asset_list() {
  CANISTER_ID=$(dfx canister id e2e_project_assets)
  assert_command "$ICX_ASSET" --pem "$DFX_CONFIG_ROOT"/.config/dfx/identity/default/identity.pem ls "$CANISTER_ID"
}

icx_asset_upload() {
  CANISTER_ID=$(dfx canister id e2e_project_assets)
  assert_command "$ICX_ASSET" --pem "$DFX_CONFIG_ROOT"/.config/dfx/identity/default/identity.pem upload "$CANISTER_ID" "$*"
}

@test "uploads a file by name" {
    echo "this is the file content" >uploaded.txt

    icx_asset_upload uploaded.txt

    icx_asset_list

    assert_match " /uploaded.txt.*text/plain.*identity"
}

@test "uploads a directory by name" {
    mkdir some_dir
    echo "some stuff" >some_dir/a.txt
    echo "more things" >some_dir/b.txt

    icx_asset_upload some_dir

    icx_asset_list

    # expect:
    #   /some_dir/a.txt
    #   /some_dir/b.txt

    assert_match " /some_dir/a.txt.*text/plain.*identity"
}

@test "uploads multiple files" {
    mkdir some_dir
    echo "some stuff" >some_dir/a.txt
    echo "more things" >some_dir/b.txt

    icx_asset_upload some_dir/*.txt

    icx_asset_list

    # expect: (is this surprising?)
    #   /a.txt
    #   /b.txt

    assert_match " /uploaded.txt.*text/plain.*identity"
}


@test "uploads multiple files from absolute path" {
    mkdir some_dir
    echo "some stuff" >some_dir/a.txt
    echo "more things" >some_dir/b.txt

    icx_asset_upload "$(realpath some_dir/a.txt)" "$(realpath some_dir/b.txt)"

    icx_asset_list

    # expect:
    #   /a.txt
    #   /b.txt

    assert_match " /uploaded.txt.*text/plain.*identity"
}



