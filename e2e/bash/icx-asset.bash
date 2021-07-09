#!/usr/bin/env bats

source $BATS_SUPPORT/load.bash

load util/assertions

setup() {
    cd $(mktemp -d -t icx-asset-e2e-XXXXXXXX)
    dfx new --no-frontend e2e_project
    cd e2e_project
    dfx start --background
    dfx deploy
}

teardown() {
    echo teardown
    dfx stop
}

icx_asset_sync() {
  CANISTER_ID=$(dfx canister id e2e_project_assets)
  assert_command $ICX_ASSET --pem $HOME/.config/dfx/identity/default/identity.pem sync $CANISTER_ID src/e2e_project_assets/assets
}

@test "no-nop test" {
    echo pass
}

@test "creates new files" {
  echo "new file content" >src/e2e_project_assets/assets/new-asset.txt
  icx_asset_sync

  assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/new-asset.txt";accept_encodings=vec{"identity"}})'
}

@test "updates existing files" {
  echo pass
}

@test "deletes removed files" {
  echo pass
}

@test "unsets asset encodings that are removed from project" {

    assert_command dfx canister --no-wallet call --update e2e_project_assets store '(record{key="/sample-asset.txt"; content_type="text/plain"; content_encoding="arbitrary"; content=blob "content encoded in another way!"})'

    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"identity"}})'
    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"arbitrary"}})'

    icx_asset_sync

    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"identity"}})'
    assert_command_fail dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"arbitrary"}})'
}
