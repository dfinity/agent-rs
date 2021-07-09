#!/usr/bin/env bats

#source "$BATS_SUPPORT"/load.bash

load util/assertions

setup() {
    cd "$(mktemp -d -t icx-asset-e2e-XXXXXXXX)" || exit 1
    dfx new --no-frontend e2e_project
    cd e2e_project || exit 1
    dfx start --background
    dfx deploy
}

teardown() {
    echo teardown
    dfx stop
}

icx_asset_sync() {
  CANISTER_ID=$(dfx canister id e2e_project_assets)
  assert_command "$ICX_ASSET" --pem "$HOME"/.config/dfx/identity/default/identity.pem sync "$CANISTER_ID" src/e2e_project_assets/assets
}

@test "creates new files" {
  echo "new file content" >src/e2e_project_assets/assets/new-asset.txt
  icx_asset_sync

  assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/new-asset.txt";accept_encodings=vec{"identity"}})'
}

@test "updates existing files" {
    echo -n "an asset that will change" >src/e2e_project_assets/assets/asset-to-change.txt
    assert_command dfx deploy

    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/asset-to-change.txt";accept_encodings=vec{"identity"}})'
    # shellcheck disable=SC2154
    assert_match '"an asset that will change"' "$stdout"

    echo -n "an asset that has been changed" >src/e2e_project_assets/assets/asset-to-change.txt

    icx_asset_sync

    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/asset-to-change.txt";accept_encodings=vec{"identity"}})'
    # shellcheck disable=SC2154
    assert_match '"an asset that has been changed"' "$stdout"
  echo pass
}

@test "deletes removed files" {
    touch src/e2e_project_assets/assets/will-delete-this.txt
    dfx deploy

    assert_command dfx canister call --query e2e_project_assets get '(record{key="/will-delete-this.txt";accept_encodings=vec{"identity"}})'
    assert_command dfx canister call --query e2e_project_assets list  '(record{})'
    assert_match '"/will-delete-this.txt"'

    rm src/e2e_project_assets/assets/will-delete-this.txt

    icx_asset_sync

    assert_command_fail dfx canister call --query e2e_project_assets get '(record{key="/will-delete-this.txt";accept_encodings=vec{"identity"}})'
    assert_command dfx canister call --query e2e_project_assets list  '(record{})'
    assert_not_match '"/will-delete-this.txt"'
}

@test "unsets asset encodings that are removed from project" {

    assert_command dfx canister --no-wallet call --update e2e_project_assets store '(record{key="/sample-asset.txt"; content_type="text/plain"; content_encoding="arbitrary"; content=blob "content encoded in another way!"})'

    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"identity"}})'
    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"arbitrary"}})'

    icx_asset_sync

    assert_command dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"identity"}})'
    assert_command_fail dfx canister --no-wallet call --query e2e_project_assets get '(record{key="/sample-asset.txt";accept_encodings=vec{"arbitrary"}})'
}
