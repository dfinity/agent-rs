use crate::asset_canister::method_names::LIST;
use crate::asset_canister::protocol::{AssetDetails, ListAssetsRequest};
use crate::convenience::waiter_with_timeout;
use crate::params::CanisterCallParams;
use candid::{Decode, Encode};
use std::collections::HashMap;
use std::time::Duration;
use ic_utils::Canister;

pub(crate) async fn list_assets(
    canister_call_params: &CanisterCallParams<'_>,
) -> anyhow::Result<HashMap<String, AssetDetails>> {
    let args = ListAssetsRequest {};
    let response = canister_call_params
        .agent
        .update(&canister_call_params.canister_id, LIST)
        .with_arg(candid::Encode!(&args)?)
        .expire_after(canister_call_params.timeout)
        .call_and_wait(waiter_with_timeout(canister_call_params.timeout))
        .await?;

    let assets: HashMap<_, _> = candid::Decode!(&response, Vec<AssetDetails>)?
        .into_iter()
        .map(|d| (d.key.clone(), d))
        .collect();

    Ok(assets)
}

pub(crate) async fn _list_assets(
    canister: &Canister<'_>,
    timeout: Duration,
) -> anyhow::Result<HashMap<String, AssetDetails>> {
    let args = ListAssetsRequest {};
    let response = canister
        .update_(LIST)
        .with_arg(candid::Encode!(&args)?)
        //.expire_after(canister_call_params.timeout)
        .build()
        .map(|result: (Vec<AssetDetails>,)|result.0)
        .call_and_wait(waiter_with_timeout(timeout))
        .await?;

    let assets: HashMap<_, _> = response
        .into_iter()
        .map(|d| (d.key.clone(), d))
        .collect();

    Ok(assets)
}
