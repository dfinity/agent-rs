use crate::sync::CanisterCallParams;
use candid::{Decode, Encode, Nat};
use crate::asset_canister::protocol::{CreateBatchRequest, CreateBatchResponse};
use crate::asset_canister::method_names::CREATE_BATCH;
use crate::convenience::waiter_with_timeout;

pub(crate) async fn create_batch(canister_call_params: &CanisterCallParams<'_>) -> anyhow::Result<Nat> {
    let create_batch_args = CreateBatchRequest {};
    let response = canister_call_params
        .agent
        .update(&canister_call_params.canister_id, CREATE_BATCH)
        .with_arg(candid::Encode!(&create_batch_args)?)
        .expire_after(canister_call_params.timeout)
        .call_and_wait(waiter_with_timeout(canister_call_params.timeout))
        .await?;
    let create_batch_response = candid::Decode!(&response, CreateBatchResponse)?;
    Ok(create_batch_response.batch_id)
}

