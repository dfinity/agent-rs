use crate::asset_canister::method_names::{COMMIT_BATCH, CREATE_BATCH};
use crate::asset_canister::protocol::{
    BatchOperationKind, CommitBatchArguments, CreateBatchRequest, CreateBatchResponse,
};
use crate::convenience::waiter_with_timeout;
use crate::params::CanisterCallParams;
use candid::{Decode, Encode, Nat};
use ic_utils::Canister;
use std::time::Duration;

pub(crate) async fn create_batch(
    canister_call_params: &CanisterCallParams<'_>,
) -> anyhow::Result<Nat> {
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

pub(crate) async fn _create_batch(
    canister: &Canister<'_>,
    timeout: Duration,
) -> anyhow::Result<Nat> {
    let create_batch_args = CreateBatchRequest {};
    let response = canister
        .update_(CREATE_BATCH)
        .with_arg(candid::Encode!(&create_batch_args)?)
        //.expire_after(canister_call_params.timeout)
        .build()
        .map(|result: (CreateBatchResponse,)| (result.0,))
        .call_and_wait(waiter_with_timeout(timeout))
        .await?;
    Ok(response.0.batch_id)
}

pub(crate) async fn commit_batch(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    operations: Vec<BatchOperationKind>,
) -> anyhow::Result<()> {
    let arg = CommitBatchArguments {
        batch_id,
        operations,
    };
    let arg = candid::Encode!(&arg)?;
    canister_call_params
        .agent
        .update(&canister_call_params.canister_id, COMMIT_BATCH)
        .with_arg(arg)
        .expire_after(canister_call_params.timeout)
        .call_and_wait(waiter_with_timeout(canister_call_params.timeout))
        .await?;
    Ok(())
}
