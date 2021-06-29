use crate::asset_canister::method_names::{COMMIT_BATCH, CREATE_BATCH};
use crate::asset_canister::protocol::{
    BatchOperationKind, CommitBatchArguments, CreateBatchRequest, CreateBatchResponse,
};
use crate::convenience::waiter_with_timeout;
use candid::{Decode, Encode, Nat};
use crate::params::CanisterCallParams;

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
