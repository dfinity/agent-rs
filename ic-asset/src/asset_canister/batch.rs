use crate::asset_canister::method_names::{COMMIT_BATCH, CREATE_BATCH};
use crate::asset_canister::protocol::{
    BatchOperationKind, CommitBatchArguments, CreateBatchRequest, CreateBatchResponse,
};
use crate::convenience::waiter_with_timeout;
use crate::params::CanisterCallParams;
use candid::Nat;

pub(crate) async fn create_batch(
    canister_call_params: &CanisterCallParams<'_>,
) -> anyhow::Result<Nat> {
    let create_batch_args = CreateBatchRequest {};
    let response = canister_call_params
        .canister
        .update_(CREATE_BATCH)
        .with_arg(&create_batch_args)
        .build()
        .map(|result: (CreateBatchResponse,)| (result.0.batch_id,))
        .call_and_wait(waiter_with_timeout(canister_call_params.timeout))
        .await?;
    let batch_id = response.0;
    Ok(batch_id)
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
    canister_call_params
        .canister
        .update_(COMMIT_BATCH)
        .with_arg(arg)
        .build()
        .call_and_wait(waiter_with_timeout(canister_call_params.timeout))
        .await?;
    Ok(())
}
