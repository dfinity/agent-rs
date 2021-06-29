use candid::{Decode, Encode, Nat};
use crate::sync::CanisterCallParams;
use futures_intrusive::sync::SharedSemaphore;
use crate::asset_canister::protocol::{CreateChunkRequest, CreateChunkResponse};
use garcon::{Delay, Waiter};
use crate::asset_canister::method_names::CREATE_CHUNK;
use crate::convenience::waiter_with_timeout;


pub(crate) async fn create_chunk(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    content: &[u8],
    create_chunk_call_semaphore: &SharedSemaphore,
    create_chunk_wait_semaphore: &SharedSemaphore,
) -> anyhow::Result<Nat> {
    let batch_id = batch_id.clone();
    let args = CreateChunkRequest { batch_id, content };
    let args = candid::Encode!(&args)?;

    let mut waiter = Delay::builder()
        .timeout(std::time::Duration::from_secs(30))
        .throttle(std::time::Duration::from_secs(1))
        .build();
    waiter.start();

    loop {
        let mut builder = canister_call_params
            .agent
            .update(&canister_call_params.canister_id, CREATE_CHUNK);
        let builder = builder.with_arg(&args);
        let request_id_result = {
            let _releaser = create_chunk_call_semaphore.acquire(1).await;
            builder
                .expire_after(canister_call_params.timeout)
                .call()
                .await
        };
        let wait_result = match request_id_result {
            Ok(request_id) => {
                let _releaser = create_chunk_wait_semaphore.acquire(1).await;
                canister_call_params
                    .agent
                    .wait(
                        request_id,
                        &canister_call_params.canister_id,
                        waiter_with_timeout(canister_call_params.timeout),
                    )
                    .await
            }
            Err(err) => Err(err),
        };
        match wait_result
            .map_err(|e| anyhow::anyhow!("{}", e))
            .and_then(|response| {
                candid::Decode!(&response, CreateChunkResponse)
                    .map_err(|e| anyhow::anyhow!("{}", e))
                    .map(|x| x.chunk_id)
            }) {
            Ok(chunk_id) => {
                break Ok(chunk_id);
            }
            Err(agent_err) => match waiter.wait() {
                Ok(()) => {}
                Err(_) => break Err(agent_err),
            },
        }
    }
}
