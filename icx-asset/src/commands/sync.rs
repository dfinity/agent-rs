use candid::Principal as CanisterId;
use ic_agent::Agent;

use crate::{support, SyncOpts};
use std::time::Duration;

pub(crate) async fn sync(
    agent: &Agent,
    canister_id: &CanisterId,
    timeout: Duration,
    o: &SyncOpts,
) -> support::Result {
    ic_asset::sync(&agent, &o.directory, canister_id, timeout).await?;
    Ok(())
}
