use ic_utils::Canister;

use crate::{support, SyncOpts};
use std::time::Duration;

pub(crate) async fn sync(
    canister: &Canister<'_>,
    timeout: Duration,
    o: &SyncOpts,
) -> support::Result {
    ic_asset::sync(canister, &o.directory, timeout).await?;
    Ok(())
}
