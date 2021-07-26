use ic_agent::Agent;
use ic_types::principal::Principal as CanisterId;

use std::time::Duration;
use std::collections::HashMap;
use std::path::PathBuf;

/// Upload the specified files
pub async fn upload(
    agent: &Agent,
    canister_id: &CanisterId,
    timeout: Duration,
    files: HashMap<String, PathBuf>,
) -> anyhow::Result<()> {
    unimplemented!();
}
