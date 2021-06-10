use ic_agent::Agent;
use ic_types::principal::Principal as CanisterId;

use std::path::Path;

pub fn sync(_agent: &Agent, _dir: &Path, _canister_id: &CanisterId) -> anyhow::Result<()> {
    Ok(())
}
