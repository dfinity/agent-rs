use ic_agent::Agent;
use ic_types::Principal;
use std::time::Duration;

pub(crate) struct CanisterCallParams<'a> {
    pub(crate) agent: &'a Agent,
    pub(crate) canister_id: Principal,
    pub(crate) timeout: Duration,
}
