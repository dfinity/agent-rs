use ic_agent::Agent;
use ic_types::Principal;
use std::time::Duration;

pub struct CanisterCallParams<'a> {
    pub agent: &'a Agent,
    pub canister_id: Principal,
    pub timeout: Duration,
}
