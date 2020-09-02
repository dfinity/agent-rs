use crate::call::AsyncCaller;
use crate::canister::{CanisterBuilderError, CanisterIdProvider};
use crate::Canister;
use ic_types::Principal;
use std::convert::TryFrom;

pub struct ManagementCanister;

pub trait ManagementCanisterInterface {
    fn create_canister(&self) -> AsyncCaller<Principal>;
}

impl<'agent> CanisterIdProvider for Canister<'agent, ManagementCanister> {
    fn get_canister_id(&self) -> Option<Result<Principal, CanisterBuilderError>> {
        Some(Ok(Principal::management_canister()))
    }
}

impl<'agent> ManagementCanisterInterface for Canister<'agent, ManagementCanister> {
    fn create_canister(&self) -> AsyncCaller<'_, Principal> {
        self.update_("create_canister")
            .map(|r: candid::Principal| Principal::try_from(r).unwrap())
            .build()
    }
}
