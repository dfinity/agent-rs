use crate::call::TypedAsyncCaller;
use crate::canister::{CanisterBuilderError, CanisterIdProvider};
use crate::Canister;
use ic_types::Principal;

pub struct ManagementCanister;

pub trait ManagementCanisterInterface {
    fn create_canister(&self) -> TypedAsyncCaller<'_, (), Principal>;
}

impl<'agent> CanisterIdProvider for ManagementCanister {
    fn get_canister_id(&self) -> Option<Result<Principal, CanisterBuilderError>> {
        Some(Ok(Principal::management_canister()))
    }
}

impl<'agent> ManagementCanisterInterface for Canister<'agent, ManagementCanister> {
    fn create_canister(&self) -> TypedAsyncCaller<'_, (), Principal> {
        self.update_("create_canister").build_typed()
    }
}
