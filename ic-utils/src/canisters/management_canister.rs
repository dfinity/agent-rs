use crate::call::TypedAsyncCall;
use crate::Canister;
use candid::{CandidType, Deserialize};
use ic_types::Principal;
use std::fmt::Debug;

pub struct ManagementCanister;

#[derive(Clone, Debug, candid::CandidType, candid::Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CanisterStatus {
    Running,
    Stopping,
    Stopped,
}

impl std::fmt::Display for CanisterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl<'agent> Canister<'agent, ManagementCanister> {
    /// Create a canister, returning a caller that returns a Canister Id.
    pub fn create_canister<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + TypedAsyncCall<Principal> {
        #[derive(Deserialize)]
        struct CreateCanisterResult {
            canister_id: Principal,
        }

        self.update_("create_canister")
            .build_typed()
            .and_then(|result: CreateCanisterResult| result.canister_id)
    }

    pub fn canister_status<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + TypedAsyncCall<CanisterStatus> {
        #[derive(CandidType)]
        struct CanisterRecord {
            canister_id: Principal,
        }

        #[derive(Deserialize)]
        struct StatusReply {
            status: CanisterStatus,
        }

        self.update_("canister_status")
            .with_arg(CanisterRecord {
                canister_id: canister_id.clone(),
            })
            .build_typed()
            .and_then(|result: StatusReply| result.status)
    }
}
