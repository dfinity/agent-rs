use crate::call::AsyncCall;
use crate::Canister;
use candid::{CandidType, Deserialize};
use ic_types::Principal;
use std::fmt::Debug;
use std::str::FromStr;

pub struct ManagementCanister;

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq)]
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

#[derive(Clone, CandidType, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallMode {
    Install,
    Reinstall,
    Upgrade,
}

impl FromStr for InstallMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "install" => Ok(InstallMode::Install),
            "reinstall" => Ok(InstallMode::Reinstall),
            "upgrade" => Ok(InstallMode::Upgrade),
            &_ => Err(format!("Invalid install mode: {}", s)),
        }
    }
}

impl<'agent> Canister<'agent, ManagementCanister> {
    pub fn canister_status<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<CanisterStatus> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        #[derive(Deserialize)]
        struct Out {
            status: CanisterStatus,
        }

        self.update_("canister_status")
            .with_arg(In {
                canister_id: canister_id.clone(),
            })
            .build()
            .map(|result: Out| result.status)
    }

    /// Create a canister, returning a caller that returns a Canister Id.
    pub fn create_canister<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + AsyncCall<Principal> {
        #[derive(Deserialize)]
        struct Out {
            canister_id: Principal,
        }

        self.update_("create_canister")
            .build()
            .map(|result: Out| result.canister_id)
    }

    /// Deletes a canister.
    pub fn delete_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        self.update_("delete_canister")
            .with_arg(In {
                canister_id: canister_id.clone(),
            })
            .build()
    }

    /// Starts a canister.
    pub fn start_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        self.update_("start_canister")
            .with_arg(In {
                canister_id: canister_id.clone(),
            })
            .build()
    }

    /// Stop a canister.
    pub fn stop_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        self.update_("stop_canister")
            .with_arg(In {
                canister_id: canister_id.clone(),
            })
            .build()
    }

    /// Install a canister, with all the arguments necessary for creating the canister.
    pub fn install_code<'canister: 'agent, Arg: CandidType + Sync + Send>(
        canister_id: &Principal,
        mode:
    ) -> impl 'agent + TypedAsyncCall<()> {
        #[derive(candid::CandidType, candid::Deserialize)]
        struct CanisterInstall {
            mode: InstallMode,
            canister_id: Principal,
            wasm_module: Vec<u8>,
            arg: Vec<u8>,
            compute_allocation: Option<u8>,
        }

    }

    /// Creates a CodeInstallCallBuilder.
    pub fn install_code<'canister: 'agent, Arg: CandidType + Sync + Send>(
        canister_id: &Principal,
        mode:
    ) -> impl 'agent + TypedAsyncCall<()> {

    }

}
