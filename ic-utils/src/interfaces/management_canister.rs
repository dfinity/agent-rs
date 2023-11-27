//! The canister interface for the IC management canister. See the [specification][spec] for full documentation of the interface.
//!
//! [spec]: https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-management-canister

use crate::{call::AsyncCall, Canister};
use candid::{CandidType, Deserialize, Nat};
use ic_agent::{export::Principal, Agent};
use std::{convert::AsRef, fmt::Debug, ops::Deref};
use strum_macros::{AsRefStr, EnumString};

pub mod attributes;
pub mod builders;
pub use builders::{CreateCanisterBuilder, InstallCodeBuilder, UpdateCanisterBuilder};

/// The IC management canister.
#[derive(Debug, Clone)]
pub struct ManagementCanister<'agent>(Canister<'agent>);

impl<'agent> Deref for ManagementCanister<'agent> {
    type Target = Canister<'agent>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// All the known methods of the management canister.
#[derive(AsRefStr, Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum MgmtMethod {
    // FIXME when rust-lang/rust#85960 is resolved, update these to links.
    /// See `Canister::<ManagementCanister>::create_canister`.
    CreateCanister,
    /// See `Canister::<ManagementCanister>::install_code`.
    InstallCode,
    /// See `Canister::<ManagementCanister>::start_canister`.
    StartCanister,
    /// See `Canister::<ManagementCanister>::stop_canister`.
    StopCanister,
    /// See `Canister::<ManagementCanister>::canister_status`.
    CanisterStatus,
    /// See `Canister::<ManagementCanister>::delete_canister`.
    DeleteCanister,
    /// See `Canister::<ManagementCanister>::deposit_cycles`.
    DepositCycles,
    /// See `Canister::<ManagementCanister>::raw_rand`.
    RawRand,
    /// See `Canister::<ManagementCanister>::provisional_create_canister_with_cycles`.
    ProvisionalCreateCanisterWithCycles,
    /// See `Canister::<ManagementCanister>::provisional_top_up_canister`.
    ProvisionalTopUpCanister,
    /// See `Canister::<ManagementCanister>::uninstall_code`.
    UninstallCode,
    /// See `Canister::<ManagementCanister>::update_settings`.
    UpdateSettings,
}

impl<'agent> ManagementCanister<'agent> {
    /// Create an instance of a `ManagementCanister` interface pointing to the specified Canister ID.
    pub fn create(agent: &'agent Agent) -> Self {
        Self(
            Canister::builder()
                .with_agent(agent)
                .with_canister_id(Principal::management_canister())
                .build()
                .unwrap(),
        )
    }

    /// Create a `ManagementCanister` interface from an existing canister object.
    pub fn from_canister(canister: Canister<'agent>) -> Self {
        Self(canister)
    }
}

/// The complete canister status information of a canister. This includes
/// the CanisterStatus, a hash of the module installed on the canister (None if nothing installed),
/// the controller of the canister, the canister's memory size, and its balance in cycles.
#[derive(Clone, Debug, Deserialize, CandidType)]
pub struct StatusCallResult {
    /// The status of the canister.
    pub status: CanisterStatus,
    /// The canister's settings.
    pub settings: DefiniteCanisterSettings,
    /// The SHA-256 hash of the canister's installed code, if any.
    pub module_hash: Option<Vec<u8>>,
    /// The total size, in bytes, of the memory the canister is using.
    pub memory_size: Nat,
    /// The canister's cycle balance.
    pub cycles: Nat,
    /// The canister's reserved cycles balance.
    pub reserved_cycles: Nat,
    /// The cycles burned by the canister in one day for its resource usage
    /// (compute and memory allocation and memory usage).
    pub idle_cycles_burned_per_day: Nat,
    /// Additional information relating to query calls.
    pub query_stats: QueryStats,
}

/// Statistics relating to query calls.
#[derive(Clone, Debug, Deserialize, CandidType)]
pub struct QueryStats {
    /// The total number of query calls this canister has performed.
    pub num_calls_total: Nat,
    /// The total number of instructions this canister has executed during query calls.
    pub num_instructions_total: Nat,
    /// The total number of bytes in request payloads sent to this canister's query calls.
    pub request_payload_bytes_total: Nat,
    /// The total number of bytes in response payloads returned from this canister's query calls.
    pub response_payload_bytes_total: Nat,
}

/// The concrete settings of a canister.
#[derive(Clone, Debug, Deserialize, CandidType)]
pub struct DefiniteCanisterSettings {
    /// The set of canister controllers. Controllers can update the canister via the management canister.
    pub controllers: Vec<Principal>,
    /// The allocation percentage (between 0 and 100 inclusive) for *guaranteed* compute capacity.
    pub compute_allocation: Nat,
    /// The allocation, in bytes (up to 256 TiB) that the canister is allowed to use for storage.
    pub memory_allocation: Nat,
    /// The IC will freeze a canister protectively if it will likely run out of cycles before this amount of time, in seconds (up to `u64::MAX`), has passed.
    pub freezing_threshold: Nat,
    /// The upper limit of the canister's reserved cycles balance.
    pub reserved_cycles_limit: Option<Nat>,
}

impl std::fmt::Display for StatusCallResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// The status of a Canister, whether it's running, in the process of stopping, or
/// stopped.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, CandidType)]
pub enum CanisterStatus {
    /// The canister is currently running.
    #[serde(rename = "running")]
    Running,
    /// The canister is in the process of stopping.
    #[serde(rename = "stopping")]
    Stopping,
    /// The canister is stopped.
    #[serde(rename = "stopped")]
    Stopped,
}

impl std::fmt::Display for CanisterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl<'agent> ManagementCanister<'agent> {
    /// Get the status of a canister.
    pub fn canister_status<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<(StatusCallResult,)> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        self.update(MgmtMethod::CanisterStatus.as_ref())
            .with_arg(In {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
            .map(|result: (StatusCallResult,)| (result.0,))
    }

    /// Create a canister.
    pub fn create_canister<'canister: 'agent>(
        &'canister self,
    ) -> CreateCanisterBuilder<'agent, 'canister> {
        CreateCanisterBuilder::builder(self)
    }

    /// This method deposits the cycles included in this call into the specified canister.
    /// Only the controller of the canister can deposit cycles.
    pub fn deposit_cycles<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update(MgmtMethod::DepositCycles.as_ref())
            .with_arg(Argument {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Deletes a canister.
    pub fn delete_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update(MgmtMethod::DeleteCanister.as_ref())
            .with_arg(Argument {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Until developers can convert real ICP tokens to a top up an existing canister,
    /// the system provides the provisional_top_up_canister method.
    /// It adds amount cycles to the balance of canister identified by amount
    /// (implicitly capping it at MAX_CANISTER_BALANCE).
    pub fn provisional_top_up_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
        amount: u64,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
            amount: u64,
        }

        self.update(MgmtMethod::ProvisionalTopUpCanister.as_ref())
            .with_arg(Argument {
                canister_id: *canister_id,
                amount,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// This method takes no input and returns 32 pseudo-random bytes to the caller.
    /// The return value is unknown to any part of the IC at time of the submission of this call.
    /// A new return value is generated for each call to this method.
    pub fn raw_rand<'canister: 'agent>(&'canister self) -> impl 'agent + AsyncCall<(Vec<u8>,)> {
        self.update(MgmtMethod::RawRand.as_ref())
            .build()
            .map(|result: (Vec<u8>,)| (result.0,))
    }

    /// Starts a canister.
    pub fn start_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update(MgmtMethod::StartCanister.as_ref())
            .with_arg(Argument {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Stop a canister.
    pub fn stop_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update(MgmtMethod::StopCanister.as_ref())
            .with_arg(Argument {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// This method removes a canister’s code and state, making the canister empty again.
    /// Only the controller of the canister can uninstall code.
    /// Uninstalling a canister’s code will reject all calls that the canister has not yet responded to,
    /// and drop the canister’s code and state.
    /// Outstanding responses to the canister will not be processed, even if they arrive after code has been installed again.
    /// The canister is now empty. In particular, any incoming or queued calls will be rejected.
    //// A canister after uninstalling retains its cycles balance, controller, status, and allocations.
    pub fn uninstall_code<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update(MgmtMethod::UninstallCode.as_ref())
            .with_arg(Argument {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Install a canister, with all the arguments necessary for creating the canister.
    pub fn install_code<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
        wasm: &'canister [u8],
    ) -> InstallCodeBuilder<'agent, 'canister> {
        InstallCodeBuilder::builder(self, canister_id, wasm)
    }

    /// Update one or more of a canisters settings (i.e its controller, compute allocation, or memory allocation.)
    pub fn update_settings<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> UpdateCanisterBuilder<'agent, 'canister> {
        UpdateCanisterBuilder::builder(self, canister_id)
    }
}
