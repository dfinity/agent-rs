use crate::call::AsyncCall;
use crate::canister::{Argument, CanisterBuilder};
use crate::Canister;
use async_trait::async_trait;
use candid::{CandidType, Deserialize};
use delay::Waiter;
use ic_agent::export::Principal;
use ic_agent::{Agent, AgentError, RequestId};
use std::convert::AsRef;
use std::fmt::Debug;
use std::str::FromStr;
use strum_macros::{AsRefStr, EnumString};

pub mod attributes;
pub use attributes::ComputeAllocation;
pub use attributes::MemoryAllocation;
use std::convert::From;
use std::convert::TryInto;

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub struct ManagementCanister;

#[derive(AsRefStr, Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum MgmtMethod {
    CreateCanister,
    InstallCode,
    SetController,
    StartCanister,
    StopCanister,
    CanisterStatus,
    DeleteCanister,
    DepositCycles,
    RawRand,
    ProvisionalCreateCanisterWithCycles,
    ProvisionalTopUpCanister,
}

impl ManagementCanister {
    /// Create an instance of a [Canister] implementing the ManagementCanister interface
    /// and pointing to the right Canister ID.
    pub fn create(agent: &Agent) -> Canister<ManagementCanister> {
        Canister::builder()
            .with_agent(agent)
            .with_canister_id(Principal::management_canister())
            .with_interface(ManagementCanister)
            .build()
            .unwrap()
    }

    /// Creating a CanisterBuilder with the right interface and Canister Id. This can
    /// be useful, for example, for providing additional Builder information.
    pub fn with_agent(agent: &Agent) -> CanisterBuilder<ManagementCanister> {
        Canister::builder()
            .with_agent(agent)
            .with_canister_id(Principal::management_canister())
            .with_interface(ManagementCanister)
    }
}

/// The complete canister status information of a canister. This includes
/// the CanisterStatus, a hash of the module installed on the canister (None if nothing installed),
/// the contoller of the canister, the canisters memory size, and its balance in cycles.
#[derive(Clone, Debug, Deserialize)]
pub struct StatusCallResult {
    pub status: CanisterStatus,
    pub module_hash: Option<Vec<u8>>,
    pub controller: Principal,
    pub memory_size: candid::Nat,
    pub cycles: candid::Nat,
}

impl std::fmt::Display for StatusCallResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// The status of a Canister, whether it's running, in the process of stopping, or
/// stopped.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
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

/// The install mode of the canister to install. If a canister is already installed,
/// using [InstallMode::Install] will be an error. [InstallMode::Reinstall] overwrites
/// the module, and [InstallMode::Upgrade] performs an Upgrade step.
#[derive(Copy, Clone, CandidType, Deserialize, Eq, PartialEq)]
pub enum InstallMode {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade,
}

#[derive(candid::CandidType, Deserialize)]
pub struct CanisterInstall {
    pub mode: InstallMode,
    pub canister_id: Principal,
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
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

pub struct InstallCodeBuilder<'agent, 'canister: 'agent, T> {
    canister: &'canister Canister<'agent, T>,
    canister_id: Principal,
    wasm: &'canister [u8],
    arg: Argument,
    mode: Option<InstallMode>,
    compute_allocation: Option<Result<ComputeAllocation, AgentError>>,
    memory_allocation: Option<Result<MemoryAllocation, AgentError>>,
}

impl<'agent, 'canister: 'agent, T> InstallCodeBuilder<'agent, 'canister, T> {
    /// Create an InstallCode builder, which is also an AsyncCall implementation.
    pub fn builder(
        canister: &'canister Canister<'agent, T>,
        canister_id: &Principal,
        wasm: &'canister [u8],
    ) -> Self {
        Self {
            canister,
            canister_id: canister_id.clone(),
            wasm,
            arg: Default::default(),
            mode: None,
            compute_allocation: None,
            memory_allocation: None,
        }
    }

    /// Add an argument to the installation, which will be passed to the init
    /// method of the canister.
    pub fn with_arg<Argument: CandidType + Sync + Send>(
        mut self,
        arg: Argument,
    ) -> InstallCodeBuilder<'agent, 'canister, T> {
        self.arg.push_idl_arg(arg);
        self
    }

    /// Override the argument passed in to the canister with raw bytes.
    pub fn with_raw_arg(mut self, arg: Vec<u8>) -> InstallCodeBuilder<'agent, 'canister, T> {
        self.arg.set_raw_arg(arg);
        self
    }

    /// Pass in the [InstallMode].
    pub fn with_mode(self, mode: InstallMode) -> Self {
        Self {
            mode: Some(mode),
            ..self
        }
    }

    /// Pass in a compute allocation optional value for the canister. If this is [None],
    /// it will revert the compute allocation to default.
    pub fn with_optional_compute_allocation<C, E>(self, compute_allocation: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ComputeAllocation, Error = E>,
    {
        Self {
            compute_allocation: compute_allocation.map(|ca| {
                ca.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
    }

    /// Pass in a compute allocation value for the canister.
    pub fn with_compute_allocation<C, E>(self, compute_allocation: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ComputeAllocation, Error = E>,
    {
        self.with_optional_compute_allocation(Some(compute_allocation))
    }

    /// Pass in a memory allocation optional value for the canister. If this is [None],
    /// it will revert the memory allocation to default.
    pub fn with_optional_memory_allocation<E, C>(self, memory_allocation: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<MemoryAllocation, Error = E>,
    {
        Self {
            memory_allocation: memory_allocation.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
    }

    /// Pass in a memory allocation value for the canister.
    pub fn with_memory_allocation<C, E>(self, memory_allocation: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<MemoryAllocation, Error = E>,
    {
        self.with_optional_memory_allocation(Some(memory_allocation))
    }

    /// Create an [AsyncCall] implementation that, when called, will install the
    /// canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<()>, AgentError> {
        let compute_allocation = match self.compute_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(candid::Nat::from(u8::from(x))),
            None => None,
        };
        let memory_allocation = match self.memory_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(candid::Nat::from(u64::from(x))),
            None => None,
        };

        Ok(self
            .canister
            .update_(MgmtMethod::InstallCode.as_ref())
            .with_arg(CanisterInstall {
                mode: self.mode.unwrap_or(InstallMode::Install),
                canister_id: self.canister_id.clone(),
                wasm_module: self.wasm.to_owned(),
                arg: self.arg.serialize()?,
                compute_allocation,
                memory_allocation,
            })
            .with_effective_canister_id(self.canister_id)
            .build())
    }

    /// Make a call. This is equivalent to the [AsyncCall::call].
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [AsyncCall::call_and_wait].
    pub async fn call_and_wait<W>(self, waiter: W) -> Result<(), AgentError>
    where
        W: Waiter,
    {
        self.build()?.call_and_wait(waiter).await
    }
}

#[async_trait]
impl<'agent, 'canister: 'agent, T: Sync> AsyncCall<()>
    for InstallCodeBuilder<'agent, 'canister, T>
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait<W>(self, waiter: W) -> Result<(), AgentError>
    where
        W: Waiter,
    {
        self.build()?.call_and_wait(waiter).await
    }
}

impl<'agent> Canister<'agent, ManagementCanister> {
    /// Get the status of a canister.
    pub fn canister_status<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<(StatusCallResult,)> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        self.update_(MgmtMethod::CanisterStatus.as_ref())
            .with_arg(In {
                canister_id: canister_id.clone(),
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
            .map(|result: (StatusCallResult,)| (result.0,))
    }

    /// Create a canister, returning a caller that returns a Canister Id.
    pub fn create_canister<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + AsyncCall<(Principal,)> {
        #[derive(Deserialize)]
        struct Out {
            canister_id: Principal,
        }

        self.update_(MgmtMethod::CreateCanister.as_ref())
            .build()
            .map(|result: (Out,)| (result.0.canister_id,))
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

        self.update_(MgmtMethod::DepositCycles.as_ref())
            .with_arg(Argument {
                canister_id: canister_id.clone(),
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

        self.update_(MgmtMethod::DeleteCanister.as_ref())
            .with_arg(Argument {
                canister_id: canister_id.clone(),
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Until developers can convert real ICP tokens to provision a new canister with cycles,
    /// the system provides the provisional_create_canister_with_cycles method.
    /// It behaves as create_canister, but initializes the canister’s balance with amount fresh cycles
    /// (using MAX_CANISTER_BALANCE if amount = null, else capping the balance at MAX_CANISTER_BALANCE).
    /// Cycles added to this call via ic0.call_cycles_add are returned to the caller.
    /// This method is only available in local development instances, and will be removed in the future.
    pub fn provisional_create_canister_with_cycles<'canister: 'agent>(
        &'canister self,
        amount: Option<u64>,
    ) -> impl 'agent + AsyncCall<(Principal,)> {
        #[derive(CandidType)]
        struct Argument {
            amount: Option<candid::Nat>,
        }

        #[derive(Deserialize)]
        struct Out {
            canister_id: Principal,
        }

        self.update_(MgmtMethod::ProvisionalCreateCanisterWithCycles.as_ref())
            .with_arg(Argument {
                amount: amount.map(candid::Nat::from),
            })
            .with_effective_canister_id(Principal::management_canister())
            .build()
            .map(|result: (Out,)| (result.0.canister_id,))
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

        self.update_(MgmtMethod::ProvisionalTopUpCanister.as_ref())
            .with_arg(Argument {
                canister_id: canister_id.clone(),
                amount,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// This method takes no input and returns 32 pseudo-random bytes to the caller.
    /// The return value is unknown to any part of the IC at time of the submission of this call.
    /// A new return value is generated for each call to this method.
    pub fn raw_rand<'canister: 'agent>(&'canister self) -> impl 'agent + AsyncCall<(Vec<u8>,)> {
        self.update_(MgmtMethod::RawRand.as_ref())
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

        self.update_(MgmtMethod::StartCanister.as_ref())
            .with_arg(Argument {
                canister_id: canister_id.clone(),
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

        self.update_(MgmtMethod::StopCanister.as_ref())
            .with_arg(Argument {
                canister_id: canister_id.clone(),
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Install a canister, with all the arguments necessary for creating the canister.
    pub fn install_code<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
        wasm: &'canister [u8],
    ) -> InstallCodeBuilder<'agent, 'canister, ManagementCanister> {
        InstallCodeBuilder::builder(self, canister_id, wasm)
    }

    /// Set controller for a canister.
    pub fn set_controller<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
        new_controller: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
            new_controller: Principal,
        }

        self.update_(MgmtMethod::SetController.as_ref())
            .with_arg(Argument {
                canister_id: canister_id.clone(),
                new_controller: new_controller.clone(),
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }
}
