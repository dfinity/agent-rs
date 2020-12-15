use crate::call::AsyncCall;
use crate::canister::Argument;
use crate::interfaces::management_canister::MgmtMethod;
use crate::Canister;
use async_trait::async_trait;
use candid::{CandidType, Deserialize, Encode};
use garcon::Waiter;
use ic_agent::export::Principal;
use ic_agent::{AgentError, RequestId};
use std::str::FromStr;

pub use super::attributes::ComputeAllocation;
pub use super::attributes::MemoryAllocation;
use std::convert::From;
use std::convert::TryInto;

#[derive(CandidType, Deserialize)]
pub struct CanisterSettings {
    pub controller: Option<Principal>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
}

pub struct CreateCanisterBuilder<'agent, 'canister: 'agent, T> {
    canister: &'canister Canister<'agent, T>,
    controller: Option<Result<Principal, AgentError>>,
    compute_allocation: Option<Result<ComputeAllocation, AgentError>>,
    memory_allocation: Option<Result<MemoryAllocation, AgentError>>,
    is_provisional_create: bool,
    amount: Option<u64>,
}

impl<'agent, 'canister: 'agent, T> CreateCanisterBuilder<'agent, 'canister, T> {
    /// Create an CreateCanister builder, which is also an AsyncCall implementation.
    pub fn builder(canister: &'canister Canister<'agent, T>) -> Self {
        Self {
            canister,
            controller: None,
            compute_allocation: None,
            memory_allocation: None,
            is_provisional_create: false,
            amount: None,
        }
    }

    /// Until developers can convert real ICP tokens to provision a new canister with cycles,
    /// the system provides the provisional_create_canister_with_cycles method.
    /// It behaves as create_canister, but initializes the canister’s balance with amount fresh cycles
    /// (using MAX_CANISTER_BALANCE if amount = null, else capping the balance at MAX_CANISTER_BALANCE).
    /// Cycles added to this call via ic0.call_cycles_add are returned to the caller.
    /// This method is only available in local development instances, and will be removed in the future.
    #[allow(clippy::wrong_self_convention)]
    pub fn as_provisional_create_with_amount(self, amount: Option<u64>) -> Self {
        Self {
            is_provisional_create: true,
            amount,
            ..self
        }
    }

    /// Pass in an optional controller for the canister. If this is [None],
    /// it will revert the controller to default.
    pub fn with_optional_controller<C, E>(self, controller: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        Self {
            controller: controller.map(|ca| {
                ca.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
    }

    /// Pass in a designated controller for the canister.
    pub fn with_controller<C, E>(self, controller: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        self.with_optional_controller(Some(controller))
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

    /// Create an [AsyncCall] implementation that, when called, will create a
    /// canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<(Principal,)>, AgentError> {
        let controller = match self.controller {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(x),
            None => None,
        };
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

        #[derive(Deserialize)]
        struct Out {
            canister_id: Principal,
        }

        let (method, arg) = if self.is_provisional_create {
            #[derive(CandidType)]
            struct In {
                amount: Option<candid::Nat>,
                settings: CanisterSettings,
            }
            let mut arg = Argument::default();
            let in_arg = In {
                amount: self.amount.map(candid::Nat::from),
                settings: CanisterSettings {
                    controller,
                    compute_allocation,
                    memory_allocation,
                },
            };
            arg.set_raw_arg(
                Encode!(&in_arg).map_err(|err| AgentError::CandidError(Box::new(err)))?,
            );
            (
                MgmtMethod::ProvisionalCreateCanisterWithCycles.as_ref(),
                arg.serialize()?,
            )
        } else {
            let mut arg = Argument::default();
            arg.set_raw_arg(
                Encode!(&CanisterSettings {
                    controller,
                    compute_allocation,
                    memory_allocation,
                })
                .map_err(|err| AgentError::CandidError(Box::new(err)))?,
            );
            (MgmtMethod::CreateCanister.as_ref(), arg.serialize()?)
        };

        Ok(self
            .canister
            .update_(method)
            .with_arg(arg)
            .build()
            .map(|result: (Out,)| (result.0.canister_id,)))
    }

    /// Make a call. This is equivalent to the [AsyncCall::call].
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [AsyncCall::call_and_wait].
    pub async fn call_and_wait<W>(self, waiter: W) -> Result<(Principal,), AgentError>
    where
        W: Waiter,
    {
        self.build()?.call_and_wait(waiter).await
    }
}

#[async_trait]
impl<'agent, 'canister: 'agent, T: Sync> AsyncCall<(Principal,)>
    for CreateCanisterBuilder<'agent, 'canister, T>
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait<W>(self, waiter: W) -> Result<(Principal,), AgentError>
    where
        W: Waiter,
    {
        self.build()?.call_and_wait(waiter).await
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

    /// Create an [AsyncCall] implementation that, when called, will install the
    /// canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<()>, AgentError> {
        Ok(self
            .canister
            .update_("install_code")
            .with_arg(CanisterInstall {
                mode: self.mode.unwrap_or(InstallMode::Install),
                canister_id: self.canister_id.clone(),
                wasm_module: self.wasm.to_owned(),
                arg: self.arg.serialize()?,
            })
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

pub struct UpdateCanisterBuilder<'agent, 'canister: 'agent, T> {
    canister: &'canister Canister<'agent, T>,
    canister_id: Principal,
    controller: Option<Result<Principal, AgentError>>,
    compute_allocation: Option<Result<ComputeAllocation, AgentError>>,
    memory_allocation: Option<Result<MemoryAllocation, AgentError>>,
}

impl<'agent, 'canister: 'agent, T> UpdateCanisterBuilder<'agent, 'canister, T> {
    /// Create an UpdateCanister builder, which is also an AsyncCall implementation.
    pub fn builder(canister: &'canister Canister<'agent, T>, canister_id: &Principal) -> Self {
        Self {
            canister,
            canister_id: canister_id.clone(),
            controller: None,
            compute_allocation: None,
            memory_allocation: None,
        }
    }

    /// Pass in an optional controller for the canister. If this is [None],
    /// it will revert the controller to default.
    pub fn with_optional_controller<C, E>(self, controller: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        Self {
            controller: controller.map(|ca| {
                ca.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
    }

    /// Pass in a designated controller for the canister.
    pub fn with_controller<C, E>(self, controller: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        self.with_optional_controller(Some(controller))
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

    /// Create an [AsyncCall] implementation that, when called, will update a
    /// canisters settings.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<()>, AgentError> {
        #[derive(candid::CandidType)]
        struct In {
            canister_id: Principal,
            settings: CanisterSettings,
        }

        let controller = match self.controller {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(x),
            None => None,
        };
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
            .update_(MgmtMethod::UpdateCanisterSettings.as_ref())
            .with_arg(In {
                canister_id: self.canister_id.clone(),
                settings: CanisterSettings {
                    controller,
                    compute_allocation,
                    memory_allocation,
                },
            })
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
    for UpdateCanisterBuilder<'agent, 'canister, T>
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
