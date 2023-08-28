//! Builder interfaces for some method calls of the management canister.

use crate::{
    call::AsyncCall, canister::Argument, interfaces::management_canister::MgmtMethod, Canister,
};
use async_trait::async_trait;
use candid::{CandidType, Deserialize, Nat};
use ic_agent::{export::Principal, AgentError, RequestId};
use std::str::FromStr;

pub use super::attributes::{ComputeAllocation, FreezingThreshold, MemoryAllocation};
use std::convert::{From, TryInto};

/// The set of possible canister settings. Similar to [`DefiniteCanisterSettings`](super::DefiniteCanisterSettings),
/// but all the fields are optional.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct CanisterSettings {
    /// The set of canister controllers. Controllers can update the canister via the management canister.
    ///
    /// If unspecified and a canister is being created with these settings, defaults to the caller.
    pub controllers: Option<Vec<Principal>>,
    /// The allocation percentage (between 0 and 100 inclusive) for *guaranteed* compute capacity.
    ///
    /// The settings update will be rejected if the IC can't commit to allocating this much compupte capacity.
    ///
    /// If unspecified and a canister is being created with these settings, defaults to 0, i.e. best-effort.
    pub compute_allocation: Option<Nat>,
    /// The allocation, in bytes (up to 256 TiB) that the canister is allowed to use for storage.
    ///
    /// The settings update will be rejected if the IC can't commit to allocating this much storage.
    ///
    /// If unspecified and a canister is being created with these settings, defaults to 0, i.e. best-effort.
    pub memory_allocation: Option<Nat>,

    /// The IC will freeze a canister protectively if it will run out of cycles before this amount of time, in seconds (up to `u64::MAX`), has passed.
    ///
    /// If unspecified and a canister is being created with these settings, defaults to 2592000, i.e. ~30 days.
    pub freezing_threshold: Option<Nat>,
}

/// A builder for a `create_canister` call.
#[derive(Debug)]
pub struct CreateCanisterBuilder<'agent, 'canister: 'agent> {
    canister: &'canister Canister<'agent>,
    effective_canister_id: Principal,
    controllers: Option<Result<Vec<Principal>, AgentError>>,
    compute_allocation: Option<Result<ComputeAllocation, AgentError>>,
    memory_allocation: Option<Result<MemoryAllocation, AgentError>>,
    freezing_threshold: Option<Result<FreezingThreshold, AgentError>>,
    is_provisional_create: bool,
    amount: Option<u128>,
    specified_id: Option<Principal>,
}

impl<'agent, 'canister: 'agent> CreateCanisterBuilder<'agent, 'canister> {
    /// Create an CreateCanister builder, which is also an AsyncCall implementation.
    pub fn builder(canister: &'canister Canister<'agent>) -> Self {
        Self {
            canister,
            effective_canister_id: Principal::management_canister(),
            controllers: None,
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
            is_provisional_create: false,
            amount: None,
            specified_id: None,
        }
    }

    /// Until developers can convert real ICP tokens to provision a new canister with cycles,
    /// the system provides the provisional_create_canister_with_cycles method.
    /// It behaves as create_canister, but initializes the canister’s balance with amount fresh cycles
    /// (using MAX_CANISTER_BALANCE if amount = null, else capping the balance at MAX_CANISTER_BALANCE).
    /// Cycles added to this call via ic0.call_cycles_add are returned to the caller.
    /// This method is only available in local development instances, and will be removed in the future.
    #[allow(clippy::wrong_self_convention)]
    pub fn as_provisional_create_with_amount(self, amount: Option<u128>) -> Self {
        Self {
            is_provisional_create: true,
            amount,
            ..self
        }
    }

    /// Specify the canister id.
    ///
    /// The effective_canister_id will also be set with the same value so that ic-ref can determine
    /// the target subnet of this request. The replica implementation ignores it.
    pub fn as_provisional_create_with_specified_id(self, specified_id: Principal) -> Self {
        Self {
            is_provisional_create: true,
            specified_id: Some(specified_id),
            effective_canister_id: specified_id,
            ..self
        }
    }

    /// Pass in an effective canister id for the update call.
    pub fn with_effective_canister_id<C, E>(self, effective_canister_id: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        match effective_canister_id.try_into() {
            Ok(effective_canister_id) => Self {
                effective_canister_id,
                ..self
            },
            Err(_) => self,
        }
    }

    /// Pass in an optional controller for the canister. If this is [None],
    /// it will revert the controller to default.
    pub fn with_optional_controller<C, E>(self, controller: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        let controller_to_add: Option<Result<Principal, _>> = controller.map(|ca| {
            ca.try_into()
                .map_err(|e| AgentError::MessageError(format!("{}", e)))
        });
        let controllers: Option<Result<Vec<Principal>, _>> =
            match (controller_to_add, self.controllers) {
                (_, Some(Err(sticky))) => Some(Err(sticky)),
                (Some(Err(e)), _) => Some(Err(e)),
                (None, _) => None,
                (Some(Ok(controller)), Some(Ok(controllers))) => {
                    let mut controllers = controllers;
                    controllers.push(controller);
                    Some(Ok(controllers))
                }
                (Some(Ok(controller)), None) => Some(Ok(vec![controller])),
            };
        Self {
            controllers,
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

    /// Pass in a freezing threshold optional value for the canister. If this is [None],
    /// it will revert the freezing threshold to default.
    pub fn with_optional_freezing_threshold<E, C>(self, freezing_threshold: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<FreezingThreshold, Error = E>,
    {
        Self {
            freezing_threshold: freezing_threshold.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
    }

    /// Pass in a freezing threshold value for the canister.
    pub fn with_freezing_threshold<C, E>(self, freezing_threshold: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<FreezingThreshold, Error = E>,
    {
        self.with_optional_freezing_threshold(Some(freezing_threshold))
    }

    /// Create an [AsyncCall] implementation that, when called, will create a
    /// canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<(Principal,)>, AgentError> {
        let controllers = match self.controllers {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(x),
            None => None,
        };
        let compute_allocation = match self.compute_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u8::from(x))),
            None => None,
        };
        let memory_allocation = match self.memory_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let freezing_threshold = match self.freezing_threshold {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };

        #[derive(Deserialize, CandidType)]
        struct Out {
            canister_id: Principal,
        }

        let async_builder = if self.is_provisional_create {
            #[derive(CandidType)]
            struct In {
                amount: Option<Nat>,
                settings: CanisterSettings,
                specified_id: Option<Principal>,
            }
            let in_arg = In {
                amount: self.amount.map(Nat::from),
                settings: CanisterSettings {
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                },
                specified_id: self.specified_id,
            };
            self.canister
                .update_(MgmtMethod::ProvisionalCreateCanisterWithCycles.as_ref())
                .with_arg(in_arg)
                .with_effective_canister_id(self.effective_canister_id)
        } else {
            self.canister
                .update_(MgmtMethod::CreateCanister.as_ref())
                .with_arg(CanisterSettings {
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                })
                .with_effective_canister_id(self.effective_canister_id)
        };

        Ok(async_builder
            .build()
            .map(|result: (Out,)| (result.0.canister_id,)))
    }

    /// Make a call. This is equivalent to the [AsyncCall::call].
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [AsyncCall::call_and_wait].
    pub async fn call_and_wait(self) -> Result<(Principal,), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall<(Principal,)>
    for CreateCanisterBuilder<'agent, 'canister>
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait(self) -> Result<(Principal,), AgentError> {
        self.build()?.call_and_wait().await
    }
}

/// The install mode of the canister to install. If a canister is already installed,
/// using [InstallMode::Install] will be an error. [InstallMode::Reinstall] overwrites
/// the module, and [InstallMode::Upgrade] performs an Upgrade step.
#[derive(Debug, Copy, Clone, CandidType, Deserialize, Eq, PartialEq)]
pub enum InstallMode {
    /// Install the module into the empty canister.
    #[serde(rename = "install")]
    Install,
    /// Overwrite the canister with this module.
    #[serde(rename = "reinstall")]
    Reinstall,
    /// Upgrade the canister with this module.
    #[serde(rename = "upgrade")]
    Upgrade,
}

/// A prepared call to `install_code`.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct CanisterInstall {
    /// The installation mode to install the module with.
    pub mode: InstallMode,
    /// The ID of the canister to install the module into.
    pub canister_id: Principal,
    /// The WebAssembly code blob to install.
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
    /// The encoded argument to pass to the module's constructor.
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

/// A builder for an `install_code` call.
#[derive(Debug)]
pub struct InstallCodeBuilder<'agent, 'canister: 'agent> {
    canister: &'canister Canister<'agent>,
    canister_id: Principal,
    wasm: &'canister [u8],
    arg: Argument,
    mode: Option<InstallMode>,
}

impl<'agent, 'canister: 'agent> InstallCodeBuilder<'agent, 'canister> {
    /// Create an InstallCode builder, which is also an AsyncCall implementation.
    pub fn builder(
        canister: &'canister Canister<'agent>,
        canister_id: &Principal,
        wasm: &'canister [u8],
    ) -> Self {
        Self {
            canister,
            canister_id: *canister_id,
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
    ) -> InstallCodeBuilder<'agent, 'canister> {
        self.arg.set_idl_arg(arg);
        self
    }

    /// Override the argument passed in to the canister with raw bytes.
    pub fn with_raw_arg(mut self, arg: Vec<u8>) -> InstallCodeBuilder<'agent, 'canister> {
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
            .update_(MgmtMethod::InstallCode.as_ref())
            .with_arg(CanisterInstall {
                mode: self.mode.unwrap_or(InstallMode::Install),
                canister_id: self.canister_id,
                wasm_module: self.wasm.to_owned(),
                arg: self.arg.serialize()?,
            })
            .with_effective_canister_id(self.canister_id)
            .build())
    }

    /// Make a call. This is equivalent to the [AsyncCall::call].
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [AsyncCall::call_and_wait].
    pub async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall<()> for InstallCodeBuilder<'agent, 'canister> {
    async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

/// A builder for an `update_settings` call.
#[derive(Debug)]
pub struct UpdateCanisterBuilder<'agent, 'canister: 'agent> {
    canister: &'canister Canister<'agent>,
    canister_id: Principal,
    controllers: Option<Result<Vec<Principal>, AgentError>>,
    compute_allocation: Option<Result<ComputeAllocation, AgentError>>,
    memory_allocation: Option<Result<MemoryAllocation, AgentError>>,
    freezing_threshold: Option<Result<FreezingThreshold, AgentError>>,
}

impl<'agent, 'canister: 'agent> UpdateCanisterBuilder<'agent, 'canister> {
    /// Create an UpdateCanister builder, which is also an AsyncCall implementation.
    pub fn builder(canister: &'canister Canister<'agent>, canister_id: &Principal) -> Self {
        Self {
            canister,
            canister_id: *canister_id,
            controllers: None,
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
        }
    }

    /// Pass in an optional controller for the canister. If this is [None],
    /// it will revert the controller to default.
    pub fn with_optional_controller<C, E>(self, controller: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        let controller_to_add: Option<Result<Principal, _>> = controller.map(|ca| {
            ca.try_into()
                .map_err(|e| AgentError::MessageError(format!("{}", e)))
        });
        let controllers: Option<Result<Vec<Principal>, _>> =
            match (controller_to_add, self.controllers) {
                (_, Some(Err(sticky))) => Some(Err(sticky)),
                (Some(Err(e)), _) => Some(Err(e)),
                (None, _) => None,
                (Some(Ok(controller)), Some(Ok(controllers))) => {
                    let mut controllers = controllers;
                    controllers.push(controller);
                    Some(Ok(controllers))
                }
                (Some(Ok(controller)), None) => Some(Ok(vec![controller])),
            };

        Self {
            controllers,
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

    /// Pass in a freezing threshold optional value for the canister. If this is [None],
    /// it will revert the freezing threshold to default.
    pub fn with_optional_freezing_threshold<E, C>(self, freezing_threshold: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<FreezingThreshold, Error = E>,
    {
        Self {
            freezing_threshold: freezing_threshold.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
    }

    /// Pass in a freezing threshold value for the canister.
    pub fn with_freezing_threshold<C, E>(self, freezing_threshold: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<FreezingThreshold, Error = E>,
    {
        self.with_optional_freezing_threshold(Some(freezing_threshold))
    }

    /// Create an [AsyncCall] implementation that, when called, will update a
    /// canisters settings.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<()>, AgentError> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
            settings: CanisterSettings,
        }

        let controllers = match self.controllers {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(x),
            None => None,
        };
        let compute_allocation = match self.compute_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u8::from(x))),
            None => None,
        };
        let memory_allocation = match self.memory_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let freezing_threshold = match self.freezing_threshold {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };

        Ok(self
            .canister
            .update_(MgmtMethod::UpdateSettings.as_ref())
            .with_arg(In {
                canister_id: self.canister_id,
                settings: CanisterSettings {
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                },
            })
            .with_effective_canister_id(self.canister_id)
            .build())
    }

    /// Make a call. This is equivalent to the [AsyncCall::call].
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [AsyncCall::call_and_wait].
    pub async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall<()> for UpdateCanisterBuilder<'agent, 'canister> {
    async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}
