//! Builder interfaces for some method calls of the management canister.

#[doc(inline)]
pub use super::attributes::{
    ComputeAllocation, FreezingThreshold, MemoryAllocation, ReservedCyclesLimit,
};
use super::{ChunkHash, ManagementCanister};
use crate::{
    call::AsyncCall, canister::Argument, interfaces::management_canister::MgmtMethod, Canister,
};
use async_trait::async_trait;
use candid::utils::ArgumentEncoder;
use candid::{CandidType, Deserialize, Nat};
use futures_util::future::BoxFuture;
use futures_util::{
    future::ready,
    stream::{self, FuturesUnordered},
    FutureExt, Stream, StreamExt, TryStreamExt,
};
use ic_agent::{export::Principal, AgentError, RequestId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{From, TryInto};
use std::pin::Pin;
use std::str::FromStr;

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

    /// The upper limit of reserved_cycles for the canister.
    ///
    /// Reserved cycles are cycles that the system sets aside for future use by the canister.
    /// If a subnet's storage exceeds 450 GiB, then every time a canister allocates new storage bytes,
    /// the system sets aside some amount of cycles from the main balance of the canister.
    /// These reserved cycles will be used to cover future payments for the newly allocated bytes.
    /// The reserved cycles are not transferable and the amount of reserved cycles depends on how full the subnet is.
    ///
    /// If unspecified and a canister is being created with these settings, defaults to 5T cycles.
    ///
    /// If set to 0, disables the reservation mechanism for the canister.
    /// Doing so will cause the canister to trap when it tries to allocate storage, if the subnet's usage exceeds 450 GiB.
    pub reserved_cycles_limit: Option<Nat>,
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
    reserved_cycles_limit: Option<Result<ReservedCyclesLimit, AgentError>>,
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
            reserved_cycles_limit: None,
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

    /// Pass in a reserved cycles limit value for the canister.
    pub fn with_reserved_cycles_limit<C, E>(self, limit: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ReservedCyclesLimit, Error = E>,
    {
        self.with_optional_reserved_cycles_limit(Some(limit))
    }

    /// Pass in a reserved cycles limit optional value for the canister. If this is [None],
    /// it will create the canister with the default limit.
    pub fn with_optional_reserved_cycles_limit<E, C>(self, limit: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ReservedCyclesLimit, Error = E>,
    {
        Self {
            reserved_cycles_limit: limit.map(|limit| {
                limit
                    .try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
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
        let reserved_cycles_limit = match self.reserved_cycles_limit {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u128::from(x))),
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
                    reserved_cycles_limit,
                },
                specified_id: self.specified_id,
            };
            self.canister
                .update(MgmtMethod::ProvisionalCreateCanisterWithCycles.as_ref())
                .with_arg(in_arg)
                .with_effective_canister_id(self.effective_canister_id)
        } else {
            self.canister
                .update(MgmtMethod::CreateCanister.as_ref())
                .with_arg(CanisterSettings {
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                    reserved_cycles_limit,
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
    Upgrade {
        /// If true, skip a canister's `#[pre_upgrade]` function.
        skip_pre_upgrade: bool,
    },
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
            "upgrade" => Ok(InstallMode::Upgrade {
                skip_pre_upgrade: false,
            }),
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

    /// Set the argument to the installation, which will be passed to the init
    /// method of the canister. Can be called at most once.
    pub fn with_arg<Argument: CandidType>(
        mut self,
        arg: Argument,
    ) -> InstallCodeBuilder<'agent, 'canister> {
        self.arg.set_idl_arg(arg);
        self
    }
    /// Set the argument with multiple arguments as tuple to the installation,
    /// which will be passed to the init method of the canister. Can be called at most once.
    pub fn with_args(mut self, tuple: impl ArgumentEncoder) -> Self {
        assert!(self.arg.0.is_none(), "argument is being set more than once");
        self.arg = Argument::from_candid(tuple);
        self
    }
    /// Set the argument passed in to the canister with raw bytes. Can be called at most once.
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
            .update(MgmtMethod::InstallCode.as_ref())
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

/// A builder for an `install_chunked_code` call.
#[derive(Debug)]
pub struct InstallChunkedCodeBuilder<'agent, 'canister> {
    canister: &'canister Canister<'agent>,
    target_canister: Principal,
    storage_canister: Principal,
    chunk_hashes_list: Vec<ChunkHash>,
    wasm_module_hash: ChunkHash,
    arg: Argument,
    mode: InstallMode,
}

impl<'agent: 'canister, 'canister> InstallChunkedCodeBuilder<'agent, 'canister> {
    /// Create an `InstallChunkedCodeBuilder`.
    pub fn builder(
        canister: &'canister Canister<'agent>,
        target_canister: Principal,
        wasm_module_hash: ChunkHash,
    ) -> Self {
        Self {
            canister,
            target_canister,
            wasm_module_hash,
            storage_canister: target_canister,
            chunk_hashes_list: vec![],
            arg: Argument::new(),
            mode: InstallMode::Install,
        }
    }

    /// Set the chunks to install. These must previously have been set with [`ManagementCanister::upload_chunk`].
    pub fn with_chunk_hashes(mut self, chunk_hashes: Vec<ChunkHash>) -> Self {
        self.chunk_hashes_list = chunk_hashes;
        self
    }

    /// Set the canister to pull uploaded chunks from. By default this is the same as the target canister.
    pub fn with_storage_canister(mut self, storage_canister: Principal) -> Self {
        self.storage_canister = storage_canister;
        self
    }

    /// Set the argument to the installation, which will be passed to the init
    /// method of the canister. Can be called at most once.
    pub fn with_arg(mut self, argument: impl CandidType) -> Self {
        self.arg.set_idl_arg(argument);
        self
    }

    /// Set the argument with multiple arguments as tuple to the installation,
    /// which will be passed to the init method of the canister. Can be called at most once.
    pub fn with_args(mut self, argument: impl ArgumentEncoder) -> Self {
        assert!(self.arg.0.is_none(), "argument is being set more than once");
        self.arg = Argument::from_candid(argument);
        self
    }

    /// Set the argument passed in to the canister with raw bytes. Can be called at most once.
    pub fn with_raw_arg(mut self, argument: Vec<u8>) -> Self {
        self.arg.set_raw_arg(argument);
        self
    }

    /// Set the [`InstallMode`].
    pub fn with_install_mode(mut self, mode: InstallMode) -> Self {
        self.mode = mode;
        self
    }

    /// Create an [`AsyncCall`] implementation that, when called, will install the canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<()>, AgentError> {
        #[derive(CandidType)]
        struct In {
            mode: InstallMode,
            target_canister: Principal,
            storage_canister: Principal,
            chunk_hashes_list: Vec<ChunkHash>,
            wasm_module_hash: ChunkHash,
            arg: Vec<u8>,
            sender_canister_version: Option<u64>,
        }
        let Self {
            mode,
            target_canister,
            storage_canister,
            chunk_hashes_list,
            wasm_module_hash,
            arg,
            ..
        } = self;
        Ok(self
            .canister
            .update(MgmtMethod::InstallChunkedCode.as_ref())
            .with_arg(In {
                mode,
                target_canister,
                storage_canister,
                chunk_hashes_list,
                wasm_module_hash,
                arg: arg.serialize()?,
                sender_canister_version: None,
            })
            .with_effective_canister_id(target_canister)
            .build())
    }

    /// Make the call. This is equivalent to [`AsyncCall::call`].
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    /// Make the call. This is equivalent to [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall<()> for InstallChunkedCodeBuilder<'agent, 'canister> {
    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }
    async fn call_and_wait(self) -> Result<(), AgentError> {
        self.call_and_wait().await
    }
}

/// A builder for a [`ManagementCanister::install`] call. This automatically selects one-shot installation or chunked installation depending on module size.
///
/// # Warnings
///
/// This will clear chunked code storage if chunked installation is used. Do not use with canisters that you are manually uploading chunked code to.
#[derive(Debug)]
pub struct InstallBuilder<'agent, 'canister, 'builder> {
    canister: &'canister ManagementCanister<'agent>,
    canister_id: Principal,
    // more precise lifetimes are used here at risk of annoying the user
    // because `wasm` may be memory-mapped which is tricky to lifetime
    wasm: &'builder [u8],
    arg: Argument,
    mode: InstallMode,
}

impl<'agent: 'canister, 'canister: 'builder, 'builder> InstallBuilder<'agent, 'canister, 'builder> {
    // Messages are a maximum of 2MiB. Thus basic installation should cap the wasm and arg size at 1.85MiB, since
    // the current API is definitely not going to produce 150KiB of framing data for it.
    const CHUNK_CUTOFF: usize = (1.85 * 1024. * 1024.) as usize;

    /// Create a canister installation builder.
    pub fn builder(
        canister: &'canister ManagementCanister<'agent>,
        canister_id: &Principal,
        wasm: &'builder [u8],
    ) -> Self {
        Self {
            canister,
            canister_id: *canister_id,
            wasm,
            arg: Default::default(),
            mode: InstallMode::Install,
        }
    }

    /// Set the argument to the installation, which will be passed to the init
    /// method of the canister. Can be called at most once.
    pub fn with_arg<Argument: CandidType>(mut self, arg: Argument) -> Self {
        self.arg.set_idl_arg(arg);
        self
    }
    /// Set the argument with multiple arguments as tuple to the installation,
    /// which will be passed to the init method of the canister. Can be called at most once.
    pub fn with_args(mut self, tuple: impl ArgumentEncoder) -> Self {
        assert!(self.arg.0.is_none(), "argument is being set more than once");
        self.arg = Argument::from_candid(tuple);
        self
    }
    /// Set the argument passed in to the canister with raw bytes. Can be called at most once.
    pub fn with_raw_arg(mut self, arg: Vec<u8>) -> Self {
        self.arg.set_raw_arg(arg);
        self
    }

    /// Pass in the [InstallMode].
    pub fn with_mode(self, mode: InstallMode) -> Self {
        Self { mode, ..self }
    }

    /// Invoke the installation process. This may result in many calls which may take several seconds;
    /// use [`call_and_wait_with_progress`](Self::call_and_wait_with_progress) if you want progress reporting.
    pub async fn call_and_wait(self) -> Result<(), AgentError> {
        self.call_and_wait_with_progress()
            .await
            .try_for_each(|_| ready(Ok(())))
            .await
    }

    /// Invoke the installation process. The returned stream must be iterated to completion; it is used to track progress,
    /// as installation may take arbitrarily long, and is intended to be passed to functions like `indicatif::ProgressBar::wrap_stream`.
    /// There are exactly [`size_hint().0`](Stream::size_hint) steps.
    pub async fn call_and_wait_with_progress(
        self,
    ) -> impl Stream<Item = Result<(), AgentError>> + Send + 'builder {
        let stream_res = /* try { */ async move {
            let arg = self.arg.serialize()?;
            let stream: BoxStream<'_, _> =
                if self.wasm.len() + arg.len() < Self::CHUNK_CUTOFF {
                    Box::pin(
                        async move {
                            self.canister
                                .install_code(&self.canister_id, self.wasm)
                                .with_raw_arg(arg)
                                .with_mode(self.mode)
                                .call_and_wait()
                                .await
                        }
                        .into_stream(),
                    )
                } else {
                    let (existing_chunks,) = self.canister.stored_chunks(&self.canister_id).call_and_wait().await?;
                    let existing_chunks = existing_chunks.into_iter().collect::<BTreeSet<_>>();
                    let to_upload_chunks_ordered = self.wasm.chunks(1024 * 1024).map(|x| (<[u8; 32]>::from(Sha256::digest(x)), x)).collect::<Vec<_>>();
                    let to_upload_chunks = to_upload_chunks_ordered.iter().map(|&(k, v)| (k, v)).collect::<BTreeMap<_, _>>();
                    let (new_chunks, setup) = if existing_chunks.iter().all(|hash| to_upload_chunks.contains_key(hash)) {
                        (
                            to_upload_chunks.iter()
                                .filter_map(|(hash, value)| (!existing_chunks.contains(hash)).then_some((*hash, *value)))
                                .collect(),
                            Box::pin(ready(Ok(()))) as BoxFuture<'_, _>,
                        )
                    } else {
                        (to_upload_chunks.clone(), self.canister.clear_chunk_store(&self.canister_id).call_and_wait())
                    };
                    let chunks_stream = FuturesUnordered::new();
                    for &chunk in new_chunks.values() {
                        chunks_stream.push(async move {
                            let (_res,) = self
                                .canister
                                .upload_chunk(&self.canister_id, chunk)
                                .call_and_wait()
                                .await?;
                            Ok(())
                        })
                    }
                    Box::pin(
                        setup.into_stream()
                            // emit the same number of elements each time for a consistent progress bar, even if some are already uploaded
                            .chain(stream::repeat_with(|| Ok(())).take(to_upload_chunks.len() - new_chunks.len()))
                            .chain(chunks_stream)
                            .chain(
                                async move {
                                    let results = to_upload_chunks_ordered.iter().map(|&(hash, _)| hash).collect();
                                    self.canister
                                        .install_chunked_code(
                                            &self.canister_id,
                                            Sha256::digest(self.wasm).into(),
                                        )
                                        .with_chunk_hashes(results)
                                        .with_raw_arg(arg)
                                        .with_install_mode(self.mode)
                                        .call_and_wait()
                                        .await
                                }
                                .into_stream(),
                            )
                            .chain(
                                async move {
                                    self.canister
                                        .clear_chunk_store(&self.canister_id)
                                        .call_and_wait()
                                        .await
                                }
                                .into_stream(),
                            ),
                    )
                };
            Ok(stream)
        }.await;
        match stream_res {
            Ok(stream) => stream,
            Err(err) => Box::pin(stream::once(async { Err(err) })),
        }
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
    reserved_cycles_limit: Option<Result<ReservedCyclesLimit, AgentError>>,
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
            reserved_cycles_limit: None,
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

    /// Pass in a reserved cycles limit value for the canister.
    pub fn with_reserved_cycles_limit<C, E>(self, limit: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ReservedCyclesLimit, Error = E>,
    {
        self.with_optional_reserved_cycles_limit(Some(limit))
    }

    /// Pass in a reserved cycles limit optional value for the canister.
    /// If this is [None], leaves the reserved cycles limit unchanged.
    pub fn with_optional_reserved_cycles_limit<E, C>(self, limit: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ReservedCyclesLimit, Error = E>,
    {
        Self {
            reserved_cycles_limit: limit.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{}", e)))
            }),
            ..self
        }
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
        let reserved_cycles_limit = match self.reserved_cycles_limit {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{}", x))),
            Some(Ok(x)) => Some(Nat::from(u128::from(x))),
            None => None,
        };

        Ok(self
            .canister
            .update(MgmtMethod::UpdateSettings.as_ref())
            .with_arg(In {
                canister_id: self.canister_id,
                settings: CanisterSettings {
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                    reserved_cycles_limit,
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

#[cfg(not(target_family = "wasm"))]
type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;
#[cfg(target_family = "wasm")]
type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + 'a>>;
