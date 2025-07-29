//! Builder interfaces for some method calls of the management canister.

#[doc(inline)]
pub use super::attributes::{
    ComputeAllocation, FreezingThreshold, MemoryAllocation, ReservedCyclesLimit, WasmMemoryLimit,
};
use super::{ChunkHash, LogVisibility, ManagementCanister};
use crate::call::CallFuture;
use crate::{
    call::AsyncCall, canister::Argument, interfaces::management_canister::MgmtMethod, Canister,
};
use async_trait::async_trait;
use candid::{utils::ArgumentEncoder, CandidType, Deserialize, Nat};
use futures_util::{
    future::ready,
    stream::{self, FuturesUnordered},
    FutureExt, Stream, StreamExt, TryStreamExt,
};
use ic_agent::{agent::CallResponse, export::Principal, AgentError};
pub use ic_management_canister_types::{
    CanisterInstallMode, CanisterSettings, InstallCodeArgs, UpgradeFlags, WasmMemoryPersistence,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    convert::{From, TryInto},
    future::IntoFuture,
    pin::Pin,
};

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
    wasm_memory_limit: Option<Result<WasmMemoryLimit, AgentError>>,
    wasm_memory_threshold: Option<Result<WasmMemoryLimit, AgentError>>,
    log_visibility: Option<Result<LogVisibility, AgentError>>,
    is_provisional_create: bool,
    amount: Option<u128>,
    specified_id: Option<Principal>,
}

impl<'agent, 'canister: 'agent> CreateCanisterBuilder<'agent, 'canister> {
    /// Create an `CreateCanister` builder, which is also an `AsyncCall` implementation.
    pub fn builder(canister: &'canister Canister<'agent>) -> Self {
        Self {
            canister,
            effective_canister_id: Principal::management_canister(),
            controllers: None,
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
            reserved_cycles_limit: None,
            wasm_memory_limit: None,
            wasm_memory_threshold: None,
            log_visibility: None,
            is_provisional_create: false,
            amount: None,
            specified_id: None,
        }
    }

    /// Until developers can convert real ICP tokens to provision a new canister with cycles,
    /// the system provides the `provisional_create_canister_with_cycles` method.
    /// It behaves as `create_canister`, but initializes the canister’s balance with amount fresh cycles
    /// (using `MAX_CANISTER_BALANCE` if amount = null, else capping the balance at `MAX_CANISTER_BALANCE`).
    /// Cycles added to this call via `ic0.call_cycles_add` are returned to the caller.
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
    /// The `effective_canister_id` will also be set with the same value so that ic-ref can determine
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

    /// Pass in an optional controller for the canister. If this is [`None`],
    /// it will revert the controller to default.
    pub fn with_optional_controller<C, E>(self, controller: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        let controller_to_add: Option<Result<Principal, _>> = controller.map(|ca| {
            ca.try_into()
                .map_err(|e| AgentError::MessageError(format!("{e}")))
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

    /// Pass in a compute allocation optional value for the canister. If this is [`None`],
    /// it will revert the compute allocation to default.
    pub fn with_optional_compute_allocation<C, E>(self, compute_allocation: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ComputeAllocation, Error = E>,
    {
        Self {
            compute_allocation: compute_allocation.map(|ca| {
                ca.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
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

    /// Pass in a memory allocation optional value for the canister. If this is [`None`],
    /// it will revert the memory allocation to default.
    pub fn with_optional_memory_allocation<E, C>(self, memory_allocation: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<MemoryAllocation, Error = E>,
    {
        Self {
            memory_allocation: memory_allocation.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
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

    /// Pass in a freezing threshold optional value for the canister. If this is [`None`],
    /// it will revert the freezing threshold to default.
    pub fn with_optional_freezing_threshold<E, C>(self, freezing_threshold: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<FreezingThreshold, Error = E>,
    {
        Self {
            freezing_threshold: freezing_threshold.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
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

    /// Pass in a reserved cycles limit optional value for the canister. If this is [`None`],
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
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Pass in a Wasm memory limit value for the canister.
    pub fn with_wasm_memory_limit<C, E>(self, wasm_memory_limit: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        self.with_optional_wasm_memory_limit(Some(wasm_memory_limit))
    }

    /// Pass in a Wasm memory limit optional value for the canister. If this is [`None`],
    /// it will revert the Wasm memory limit to default.
    pub fn with_optional_wasm_memory_limit<E, C>(self, wasm_memory_limit: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        Self {
            wasm_memory_limit: wasm_memory_limit.map(|limit| {
                limit
                    .try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Pass in a Wasm memory threshold value for the canister.
    pub fn with_wasm_memory_threshold<C, E>(self, wasm_memory_threshold: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        self.with_optional_wasm_memory_threshold(Some(wasm_memory_threshold))
    }

    /// Pass in a Wasm memory threshold optional value for the canister. If this is [`None`],
    /// it will revert the Wasm memory threshold to default.
    pub fn with_optional_wasm_memory_threshold<E, C>(self, wasm_memory_threshold: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        Self {
            wasm_memory_threshold: wasm_memory_threshold.map(|limit| {
                limit
                    .try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Pass in a log visibility setting for the canister.
    pub fn with_log_visibility<C, E>(self, log_visibility: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<LogVisibility, Error = E>,
    {
        self.with_optional_log_visibility(Some(log_visibility))
    }

    /// Pass in a log visibility optional setting for the canister. If this is [`None`],
    /// it will revert the log visibility to default.
    pub fn with_optional_log_visibility<E, C>(self, log_visibility: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<LogVisibility, Error = E>,
    {
        Self {
            log_visibility: log_visibility.map(|visibility| {
                visibility
                    .try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Create an [`AsyncCall`] implementation that, when called, will create a
    /// canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<Value = (Principal,)>, AgentError> {
        let controllers = match self.controllers {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(x),
            None => None,
        };
        let compute_allocation = match self.compute_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u8::from(x))),
            None => None,
        };
        let memory_allocation = match self.memory_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let freezing_threshold = match self.freezing_threshold {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let reserved_cycles_limit = match self.reserved_cycles_limit {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u128::from(x))),
            None => None,
        };
        let wasm_memory_limit = match self.wasm_memory_limit {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let wasm_memory_threshold = match self.wasm_memory_threshold {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let log_visibility = match self.log_visibility {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(x),
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
                    wasm_memory_limit,
                    wasm_memory_threshold,
                    log_visibility,
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
                    wasm_memory_limit,
                    wasm_memory_threshold,
                    log_visibility,
                })
                .with_effective_canister_id(self.effective_canister_id)
        };

        Ok(async_builder
            .build()
            .map(|result: (Out,)| (result.0.canister_id,)))
    }

    /// Make a call. This is equivalent to the [`AsyncCall::call`].
    pub async fn call(self) -> Result<CallResponse<(Principal,)>, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<(Principal,), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall for CreateCanisterBuilder<'agent, 'canister> {
    type Value = (Principal,);

    async fn call(self) -> Result<CallResponse<(Principal,)>, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait(self) -> Result<(Principal,), AgentError> {
        self.build()?.call_and_wait().await
    }
}

impl<'agent, 'canister: 'agent> IntoFuture for CreateCanisterBuilder<'agent, 'canister> {
    type IntoFuture = CallFuture<'agent, (Principal,)>;
    type Output = Result<(Principal,), AgentError>;

    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}

#[doc(hidden)]
#[deprecated(since = "0.42.0", note = "Please use UpgradeFlags instead")]
pub type CanisterUpgradeOptions = UpgradeFlags;

#[doc(hidden)]
#[deprecated(since = "0.42.0", note = "Please use CanisterInstallMode instead")]
pub type InstallMode = CanisterInstallMode;

#[doc(hidden)]
#[deprecated(since = "0.42.0", note = "Please use InstallCodeArgs instead")]
pub type CanisterInstall = InstallCodeArgs;

/// A builder for an `install_code` call.
#[derive(Debug)]
pub struct InstallCodeBuilder<'agent, 'canister: 'agent> {
    canister: &'canister Canister<'agent>,
    canister_id: Principal,
    wasm: &'canister [u8],
    arg: Argument,
    mode: Option<CanisterInstallMode>,
}

impl<'agent, 'canister: 'agent> InstallCodeBuilder<'agent, 'canister> {
    /// Create an `InstallCode` builder, which is also an `AsyncCall` implementation.
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

    /// Pass in the [`CanisterInstallMode`].
    pub fn with_mode(self, mode: CanisterInstallMode) -> Self {
        Self {
            mode: Some(mode),
            ..self
        }
    }

    /// Create an [`AsyncCall`] implementation that, when called, will install the
    /// canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<Value = ()>, AgentError> {
        Ok(self
            .canister
            .update(MgmtMethod::InstallCode.as_ref())
            .with_arg(InstallCodeArgs {
                mode: self.mode.unwrap_or(CanisterInstallMode::Install),
                canister_id: self.canister_id,
                wasm_module: self.wasm.to_owned(),
                arg: self.arg.serialize()?,
                sender_canister_version: None,
            })
            .with_effective_canister_id(self.canister_id)
            .build())
    }

    /// Make a call. This is equivalent to the [`AsyncCall::call`].
    pub async fn call(self) -> Result<CallResponse<()>, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall for InstallCodeBuilder<'agent, 'canister> {
    type Value = ();

    async fn call(self) -> Result<CallResponse<()>, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

impl<'agent, 'canister: 'agent> IntoFuture for InstallCodeBuilder<'agent, 'canister> {
    type IntoFuture = CallFuture<'agent, ()>;
    type Output = Result<(), AgentError>;

    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}

/// A builder for an `install_chunked_code` call.
#[derive(Debug)]
pub struct InstallChunkedCodeBuilder<'agent, 'canister> {
    canister: &'canister Canister<'agent>,
    target_canister: Principal,
    store_canister: Option<Principal>,
    chunk_hashes_list: Vec<ChunkHash>,
    wasm_module_hash: Vec<u8>,
    arg: Argument,
    mode: CanisterInstallMode,
}

impl<'agent: 'canister, 'canister> InstallChunkedCodeBuilder<'agent, 'canister> {
    /// Create an `InstallChunkedCodeBuilder`.
    pub fn builder(
        canister: &'canister Canister<'agent>,
        target_canister: Principal,
        wasm_module_hash: &[u8],
    ) -> Self {
        Self {
            canister,
            target_canister,
            wasm_module_hash: wasm_module_hash.to_vec(),
            store_canister: None,
            chunk_hashes_list: vec![],
            arg: Argument::new(),
            mode: CanisterInstallMode::Install,
        }
    }

    /// Set the chunks to install. These must previously have been set with [`ManagementCanister::upload_chunk`].
    pub fn with_chunk_hashes(mut self, chunk_hashes: Vec<ChunkHash>) -> Self {
        self.chunk_hashes_list = chunk_hashes;
        self
    }

    /// Set the canister to pull uploaded chunks from. By default this is the same as the target canister.
    pub fn with_store_canister(mut self, store_canister: Principal) -> Self {
        self.store_canister = Some(store_canister);
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

    /// Set the [`CanisterInstallMode`].
    pub fn with_install_mode(mut self, mode: CanisterInstallMode) -> Self {
        self.mode = mode;
        self
    }

    /// Create an [`AsyncCall`] implementation that, when called, will install the canister.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<Value = ()>, AgentError> {
        #[derive(CandidType)]
        struct In {
            mode: CanisterInstallMode,
            target_canister: Principal,
            store_canister: Option<Principal>,
            chunk_hashes_list: Vec<ChunkHash>,
            wasm_module_hash: Vec<u8>,
            arg: Vec<u8>,
            sender_canister_version: Option<u64>,
        }
        let Self {
            mode,
            target_canister,
            store_canister,
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
                store_canister,
                chunk_hashes_list,
                wasm_module_hash,
                arg: arg.serialize()?,
                sender_canister_version: None,
            })
            .with_effective_canister_id(target_canister)
            .build())
    }

    /// Make the call. This is equivalent to [`AsyncCall::call`].
    pub async fn call(self) -> Result<CallResponse<()>, AgentError> {
        self.build()?.call().await
    }

    /// Make the call. This is equivalent to [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall for InstallChunkedCodeBuilder<'agent, 'canister> {
    type Value = ();

    async fn call(self) -> Result<CallResponse<()>, AgentError> {
        self.call().await
    }

    async fn call_and_wait(self) -> Result<(), AgentError> {
        self.call_and_wait().await
    }
}

impl<'agent, 'canister: 'agent> IntoFuture for InstallChunkedCodeBuilder<'agent, 'canister> {
    type IntoFuture = CallFuture<'agent, ()>;
    type Output = Result<(), AgentError>;

    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
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
    mode: CanisterInstallMode,
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
            mode: CanisterInstallMode::Install,
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

    /// Pass in the [`CanisterInstallMode`].
    pub fn with_mode(self, mode: CanisterInstallMode) -> Self {
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
    ) -> impl Stream<Item = Result<(), AgentError>> + 'builder {
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
                    let existing_chunks = existing_chunks.into_iter().map(|c| c.hash).collect::<BTreeSet<_>>();
                    let all_chunks = self.wasm.chunks(1024 * 1024).map(|x| (Sha256::digest(x).to_vec(), x)).collect::<Vec<_>>();
                    let mut to_upload_chunks = vec![];
                    for (hash, chunk) in &all_chunks {
                        if !existing_chunks.contains(hash) {
                            to_upload_chunks.push(*chunk);
                        }
                    }

                    let upload_chunks_stream = FuturesUnordered::new();
                    for chunk in to_upload_chunks {
                        upload_chunks_stream.push(async move {
                            let (_res,) = self
                                .canister
                                .upload_chunk(&self.canister_id, &ic_management_canister_types::UploadChunkArgs {
                                    canister_id: self.canister_id,
                                    chunk: chunk.to_vec(),
                                })
                                .call_and_wait()
                                .await?;
                            Ok(())
                        });
                    }
                    let install_chunked_code_stream = async move {
                        let results = all_chunks.iter().map(|(hash,_)| ChunkHash{ hash: hash.clone() }).collect();
                        self.canister
                            .install_chunked_code(
                                &self.canister_id,
                                &Sha256::digest(self.wasm),
                            )
                            .with_chunk_hashes(results)
                            .with_raw_arg(arg)
                            .with_install_mode(self.mode)
                            .call_and_wait()
                            .await
                    }
                    .into_stream();
                    let clear_store_stream = async move {
                        self.canister
                            .clear_chunk_store(&self.canister_id)
                            .call_and_wait()
                            .await
                    }
                    .into_stream();

                    Box::pin(
                        upload_chunks_stream
                            .chain(install_chunked_code_stream)
                            .chain(clear_store_stream                        ),
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

impl<'agent: 'canister, 'canister: 'builder, 'builder> IntoFuture
    for InstallBuilder<'agent, 'canister, 'builder>
{
    type IntoFuture = CallFuture<'builder, ()>;
    type Output = Result<(), AgentError>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.call_and_wait())
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
    wasm_memory_limit: Option<Result<WasmMemoryLimit, AgentError>>,
    wasm_memory_threshold: Option<Result<WasmMemoryLimit, AgentError>>,
    log_visibility: Option<Result<LogVisibility, AgentError>>,
}

impl<'agent, 'canister: 'agent> UpdateCanisterBuilder<'agent, 'canister> {
    /// Create an `UpdateCanister` builder, which is also an `AsyncCall` implementation.
    pub fn builder(canister: &'canister Canister<'agent>, canister_id: &Principal) -> Self {
        Self {
            canister,
            canister_id: *canister_id,
            controllers: None,
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
            reserved_cycles_limit: None,
            wasm_memory_limit: None,
            wasm_memory_threshold: None,
            log_visibility: None,
        }
    }

    /// Pass in an optional controller for the canister. If this is [`None`],
    /// it will revert the controller to default.
    pub fn with_optional_controller<C, E>(self, controller: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<Principal, Error = E>,
    {
        let controller_to_add: Option<Result<Principal, _>> = controller.map(|ca| {
            ca.try_into()
                .map_err(|e| AgentError::MessageError(format!("{e}")))
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

    /// Pass in a compute allocation optional value for the canister. If this is [`None`],
    /// it will revert the compute allocation to default.
    pub fn with_optional_compute_allocation<C, E>(self, compute_allocation: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ComputeAllocation, Error = E>,
    {
        Self {
            compute_allocation: compute_allocation.map(|ca| {
                ca.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
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

    /// Pass in a memory allocation optional value for the canister. If this is [`None`],
    /// it will revert the memory allocation to default.
    pub fn with_optional_memory_allocation<E, C>(self, memory_allocation: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<MemoryAllocation, Error = E>,
    {
        Self {
            memory_allocation: memory_allocation.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
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

    /// Pass in a freezing threshold optional value for the canister. If this is [`None`],
    /// it will revert the freezing threshold to default.
    pub fn with_optional_freezing_threshold<E, C>(self, freezing_threshold: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<FreezingThreshold, Error = E>,
    {
        Self {
            freezing_threshold: freezing_threshold.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
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
    /// If this is [`None`], leaves the reserved cycles limit unchanged.
    pub fn with_optional_reserved_cycles_limit<E, C>(self, limit: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<ReservedCyclesLimit, Error = E>,
    {
        Self {
            reserved_cycles_limit: limit.map(|ma| {
                ma.try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Pass in a Wasm memory limit value for the canister.
    pub fn with_wasm_memory_limit<C, E>(self, wasm_memory_limit: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        self.with_optional_wasm_memory_limit(Some(wasm_memory_limit))
    }

    /// Pass in a Wasm memory limit optional value for the canister. If this is [`None`],
    /// leaves the Wasm memory limit unchanged.
    pub fn with_optional_wasm_memory_limit<E, C>(self, wasm_memory_limit: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        Self {
            wasm_memory_limit: wasm_memory_limit.map(|limit| {
                limit
                    .try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Pass in a Wasm memory threshold value for the canister.
    pub fn with_wasm_memory_threshold<C, E>(self, wasm_memory_threshold: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        self.with_optional_wasm_memory_threshold(Some(wasm_memory_threshold))
    }

    /// Pass in a Wasm memory threshold value for the canister. If this is [`None`],
    /// leaves the memory threshold unchanged.
    pub fn with_optional_wasm_memory_threshold<E, C>(self, wasm_memory_threshold: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<WasmMemoryLimit, Error = E>,
    {
        Self {
            wasm_memory_threshold: wasm_memory_threshold.map(|limit| {
                limit
                    .try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Pass in a log visibility setting for the canister.
    pub fn with_log_visibility<C, E>(self, log_visibility: C) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<LogVisibility, Error = E>,
    {
        self.with_optional_log_visibility(Some(log_visibility))
    }

    /// Pass in a log visibility optional setting for the canister. If this is [`None`],
    /// leaves the log visibility unchanged.
    pub fn with_optional_log_visibility<E, C>(self, log_visibility: Option<C>) -> Self
    where
        E: std::fmt::Display,
        C: TryInto<LogVisibility, Error = E>,
    {
        Self {
            log_visibility: log_visibility.map(|limit| {
                limit
                    .try_into()
                    .map_err(|e| AgentError::MessageError(format!("{e}")))
            }),
            ..self
        }
    }

    /// Create an [`AsyncCall`] implementation that, when called, will update a
    /// canisters settings.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<Value = ()>, AgentError> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
            settings: CanisterSettings,
        }

        let controllers = match self.controllers {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(x),
            None => None,
        };
        let compute_allocation = match self.compute_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u8::from(x))),
            None => None,
        };
        let memory_allocation = match self.memory_allocation {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let freezing_threshold = match self.freezing_threshold {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let reserved_cycles_limit = match self.reserved_cycles_limit {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u128::from(x))),
            None => None,
        };
        let wasm_memory_limit = match self.wasm_memory_limit {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let wasm_memory_threshold = match self.wasm_memory_threshold {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(Nat::from(u64::from(x))),
            None => None,
        };
        let log_visibility = match self.log_visibility {
            Some(Err(x)) => return Err(AgentError::MessageError(format!("{x}"))),
            Some(Ok(x)) => Some(x),
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
                    wasm_memory_limit,
                    wasm_memory_threshold,
                    log_visibility,
                },
            })
            .with_effective_canister_id(self.canister_id)
            .build())
    }

    /// Make a call. This is equivalent to the [`AsyncCall::call`].
    pub async fn call(self) -> Result<CallResponse<()>, AgentError> {
        self.build()?.call().await
    }

    /// Make a call. This is equivalent to the [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent> AsyncCall for UpdateCanisterBuilder<'agent, 'canister> {
    type Value = ();
    async fn call(self) -> Result<CallResponse<()>, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait(self) -> Result<(), AgentError> {
        self.build()?.call_and_wait().await
    }
}

impl<'agent, 'canister: 'agent> IntoFuture for UpdateCanisterBuilder<'agent, 'canister> {
    type IntoFuture = CallFuture<'agent, ()>;
    type Output = Result<(), AgentError>;
    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}

#[cfg(not(target_family = "wasm"))]
type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;
#[cfg(target_family = "wasm")]
type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + 'a>>;
