//! The canister interface for the IC management canister. See the [specification][spec] for full documentation of the interface.
//!
//! [spec]: https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-management-canister

use crate::{
    call::{AsyncCall, SyncCall},
    Canister,
};
use ic_agent::{export::Principal, Agent};
use ic_management_canister_types::{
    CanisterIdRecord, DeleteCanisterSnapshotArgs, LoadCanisterSnapshotArgs,
    ProvisionalTopUpCanisterArgs, ReadCanisterSnapshotDataArgs, ReadCanisterSnapshotMetadataArgs,
    TakeCanisterSnapshotArgs, UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs,
    UploadChunkArgs,
};
// Re-export the types that are used be defined in this file.
pub use ic_management_canister_types::{
    CanisterLogRecord, CanisterStatusResult, CanisterStatusType, CanisterTimer, ChunkHash,
    DefiniteCanisterSettings, ExportedGlobal, FetchCanisterLogsResult, LogVisibility,
    OnLowWasmMemoryHookStatus, QueryStats, ReadCanisterSnapshotDataResult,
    ReadCanisterSnapshotMetadataResult, Snapshot, SnapshotDataKind, SnapshotDataOffset,
    SnapshotSource, StoredChunksResult, UploadCanisterSnapshotMetadataResult, UploadChunkResult,
};
use std::{convert::AsRef, ops::Deref};
use strum_macros::{AsRefStr, Display, EnumString};

pub mod attributes;
pub mod builders;

#[doc(inline)]
pub use builders::{
    CreateCanisterBuilder, InstallBuilder, InstallChunkedCodeBuilder, InstallCodeBuilder,
    UpdateCanisterBuilder,
};

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
#[derive(AsRefStr, Debug, EnumString, Display)]
#[strum(serialize_all = "snake_case")]
pub enum MgmtMethod {
    /// See [`ManagementCanister::create_canister`].
    CreateCanister,
    /// See [`ManagementCanister::install_code`].
    InstallCode,
    /// See [`ManagementCanister::start_canister`].
    StartCanister,
    /// See [`ManagementCanister::stop_canister`].
    StopCanister,
    /// See [`ManagementCanister::canister_status`].
    CanisterStatus,
    /// See [`ManagementCanister::delete_canister`].
    DeleteCanister,
    /// See [`ManagementCanister::deposit_cycles`].
    DepositCycles,
    /// See [`ManagementCanister::raw_rand`].
    RawRand,
    /// See [`CreateCanisterBuilder::as_provisional_create_with_amount`].
    ProvisionalCreateCanisterWithCycles,
    /// See [`ManagementCanister::provisional_top_up_canister`].
    ProvisionalTopUpCanister,
    /// See [`ManagementCanister::uninstall_code`].
    UninstallCode,
    /// See [`ManagementCanister::update_settings`].
    UpdateSettings,
    /// See [`ManagementCanister::upload_chunk`].
    UploadChunk,
    /// See [`ManagementCanister::clear_chunk_store`].
    ClearChunkStore,
    /// See [`ManagementCanister::stored_chunks`].
    StoredChunks,
    /// See [`ManagementCanister::install_chunked_code`].
    InstallChunkedCode,
    /// See [`ManagementCanister::fetch_canister_logs`].
    FetchCanisterLogs,
    /// See [`ManagementCanister::take_canister_snapshot`].
    TakeCanisterSnapshot,
    /// See [`ManagementCanister::load_canister_snapshot`].
    LoadCanisterSnapshot,
    /// See [`ManagementCanister::list_canister_snapshots`].
    ListCanisterSnapshots,
    /// See [`ManagementCanister::delete_canister_snapshot`].
    DeleteCanisterSnapshot,
    /// See [`ManagementCanister::read_canister_snapshot_metadata`].
    ReadCanisterSnapshotMetadata,
    /// See [`ManagementCanister::read_canister_snapshot_data`].
    ReadCanisterSnapshotData,
    /// See [`ManagementCanister::upload_canister_snapshot_metadata`].
    UploadCanisterSnapshotMetadata,
    /// See [`ManagementCanister::upload_canister_snapshot_data`].
    UploadCanisterSnapshotData,
    /// There is no corresponding agent function as only canisters can call it.
    EcdsaPublicKey,
    /// There is no corresponding agent function as only canisters can call it.
    SignWithEcdsa,
    /// There is no corresponding agent function as only canisters can call it. Use [`BitcoinCanister`](super::BitcoinCanister) instead.
    BitcoinGetBalance,
    /// There is no corresponding agent function as only canisters can call it. Use [`BitcoinCanister`](super::BitcoinCanister) instead.
    BitcoinGetUtxos,
    /// There is no corresponding agent function as only canisters can call it. Use [`BitcoinCanister`](super::BitcoinCanister) instead.
    BitcoinSendTransaction,
    /// There is no corresponding agent function as only canisters can call it. Use [`BitcoinCanister`](super::BitcoinCanister) instead.
    BitcoinGetCurrentFeePercentiles,
    /// There is no corresponding agent function as only canisters can call it. Use [`BitcoinCanister`](super::BitcoinCanister) instead.
    BitcoinGetBlockHeaders,
    /// There is no corresponding agent function as only canisters can call it.
    NodeMetricsHistory,
    /// There is no corresponding agent function as only canisters can call it.
    CanisterInfo,
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

#[doc(hidden)]
#[deprecated(since = "0.42.0", note = "Please use CanisterStatusResult instead")]
pub type StatusCallResult = CanisterStatusResult;

#[doc(hidden)]
#[deprecated(since = "0.42.0", note = "Please use CanisterStatusType instead")]
pub type CanisterStatus = CanisterStatusType;

#[doc(hidden)]
#[deprecated(since = "0.42.0", note = "Please use FetchCanisterLogsResult instead")]
pub type FetchCanisterLogsResponse = FetchCanisterLogsResult;

#[doc(hidden)]
#[deprecated(since = "0.42.0", note = "Please use StoredChunksResult instead")]
pub type StoreChunksResult = StoredChunksResult;

#[doc(hidden)]
#[deprecated(
    since = "0.42.0",
    note = "Please use ReadCanisterSnapshotMetadataResult instead"
)]
pub type SnapshotMetadata = ReadCanisterSnapshotMetadataResult;

#[doc(hidden)]
#[deprecated(
    since = "0.42.0",
    note = "Please use ReadCanisterSnapshotDataResult instead"
)]
pub type SnapshotDataResult = ReadCanisterSnapshotDataResult;

#[doc(hidden)]
#[deprecated(
    since = "0.42.0",
    note = "Please use UploadCanisterSnapshotMetadataResult instead"
)]
pub type CanisterSnapshotId = UploadCanisterSnapshotMetadataResult;

impl<'agent> ManagementCanister<'agent> {
    /// Get the status of a canister.
    pub fn canister_status(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = (CanisterStatusResult,)> {
        self.update(MgmtMethod::CanisterStatus.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
            .map(|result: (CanisterStatusResult,)| (result.0,))
    }

    /// Create a canister.
    pub fn create_canister<'canister>(&'canister self) -> CreateCanisterBuilder<'agent, 'canister> {
        CreateCanisterBuilder::builder(self)
    }

    /// This method deposits the cycles included in this call into the specified canister.
    /// Only the controller of the canister can deposit cycles.
    pub fn deposit_cycles(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::DepositCycles.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Deletes a canister.
    pub fn delete_canister(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::DeleteCanister.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Until developers can convert real ICP tokens to a top up an existing canister,
    /// the system provides the `provisional_top_up_canister` method.
    /// It adds amount cycles to the balance of canister identified by amount
    /// (implicitly capping it at `MAX_CANISTER_BALANCE`).
    pub fn provisional_top_up_canister(
        &self,
        canister_id: &Principal,
        top_up_args: &ProvisionalTopUpCanisterArgs,
    ) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::ProvisionalTopUpCanister.as_ref())
            .with_arg(top_up_args)
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// This method takes no input and returns 32 pseudo-random bytes to the caller.
    /// The return value is unknown to any part of the IC at time of the submission of this call.
    /// A new return value is generated for each call to this method.
    pub fn raw_rand(&self) -> impl 'agent + AsyncCall<Value = (Vec<u8>,)> {
        self.update(MgmtMethod::RawRand.as_ref())
            .build()
            .map(|result: (Vec<u8>,)| (result.0,))
    }

    /// Starts a canister.
    pub fn start_canister(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::StartCanister.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Stop a canister.
    pub fn stop_canister(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::StopCanister.as_ref())
            .with_arg(CanisterIdRecord {
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
    pub fn uninstall_code(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::UninstallCode.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(canister_id.to_owned())
            .build()
    }

    /// Install a canister, with all the arguments necessary for creating the canister.
    pub fn install_code<'canister>(
        &'canister self,
        canister_id: &Principal,
        wasm: &'canister [u8],
    ) -> InstallCodeBuilder<'agent, 'canister> {
        InstallCodeBuilder::builder(self, canister_id, wasm)
    }

    /// Update one or more of a canisters settings (i.e its controller, compute allocation, or memory allocation.)
    pub fn update_settings<'canister>(
        &'canister self,
        canister_id: &Principal,
    ) -> UpdateCanisterBuilder<'agent, 'canister> {
        UpdateCanisterBuilder::builder(self, canister_id)
    }

    /// Upload a chunk of a WASM module to a canister's chunked WASM storage.
    pub fn upload_chunk(
        &self,
        canister_id: &Principal,
        upload_chunk_args: &UploadChunkArgs,
    ) -> impl 'agent + AsyncCall<Value = (UploadChunkResult,)> {
        self.update(MgmtMethod::UploadChunk.as_ref())
            .with_arg(upload_chunk_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Clear a canister's chunked WASM storage.
    pub fn clear_chunk_store(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::ClearChunkStore.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Get a list of the hashes of a canister's stored WASM chunks
    pub fn stored_chunks(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = (StoredChunksResult,)> {
        self.update(MgmtMethod::StoredChunks.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Install a canister module previously uploaded in chunks via [`upload_chunk`](Self::upload_chunk).
    pub fn install_chunked_code<'canister>(
        &'canister self,
        canister_id: &Principal,
        wasm_module_hash: &[u8],
    ) -> InstallChunkedCodeBuilder<'agent, 'canister> {
        InstallChunkedCodeBuilder::builder(self, *canister_id, wasm_module_hash)
    }

    /// Install a canister module, automatically selecting one-shot installation or chunked installation depending on module size.
    ///
    /// # Warnings
    ///
    /// This will clear chunked code storage if chunked installation is used. Do not use with canisters that you are manually uploading chunked code to.
    pub fn install<'canister: 'builder, 'builder>(
        &'canister self,
        canister_id: &Principal,
        wasm: &'builder [u8],
    ) -> InstallBuilder<'agent, 'canister, 'builder> {
        InstallBuilder::builder(self, canister_id, wasm)
    }

    /// Fetch the logs of a canister.
    pub fn fetch_canister_logs(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + SyncCall<Value = (FetchCanisterLogsResult,)> {
        // `fetch_canister_logs` is only supported in non-replicated mode.
        self.query(MgmtMethod::FetchCanisterLogs.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Creates a canister snapshot, optionally replacing an existing snapshot.
    ///  
    /// <div class="warning">Canisters should be stopped before running this method!</div>
    pub fn take_canister_snapshot(
        &self,
        canister_id: &Principal,
        take_args: &TakeCanisterSnapshotArgs,
    ) -> impl 'agent + AsyncCall<Value = (Snapshot,)> {
        self.update(MgmtMethod::TakeCanisterSnapshot.as_ref())
            .with_arg(take_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Loads a canister snapshot by ID, replacing the canister's state with its state at the time the snapshot was taken.
    ///
    /// <div class="warning">Canisters should be stopped before running this method!</div>
    pub fn load_canister_snapshot(
        &self,
        canister_id: &Principal,
        load_args: &LoadCanisterSnapshotArgs,
    ) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::LoadCanisterSnapshot.as_ref())
            .with_arg(load_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// List a canister's recorded snapshots.
    pub fn list_canister_snapshots(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = (Vec<Snapshot>,)> {
        self.update(MgmtMethod::ListCanisterSnapshots.as_ref())
            .with_arg(CanisterIdRecord {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Deletes a recorded canister snapshot by ID.
    pub fn delete_canister_snapshot(
        &self,
        canister_id: &Principal,
        delete_args: &DeleteCanisterSnapshotArgs,
    ) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::DeleteCanisterSnapshot.as_ref())
            .with_arg(delete_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Reads the metadata of a recorded canister snapshot by canister ID and snapshot ID.
    pub fn read_canister_snapshot_metadata(
        &self,
        canister_id: &Principal,
        metadata_args: &ReadCanisterSnapshotMetadataArgs,
    ) -> impl 'agent + AsyncCall<Value = (ReadCanisterSnapshotMetadataResult,)> {
        self.update(MgmtMethod::ReadCanisterSnapshotMetadata.as_ref())
            .with_arg(metadata_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Reads the data of a recorded canister snapshot by canister ID and snapshot ID.
    pub fn read_canister_snapshot_data(
        &self,
        canister_id: &Principal,
        data_args: &ReadCanisterSnapshotDataArgs,
    ) -> impl 'agent + AsyncCall<Value = (ReadCanisterSnapshotDataResult,)> {
        self.update(MgmtMethod::ReadCanisterSnapshotData.as_ref())
            .with_arg(data_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Uploads the metadata of a canister snapshot by canister ID.
    pub fn upload_canister_snapshot_metadata(
        &self,
        canister_id: &Principal,
        metadata_args: &UploadCanisterSnapshotMetadataArgs,
    ) -> impl 'agent + AsyncCall<Value = (UploadCanisterSnapshotMetadataResult,)> {
        self.update(MgmtMethod::UploadCanisterSnapshotMetadata.as_ref())
            .with_arg(metadata_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Uploads the data of a canister snapshot by canister ID and snapshot ID..
    pub fn upload_canister_snapshot_data(
        &self,
        canister_id: &Principal,
        data_args: &UploadCanisterSnapshotDataArgs,
    ) -> impl 'agent + AsyncCall<Value = ()> {
        self.update(MgmtMethod::UploadCanisterSnapshotData.as_ref())
            .with_arg(data_args)
            .with_effective_canister_id(*canister_id)
            .build()
    }
}
