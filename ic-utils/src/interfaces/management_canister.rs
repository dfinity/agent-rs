//! The canister interface for the IC management canister. See the [specification][spec] for full documentation of the interface.
//!
//! [spec]: https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-management-canister

use crate::{
    call::{AsyncCall, SyncCall},
    Canister,
};
use candid::{CandidType, Deserialize, Nat};
use ic_agent::{export::Principal, Agent};
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
    /// See [`ManagementCanister::provisional_create_canister_with_cycles`].
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
    /// There is no corresponding agent function as only canisters can call it.
    NodeMetricsHistory,
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

/// Log visibility for a canister.
#[derive(Default, Clone, Copy, CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum LogVisibility {
    #[default]
    #[serde(rename = "controllers")]
    /// Canister logs are visible to controllers only.
    Controllers,
    #[serde(rename = "public")]
    /// Canister logs are visible to everyone.
    Public,
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
    /// A soft limit on the Wasm memory usage of the canister in bytes (up to 256TiB).
    pub wasm_memory_limit: Option<Nat>,
    /// The canister log visibility. Defines which principals are allowed to fetch logs.
    pub log_visibility: LogVisibility,
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

/// A log record of a canister.
#[derive(Default, Clone, CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct CanisterLogRecord {
    /// The index of the log record.
    pub idx: u64,
    /// The timestamp of the log record.
    pub timestamp_nanos: u64,
    /// The content of the log record.
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
}

/// The result of a [`ManagementCanister::fetch_canister_logs`] call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, CandidType)]
pub struct FetchCanisterLogsResponse {
    /// The logs of the canister.
    pub canister_log_records: Vec<CanisterLogRecord>,
}

/// Chunk hash.
#[derive(CandidType, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct ChunkHash {
    /// The hash of an uploaded chunk
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

/// Return type of [ManagementCanister::stored_chunks].
pub type StoreChunksResult = Vec<ChunkHash>;

/// Return type of [ManagementCanister::upload_chunk].
pub type UploadChunkResult = ChunkHash;

/// A recorded snapshot of a canister. Can be restored with [`ManagementCanister::load_canister_snapshot`].
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct Snapshot {
    /// The ID of the snapshot.
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    /// The Unix nanosecond timestamp the snapshot was taken at.
    pub taken_at_timestamp: u64,
    /// The size of the snapshot in bytes.
    pub total_size: u64,
}

impl<'agent> ManagementCanister<'agent> {
    /// Get the status of a canister.
    pub fn canister_status(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = (StatusCallResult,)> {
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
    pub fn create_canister<'canister>(&'canister self) -> CreateCanisterBuilder<'agent, 'canister> {
        CreateCanisterBuilder::builder(self)
    }

    /// This method deposits the cycles included in this call into the specified canister.
    /// Only the controller of the canister can deposit cycles.
    pub fn deposit_cycles(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
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
    pub fn delete_canister(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
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
    pub fn provisional_top_up_canister(
        &self,
        canister_id: &Principal,
        amount: u64,
    ) -> impl 'agent + AsyncCall<Value = ()> {
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
    pub fn raw_rand(&self) -> impl 'agent + AsyncCall<Value = (Vec<u8>,)> {
        self.update(MgmtMethod::RawRand.as_ref())
            .build()
            .map(|result: (Vec<u8>,)| (result.0,))
    }

    /// Starts a canister.
    pub fn start_canister(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
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
    pub fn stop_canister(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
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
    pub fn uninstall_code(&self, canister_id: &Principal) -> impl 'agent + AsyncCall<Value = ()> {
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
        chunk: &[u8],
    ) -> impl 'agent + AsyncCall<Value = (UploadChunkResult,)> {
        #[derive(CandidType, Deserialize)]
        struct Argument<'a> {
            canister_id: Principal,
            #[serde(with = "serde_bytes")]
            chunk: &'a [u8],
        }

        self.update(MgmtMethod::UploadChunk.as_ref())
            .with_arg(Argument {
                canister_id: *canister_id,
                chunk,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Clear a canister's chunked WASM storage.
    pub fn clear_chunk_store(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = ()> {
        #[derive(CandidType)]
        struct Argument<'a> {
            canister_id: &'a Principal,
        }
        self.update(MgmtMethod::ClearChunkStore.as_ref())
            .with_arg(Argument { canister_id })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Get a list of the hashes of a canister's stored WASM chunks
    pub fn stored_chunks(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = (StoreChunksResult,)> {
        #[derive(CandidType)]
        struct Argument<'a> {
            canister_id: &'a Principal,
        }
        self.update(MgmtMethod::StoredChunks.as_ref())
            .with_arg(Argument { canister_id })
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
    ) -> impl 'agent + SyncCall<Value = (FetchCanisterLogsResponse,)> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        // `fetch_canister_logs` is only supported in non-replicated mode.
        self.query(MgmtMethod::FetchCanisterLogs.as_ref())
            .with_arg(In {
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
        replace_snapshot: Option<&[u8]>,
    ) -> impl 'agent + AsyncCall<Value = (Snapshot,)> {
        #[derive(CandidType)]
        struct In<'a> {
            canister_id: Principal,
            replace_snapshot: Option<&'a [u8]>,
        }
        self.update(MgmtMethod::TakeCanisterSnapshot.as_ref())
            .with_arg(In {
                canister_id: *canister_id,
                replace_snapshot,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Loads a canister snapshot by ID, replacing the canister's state with its state at the time the snapshot was taken.
    ///
    /// <div class="warning">Canisters should be stopped before running this method!</div>
    pub fn load_canister_snapshot(
        &self,
        canister_id: &Principal,
        snapshot_id: &[u8],
    ) -> impl 'agent + AsyncCall<Value = ()> {
        #[derive(CandidType)]
        struct In<'a> {
            canister_id: Principal,
            snapshot_id: &'a [u8],
            sender_canister_version: Option<u64>,
        }
        self.update(MgmtMethod::LoadCanisterSnapshot.as_ref())
            .with_arg(In {
                canister_id: *canister_id,
                snapshot_id,
                sender_canister_version: None,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// List a canister's recorded snapshots.
    pub fn list_canister_snapshots(
        &self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<Value = (Vec<Snapshot>,)> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }
        self.update(MgmtMethod::ListCanisterSnapshots.as_ref())
            .with_arg(In {
                canister_id: *canister_id,
            })
            .with_effective_canister_id(*canister_id)
            .build()
    }

    /// Deletes a recorded canister snapshot by ID.
    pub fn delete_canister_snapshot(
        &self,
        canister_id: &Principal,
        snapshot_id: &[u8],
    ) -> impl 'agent + AsyncCall<Value = ()> {
        #[derive(CandidType)]
        struct In<'a> {
            canister_id: Principal,
            snapshot_id: &'a [u8],
        }
        self.update(MgmtMethod::DeleteCanisterSnapshot.as_ref())
            .with_arg(In {
                canister_id: *canister_id,
                snapshot_id,
            })
            .build()
    }
}
