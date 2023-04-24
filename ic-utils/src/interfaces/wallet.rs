//! The canister interface for the [cycles wallet] canister.
//!
//! [cycles wallet]: https://github.com/dfinity/cycles-wallet

use std::ops::Deref;

use crate::{
    call::{AsyncCall, SyncCall},
    canister::Argument,
    interfaces::management_canister::{
        attributes::{ComputeAllocation, FreezingThreshold, MemoryAllocation},
        builders::CanisterSettings,
    },
    Canister,
};
use async_trait::async_trait;
use candid::{decode_args, utils::ArgumentDecoder, CandidType, Deserialize, Nat};
use ic_agent::{agent::RejectCode, export::Principal, Agent, AgentError, RequestId};
use once_cell::sync::Lazy;
use semver::{Version, VersionReq};

const REPLICA_ERROR_NO_SUCH_QUERY_METHOD: &str = "has no query method 'wallet_api_version'";
const IC_REF_ERROR_NO_SUCH_QUERY_METHOD: &str = "query method does not exist";

/// An interface for forwarding a canister method call through the wallet canister via `wallet_canister_call`.
#[derive(Debug)]
pub struct CallForwarder<'agent, 'canister: 'agent, Out>
where
    Self: 'canister,
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    wallet: &'canister WalletCanister<'agent>,
    destination: Principal,
    method_name: String,
    amount: u128,
    u128: bool,
    arg: Argument,
    phantom_out: std::marker::PhantomData<Out>,
}

/// A canister's settings. Similar to the canister settings struct from [`management_canister`](super::management_canister),
/// but the management canister may evolve to have more settings without the wallet canister evolving to recognize them.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct CanisterSettingsV1 {
    /// The set of canister controllers. Controllers can update the canister via the management canister.
    pub controller: Option<Principal>,
    /// The allocation percentage (between 0 and 100 inclusive) for *guaranteed* compute capacity.
    pub compute_allocation: Option<Nat>,
    /// The allocation, in bytes (up to 256 TiB) that the canister is allowed to use for storage.
    pub memory_allocation: Option<Nat>,
    /// The IC will freeze a canister protectively if it will likely run out of cycles before this amount of time, in seconds (up to `u64::MAX`), has passed.
    pub freezing_threshold: Option<Nat>,
}

impl<'agent, 'canister: 'agent, Out> CallForwarder<'agent, 'canister, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    /// Add an argument to the candid argument list. This requires Candid arguments, if
    /// there is a raw argument set (using [with_arg_raw]), this will fail.
    pub fn with_arg<Argument>(mut self, arg: Argument) -> Self
    where
        Argument: CandidType + Sync + Send,
    {
        self.arg.push_idl_arg(arg);
        self
    }

    /// Replace the argument with raw argument bytes. This will overwrite the current
    /// argument set, so calling this method twice will discard the first argument.
    pub fn with_arg_raw(mut self, arg: Vec<u8>) -> Self {
        self.arg.set_raw_arg(arg);
        self
    }

    /// Creates an [`AsyncCall`] implementation that, when called, will forward the specified canister call.
    pub fn build(self) -> Result<impl 'agent + AsyncCall<Out>, AgentError> {
        #[derive(CandidType, Deserialize)]
        struct In<TCycles> {
            canister: Principal,
            method_name: String,
            #[serde(with = "serde_bytes")]
            args: Vec<u8>,
            cycles: TCycles,
        }
        Ok(if self.u128 {
            self.wallet.update_("wallet_call128").with_arg(In {
                canister: self.destination,
                method_name: self.method_name,
                args: self.arg.serialize()?.to_vec(),
                cycles: self.amount,
            })
        } else {
            self.wallet.update_("wallet_call").with_arg(In {
                canister: self.destination,
                method_name: self.method_name,
                args: self.arg.serialize()?.to_vec(),
                cycles: u64::try_from(self.amount).map_err(|_| {
                    AgentError::WalletUpgradeRequired(
                        "The installed wallet does not support cycle counts >2^64-1".to_string(),
                    )
                })?,
            })
        }
        .build()
        .and_then(|(result,): (Result<CallResult, String>,)| async move {
            let result = result.map_err(AgentError::WalletCallFailed)?;
            decode_args::<Out>(result.r#return.as_slice())
                .map_err(|e| AgentError::CandidError(Box::new(e)))
        }))
    }

    /// Calls the forwarded canister call on the wallet canister. Equivalent to `.build().call()`.
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    /// Calls the forwarded canister call on the wallet canister, and waits for the result. Equivalent to `.build().call_and_wait()`.
    pub async fn call_and_wait(self) -> Result<Out, AgentError> {
        self.build()?.call_and_wait().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, 'canister: 'agent, Out> AsyncCall<Out> for CallForwarder<'agent, 'canister, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }

    async fn call_and_wait(self) -> Result<Out, AgentError> {
        self.call_and_wait().await
    }
}

/// A wallet canister interface, for the standard wallet provided by DFINITY.
/// This interface implements most methods conveniently for the user.
#[derive(Debug, Clone)]
pub struct WalletCanister<'agent> {
    canister: Canister<'agent>,
    version: Version,
}

impl<'agent> Deref for WalletCanister<'agent> {
    type Target = Canister<'agent>;
    fn deref(&self) -> &Self::Target {
        &self.canister
    }
}

/// The possible kinds of events that can be stored in an [`Event`].
#[derive(CandidType, Debug, Deserialize)]
pub enum EventKind<TCycles = u128> {
    /// Cycles were sent to a canister.
    CyclesSent {
        /// The canister the cycles were sent to.
        to: Principal,
        /// The number of cycles that were initially sent.
        amount: TCycles,
        /// The number of cycles that were refunded by the canister.
        refund: TCycles,
    },
    /// Cycles were received from a canister.
    CyclesReceived {
        /// The canister that sent the cycles.
        from: Principal,
        /// The number of cycles received.
        amount: TCycles,
        /// The memo provided with the payment.
        memo: Option<String>,
    },
    /// A known principal was added to the address book.
    AddressAdded {
        /// The principal that was added.
        id: Principal,
        /// The friendly name of the principal, if any.
        name: Option<String>,
        /// The significance of this principal to the wallet.
        role: Role,
    },
    /// A principal was removed from the address book.
    AddressRemoved {
        /// The principal that was removed.
        id: Principal,
    },
    /// A canister was created.
    CanisterCreated {
        /// The canister that was created.
        canister: Principal,
        /// The initial cycles balance that the canister was created with.
        cycles: TCycles,
    },
    /// A call was forwarded to the canister.
    CanisterCalled {
        /// The canister that was called.
        canister: Principal,
        /// The name of the canister method that was called.
        method_name: String,
        /// The number of cycles that were supplied with the call.
        cycles: TCycles,
    },
}

impl From<EventKind<u64>> for EventKind {
    fn from(kind: EventKind<u64>) -> Self {
        use EventKind::*;
        match kind {
            AddressAdded { id, name, role } => AddressAdded { id, name, role },
            AddressRemoved { id } => AddressRemoved { id },
            CanisterCalled {
                canister,
                cycles,
                method_name,
            } => CanisterCalled {
                canister,
                cycles: cycles as u128,
                method_name,
            },
            CanisterCreated { canister, cycles } => CanisterCreated {
                canister,
                cycles: cycles as u128,
            },
            CyclesReceived { amount, from, memo } => CyclesReceived {
                amount: amount as u128,
                from,
                memo,
            },
            CyclesSent { amount, refund, to } => CyclesSent {
                amount: amount as u128,
                refund: refund as u128,
                to,
            },
        }
    }
}

/// A transaction event tracked by the wallet's history feature.
#[derive(CandidType, Debug, Deserialize)]
pub struct Event<TCycles = u128> {
    /// An ID uniquely identifying this event.
    pub id: u32,
    /// The Unix timestamp that this event occurred at.
    pub timestamp: u64,
    /// The kind of event that occurred.
    pub kind: EventKind<TCycles>,
}

impl From<Event<u64>> for Event {
    fn from(
        Event {
            id,
            timestamp,
            kind,
        }: Event<u64>,
    ) -> Self {
        Self {
            id,
            timestamp,
            kind: kind.into(),
        }
    }
}

/// The significance of a principal in the wallet's address book.
#[derive(CandidType, Debug, Deserialize)]
pub enum Role {
    /// The principal has no particular significance, and is only there to be assigned a friendly name or be mentioned in the event log.
    Contact,
    /// The principal is a custodian of the wallet, and can therefore access the wallet, create canisters, and send and receive cycles.
    Custodian,
    /// The principal is a controller of the wallet, and can therefore access any wallet function or action.
    Controller,
}

/// The kind of principal that a particular principal is.
#[derive(CandidType, Debug, Deserialize)]
pub enum Kind {
    /// The kind of principal is unknown, such as the anonymous principal `2vxsx-fae`.
    Unknown,
    /// The principal belongs to an external user.
    User,
    /// The principal belongs to an IC canister.
    Canister,
}

/// An entry in the address book.
#[derive(CandidType, Debug, Deserialize)]
pub struct AddressEntry {
    /// The principal being identified.
    pub id: Principal,
    /// The friendly name for this principal, if one exists.
    pub name: Option<String>,
    /// The kind of principal it is.
    pub kind: Kind,
    /// The significance of this principal to the wallet canister.
    pub role: Role,
}

/// A canister that the wallet is responsible for managing.
#[derive(CandidType, Debug, Deserialize)]
pub struct ManagedCanisterInfo {
    /// The principal ID of the canister.
    pub id: Principal,
    /// The friendly name of the canister, if one has been set.
    pub name: Option<String>,
    /// The Unix timestamp that the canister was created at.
    pub created_at: u64,
}

/// The possible kinds of events that can be stored in a [`ManagedCanisterEvent`].
#[derive(CandidType, Debug, Deserialize)]
pub enum ManagedCanisterEventKind<TCycles = u128> {
    /// Cycles were sent to the canister.
    CyclesSent {
        /// The number of cycles that were sent.
        amount: TCycles,
        /// The number of cycles that were refunded.
        refund: TCycles,
    },
    /// A function call was forwarded to the canister.
    Called {
        /// The name of the function that was called.
        method_name: String,
        /// The number of cycles that were provided along with the call.
        cycles: TCycles,
    },
    /// The canister was created.
    Created {
        /// The number of cycles the canister was created with.
        cycles: TCycles,
    },
}

impl From<ManagedCanisterEventKind<u64>> for ManagedCanisterEventKind {
    fn from(event: ManagedCanisterEventKind<u64>) -> Self {
        use ManagedCanisterEventKind::*;
        match event {
            Called {
                cycles,
                method_name,
            } => Called {
                cycles: cycles as u128,
                method_name,
            },
            Created { cycles } => Created {
                cycles: cycles as u128,
            },
            CyclesSent { amount, refund } => CyclesSent {
                amount: amount as u128,
                refund: refund as u128,
            },
        }
    }
}

/// A transaction event related to a [`ManagedCanisterInfo`].
#[derive(CandidType, Deserialize, Debug)]
pub struct ManagedCanisterEvent<TCycles = u128> {
    /// The event ID.
    pub id: u32,
    /// The Unix timestamp the event occurred at.
    pub timestamp: u64,
    /// The kind of event that occurred.
    pub kind: ManagedCanisterEventKind<TCycles>,
}

impl From<ManagedCanisterEvent<u64>> for ManagedCanisterEvent {
    fn from(
        ManagedCanisterEvent {
            id,
            timestamp,
            kind,
        }: ManagedCanisterEvent<u64>,
    ) -> Self {
        Self {
            id,
            timestamp,
            kind: kind.into(),
        }
    }
}

/// The result of a balance request.
#[derive(Debug, Copy, Clone, CandidType, Deserialize)]
pub struct BalanceResult<TCycles = u128> {
    /// The balance of the wallet, in cycles.
    pub amount: TCycles,
}

/// The result of a canister creation request.
#[derive(Debug, Copy, Clone, CandidType, Deserialize)]
pub struct CreateResult {
    /// The principal ID of the newly created (empty) canister.
    pub canister_id: Principal,
}

/// The result of a call forwarding request.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct CallResult {
    /// The encoded return value blob of the canister method.
    #[serde(with = "serde_bytes")]
    pub r#return: Vec<u8>,
}

impl<'agent> WalletCanister<'agent> {
    /// Create an instance of a `WalletCanister` interface pointing to the given Canister ID. Fails if it cannot learn the wallet's version.
    pub async fn create(
        agent: &'agent Agent,
        canister_id: Principal,
    ) -> Result<WalletCanister<'agent>, AgentError> {
        let canister = Canister::builder()
            .with_agent(agent)
            .with_canister_id(canister_id)
            .build()
            .unwrap();
        Self::from_canister(canister).await
    }

    /// Create a `WalletCanister` interface from an existing canister object. Fails if it cannot learn the wallet's version.
    pub async fn from_canister(
        canister: Canister<'agent>,
    ) -> Result<WalletCanister<'agent>, AgentError> {
        static DEFAULT_VERSION: Lazy<Version> = Lazy::new(|| Version::parse("0.1.0").unwrap());
        let version: Result<(String,), _> =
            canister.query_("wallet_api_version").build().call().await;
        let version = match version {
            Err(AgentError::ReplicaError(replica_error))
                if replica_error.reject_code == RejectCode::DestinationInvalid
                    && (replica_error
                        .reject_message
                        .contains(REPLICA_ERROR_NO_SUCH_QUERY_METHOD)
                        || replica_error
                            .reject_message
                            .contains(IC_REF_ERROR_NO_SUCH_QUERY_METHOD)) =>
            {
                DEFAULT_VERSION.clone()
            }
            version => Version::parse(&version?.0).unwrap_or_else(|_| DEFAULT_VERSION.clone()),
        };
        Ok(Self { canister, version })
    }

    /// Create a `WalletCanister` interface from an existing canister object and a known wallet version.
    ///
    /// This interface's methods may raise errors if the provided version is newer than the wallet's actual supported version.
    pub fn from_canister_with_version(canister: Canister<'agent>, version: Version) -> Self {
        Self { canister, version }
    }
}

impl<'agent> WalletCanister<'agent> {
    /// Re-fetch the API version string of the wallet.
    pub fn fetch_wallet_api_version<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Option<String>,)> {
        self.query_("wallet_api_version").build()
    }

    /// Get the (cached) API version of the wallet.
    pub fn wallet_api_version(&self) -> &Version {
        &self.version
    }

    /// Get the friendly name of the wallet (if one exists).
    pub fn name<'canister: 'agent>(&'canister self) -> impl 'agent + SyncCall<(Option<String>,)> {
        self.query_("name").build()
    }

    /// Set the friendly name of the wallet.
    pub fn set_name<'canister: 'agent>(
        &'canister self,
        name: String,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("set_name").with_arg(name).build()
    }

    /// Get the current controller's principal ID.
    pub fn get_controllers<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Vec<Principal>,)> {
        self.query_("get_controllers").build()
    }

    /// Transfer controller to another principal ID.
    pub fn add_controller<'canister: 'agent>(
        &'canister self,
        principal: Principal,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("add_controller").with_arg(principal).build()
    }

    /// Remove a user as a wallet controller.
    pub fn remove_controller<'canister: 'agent>(
        &'canister self,
        principal: Principal,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("remove_controller")
            .with_arg(principal)
            .build()
    }

    /// Get the list of custodians.
    pub fn get_custodians<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Vec<Principal>,)> {
        self.query_("get_custodians").build()
    }

    /// Authorize a new custodian.
    pub fn authorize<'canister: 'agent>(
        &'canister self,
        custodian: Principal,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("authorize").with_arg(custodian).build()
    }

    /// Deauthorize a custodian.
    pub fn deauthorize<'canister: 'agent>(
        &'canister self,
        custodian: Principal,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("deauthorize").with_arg(custodian).build()
    }

    /// Get the balance with the 64-bit API.
    pub fn wallet_balance64<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(BalanceResult<u64>,)> {
        self.query_("wallet_balance").build()
    }

    /// Get the balance with the 128-bit API.
    pub fn wallet_balance128<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(BalanceResult,)> {
        self.query_("wallet_balance128").build()
    }

    /// Get the balance.
    pub async fn wallet_balance<'canister: 'agent>(
        &'canister self,
    ) -> Result<BalanceResult, AgentError> {
        if self.version_supports_u128_cycles() {
            self.wallet_balance128().call().await.map(|(r,)| r)
        } else {
            self.wallet_balance64()
                .call()
                .await
                .map(|(r,)| BalanceResult {
                    amount: r.amount as u128,
                })
        }
    }

    /// Send cycles to another canister using the 64-bit API.
    pub fn wallet_send64<'canister: 'agent>(
        &'canister self,
        destination: Principal,
        amount: u64,
    ) -> impl 'agent + AsyncCall<(Result<(), String>,)> {
        #[derive(CandidType)]
        struct In {
            canister: Principal,
            amount: u64,
        }

        self.update_("wallet_send")
            .with_arg(In {
                canister: destination,
                amount,
            })
            .build()
    }

    /// Send cycles to another canister using the 128-bit API.
    pub fn wallet_send128<'canister: 'agent>(
        &'canister self,
        destination: Principal,
        amount: u128,
    ) -> impl 'agent + AsyncCall<(Result<(), String>,)> {
        #[derive(CandidType)]
        struct In {
            canister: Principal,
            amount: u128,
        }

        self.update_("wallet_send128")
            .with_arg(In {
                canister: destination,
                amount,
            })
            .build()
    }

    /// Send cycles to another canister.
    pub async fn wallet_send<'canister: 'agent>(
        &'canister self,
        destination: Principal,
        amount: u128,
    ) -> Result<(), AgentError> {
        if self.version_supports_u128_cycles() {
            self.wallet_send128(destination, amount)
                .call_and_wait()
                .await?
        } else {
            let amount = u64::try_from(amount).map_err(|_| {
                AgentError::WalletUpgradeRequired(
                    "The installed wallet does not support cycle counts >2^64-1.".to_string(),
                )
            })?;
            self.wallet_send64(destination, amount)
                .call_and_wait()
                .await?
        }
        .0
        .map_err(AgentError::WalletError)
    }

    /// A function for sending cycles to, so that a memo can be passed along with them.
    pub fn wallet_receive<'canister: 'agent>(
        &'canister self,
        memo: Option<String>,
    ) -> impl 'agent + AsyncCall<((),)> {
        #[derive(CandidType)]
        struct In {
            memo: Option<String>,
        }
        self.update_("wallet_receive")
            .with_arg(memo.map(|memo| In { memo: Some(memo) }))
            .build()
    }

    /// Create a canister through the wallet, using the single-controller 64-bit API.
    pub fn wallet_create_canister64_v1<'canister: 'agent>(
        &'canister self,
        cycles: u64,
        controller: Option<Principal>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> impl 'agent + AsyncCall<(Result<CreateResult, String>,)> {
        #[derive(CandidType)]
        struct In {
            cycles: u64,
            settings: CanisterSettingsV1,
        }

        let settings = CanisterSettingsV1 {
            controller,
            compute_allocation: compute_allocation.map(u8::from).map(Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(Nat::from),
        };

        self.update_("wallet_create_canister")
            .with_arg(In { cycles, settings })
            .build()
            .map(|result: (Result<CreateResult, String>,)| (result.0,))
    }

    /// Create a canister through the wallet, using the multi-controller 64-bit API.
    pub fn wallet_create_canister64_v2<'canister: 'agent>(
        &'canister self,
        cycles: u64,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> impl 'agent + AsyncCall<(Result<CreateResult, String>,)> {
        #[derive(CandidType)]
        struct In {
            cycles: u64,
            settings: CanisterSettings,
        }

        let settings = CanisterSettings {
            controllers,
            compute_allocation: compute_allocation.map(u8::from).map(Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(Nat::from),
        };

        self.update_("wallet_create_canister")
            .with_arg(In { cycles, settings })
            .build()
            .map(|result: (Result<CreateResult, String>,)| (result.0,))
    }

    /// Create a canister through the wallet, using the 128-bit API.
    pub fn wallet_create_canister128<'canister: 'agent>(
        &'canister self,
        cycles: u128,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> impl 'agent + AsyncCall<(Result<CreateResult, String>,)> {
        #[derive(CandidType)]
        struct In {
            cycles: u128,
            settings: CanisterSettings,
        }

        let settings = CanisterSettings {
            controllers,
            compute_allocation: compute_allocation.map(u8::from).map(Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(Nat::from),
        };

        self.update_("wallet_create_canister128")
            .with_arg(In { cycles, settings })
            .build()
            .map(|result: (Result<CreateResult, String>,)| (result.0,))
    }

    /// Create a canister through the wallet.
    pub async fn wallet_create_canister<'canister: 'agent>(
        &'canister self,
        cycles: u128,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> Result<CreateResult, AgentError> {
        if self.version_supports_u128_cycles() {
            self.wallet_create_canister128(
                cycles,
                controllers,
                compute_allocation,
                memory_allocation,
                freezing_threshold,
            )
            .call_and_wait()
            .await?
        } else {
            let cycles = u64::try_from(cycles).map_err(|_| {
                AgentError::WalletUpgradeRequired(
                    "The installed wallet does not support cycle counts >2^64-1.".to_string(),
                )
            })?;
            if self.version_supports_multiple_controllers() {
                self.wallet_create_canister64_v2(
                    cycles,
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait()
                .await?
            } else {
                let controller: Option<Principal> = match &controllers {
                    Some(c) if c.len() == 1 => {
                        let first: Option<&Principal> = c.first();
                        let first: Principal = *first.unwrap();
                        Ok(Some(first))
                    }
                    Some(_) => Err(AgentError::WalletUpgradeRequired(
                        "The installed wallet does not support multiple controllers.".to_string(),
                    )),
                    None => Ok(None),
                }?;
                self.wallet_create_canister64_v1(
                    cycles,
                    controller,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait()
                .await?
            }
        }
        .0
        .map_err(AgentError::WalletError)
    }

    /// Create a wallet canister with the single-controller 64-bit API.
    pub fn wallet_create_wallet64_v1<'canister: 'agent>(
        &'canister self,
        cycles: u64,
        controller: Option<Principal>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> impl 'agent + AsyncCall<(Result<CreateResult, String>,)> {
        #[derive(CandidType)]
        struct In {
            cycles: u64,
            settings: CanisterSettingsV1,
        }

        let settings = CanisterSettingsV1 {
            controller,
            compute_allocation: compute_allocation.map(u8::from).map(Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(Nat::from),
        };

        self.update_("wallet_create_wallet")
            .with_arg(In { cycles, settings })
            .build()
            .map(|result: (Result<CreateResult, String>,)| (result.0,))
    }

    /// Create a wallet canister with the multi-controller 64-bit API.
    pub fn wallet_create_wallet64_v2<'canister: 'agent>(
        &'canister self,
        cycles: u64,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> impl 'agent + AsyncCall<(Result<CreateResult, String>,)> {
        #[derive(CandidType)]
        struct In {
            cycles: u64,
            settings: CanisterSettings,
        }

        let settings = CanisterSettings {
            controllers,
            compute_allocation: compute_allocation.map(u8::from).map(Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(Nat::from),
        };

        self.update_("wallet_create_wallet")
            .with_arg(In { cycles, settings })
            .build()
            .map(|result: (Result<CreateResult, String>,)| (result.0,))
    }

    /// Create a wallet canister with the 128-bit API.
    pub fn wallet_create_wallet128<'canister: 'agent>(
        &'canister self,
        cycles: u128,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> impl 'agent + AsyncCall<(Result<CreateResult, String>,)> {
        #[derive(CandidType)]
        struct In {
            cycles: u128,
            settings: CanisterSettings,
        }

        let settings = CanisterSettings {
            controllers,
            compute_allocation: compute_allocation.map(u8::from).map(Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(Nat::from),
        };

        self.update_("wallet_create_wallet128")
            .with_arg(In { cycles, settings })
            .build()
            .map(|result: (Result<CreateResult, String>,)| (result.0,))
    }

    /// Create a wallet canister.
    pub async fn wallet_create_wallet<'canister: 'agent>(
        &'canister self,
        cycles: u128,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
    ) -> Result<CreateResult, AgentError> {
        if self.version_supports_u128_cycles() {
            self.wallet_create_wallet128(
                cycles,
                controllers,
                compute_allocation,
                memory_allocation,
                freezing_threshold,
            )
            .call_and_wait()
            .await?
        } else {
            let cycles = u64::try_from(cycles).map_err(|_| {
                AgentError::WalletUpgradeRequired(
                    "The installed wallet does not support cycle counts >2^64-1.".to_string(),
                )
            })?;
            if self.version_supports_multiple_controllers() {
                self.wallet_create_wallet64_v2(
                    cycles,
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait()
                .await?
            } else {
                let controller: Option<Principal> = match &controllers {
                    Some(c) if c.len() == 1 => Ok(Some(c[0])),
                    Some(_) => Err(AgentError::WalletUpgradeRequired(
                        "The installed wallet does not support multiple controllers.".to_string(),
                    )),
                    None => Ok(None),
                }?;
                self.wallet_create_wallet64_v1(
                    cycles,
                    controller,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait()
                .await?
            }
        }
        .0
        .map_err(AgentError::WalletError)
    }

    /// Store the wallet WASM inside the wallet canister.
    /// This is needed to enable wallet_create_wallet
    pub fn wallet_store_wallet_wasm<'canister: 'agent>(
        &'canister self,
        wasm_module: Vec<u8>,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType, Deserialize)]
        struct In {
            #[serde(with = "serde_bytes")]
            wasm_module: Vec<u8>,
        }
        self.update_("wallet_store_wallet_wasm")
            .with_arg(In { wasm_module })
            .build()
    }

    /// Add a principal to the address book.
    pub fn add_address<'canister: 'agent>(
        &'canister self,
        address: AddressEntry,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("add_address").with_arg(address).build()
    }

    /// List the entries in the address book.
    pub fn list_addresses<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Vec<AddressEntry>,)> {
        self.query_("list_addresses").build()
    }

    /// Remove a principal from the address book.
    pub fn remove_address<'canister: 'agent>(
        &'canister self,
        principal: Principal,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("remove_address").with_arg(principal).build()
    }

    /// Get a list of all transaction events this wallet remembers, using the 64-bit API. Fails if any events are 128-bit.
    pub fn get_events64<'canister: 'agent>(
        &'canister self,
        from: Option<u32>,
        to: Option<u32>,
    ) -> impl 'agent + SyncCall<(Vec<Event<u64>>,)> {
        #[derive(CandidType)]
        struct In {
            from: Option<u32>,
            to: Option<u32>,
        }

        let arg = if from.is_none() && to.is_none() {
            None
        } else {
            Some(In { from, to })
        };

        self.query_("get_events").with_arg(arg).build()
    }

    /// Get a list of all transaction events this wallet remembers, using the 128-bit API.
    pub fn get_events128<'canister: 'agent>(
        &'canister self,
        from: Option<u32>,
        to: Option<u32>,
    ) -> impl 'agent + SyncCall<(Vec<Event>,)> {
        #[derive(CandidType)]
        struct In {
            from: Option<u32>,
            to: Option<u32>,
        }
        let arg = if from.is_none() && to.is_none() {
            None
        } else {
            Some(In { from, to })
        };
        self.query_("get_events128").with_arg(arg).build()
    }

    /// Get a list of all transaction events this wallet remembers.
    pub async fn get_events<'canister: 'agent>(
        &'canister self,
        from: Option<u32>,
        to: Option<u32>,
    ) -> Result<Vec<Event>, AgentError> {
        if self.version_supports_u128_cycles() {
            self.get_events128(from, to)
                .call()
                .await
                .map(|(events,)| events)
        } else {
            self.get_events64(from, to)
                .call()
                .await
                .map(|(events,)| events.into_iter().map(|event| event.into()).collect())
        }
    }

    /// Forward a call to another canister, including an amount of cycles
    /// from the wallet, using the 64-bit API.
    pub fn call64<'canister: 'agent, Out, M: Into<String>>(
        &'canister self,
        destination: Principal,
        method_name: M,
        arg: Argument,
        amount: u64,
    ) -> CallForwarder<'agent, 'canister, Out>
    where
        Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        CallForwarder {
            wallet: self,
            destination,
            method_name: method_name.into(),
            amount: amount as u128,
            arg,
            phantom_out: std::marker::PhantomData,
            u128: false,
        }
    }

    /// Forward a call to another canister, including an amount of cycles
    /// from the wallet, using the 128-bit API.
    pub fn call128<'canister: 'agent, Out, M: Into<String>>(
        &'canister self,
        destination: Principal,
        method_name: M,
        arg: Argument,
        amount: u128,
    ) -> CallForwarder<'agent, 'canister, Out>
    where
        Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        CallForwarder {
            wallet: self,
            destination,
            method_name: method_name.into(),
            amount,
            arg,
            phantom_out: std::marker::PhantomData,
            u128: true,
        }
    }

    /// Forward a call to another canister, including an amount of cycles
    /// from the wallet.
    pub fn call<'canister: 'agent, Out, M: Into<String>>(
        &'canister self,
        destination: Principal,
        method_name: M,
        arg: Argument,
        amount: u128,
    ) -> CallForwarder<'agent, 'canister, Out>
    where
        Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        CallForwarder {
            wallet: self,
            destination,
            method_name: method_name.into(),
            amount,
            arg,
            phantom_out: std::marker::PhantomData,
            u128: self.version_supports_u128_cycles(),
        }
    }

    /// Gets the managed canisters the wallet knows about.
    pub fn list_managed_canisters<'canister: 'agent>(
        &'canister self,
        from: Option<u32>,
        to: Option<u32>,
    ) -> impl 'agent + SyncCall<(Vec<ManagedCanisterInfo>, u32)> {
        #[derive(CandidType)]
        struct In {
            from: Option<u32>,
            to: Option<u32>,
        }
        self.query_("list_managed_canisters")
            .with_arg((In { from, to },))
            .build()
    }

    /// Gets the [`ManagedCanisterEvent`]s for a particular canister, if the wallet knows about that canister, using the 64-bit API.
    pub fn get_managed_canister_events64<'canister: 'agent>(
        &'canister self,
        canister: Principal,
        from: Option<u32>,
        to: Option<u32>,
    ) -> impl 'agent + SyncCall<(Option<Vec<ManagedCanisterEvent<u64>>>,)> {
        #[derive(CandidType)]
        struct In {
            canister: Principal,
            from: Option<u32>,
            to: Option<u32>,
        }
        self.query_("get_managed_canister_events")
            .with_arg((In { canister, from, to },))
            .build()
    }

    /// Gets the [`ManagedCanisterEvent`]s for a particular canister, if the wallet knows about that canister, using the 128-bit API.
    pub fn get_managed_canister_events128<'canister: 'agent>(
        &'canister self,
        canister: Principal,
        from: Option<u32>,
        to: Option<u32>,
    ) -> impl 'agent + SyncCall<(Option<Vec<ManagedCanisterEvent>>,)> {
        #[derive(CandidType)]
        struct In {
            canister: Principal,
            from: Option<u32>,
            to: Option<u32>,
        }
        self.query_("get_managed_canister_events128")
            .with_arg((In { canister, from, to },))
            .build()
    }

    /// Gets the [`ManagedCanisterEvent`]s for a particular canister, if the wallet knows about that canister
    pub async fn get_managed_canister_events<'canister: 'agent>(
        &'canister self,
        canister: Principal,
        from: Option<u32>,
        to: Option<u32>,
    ) -> Result<Option<Vec<ManagedCanisterEvent>>, AgentError> {
        if self.version_supports_u128_cycles() {
            self.get_managed_canister_events128(canister, from, to)
                .call()
                .await
                .map(|(events,)| events)
        } else {
            self.get_managed_canister_events64(canister, from, to)
                .call()
                .await
                .map(|(events,)| {
                    events.map(|events| events.into_iter().map(|event| event.into()).collect())
                })
        }
    }

    /// Gets whether the wallet version supports initializing a canister with multiple controllers (introduced in 0.2.0).
    pub fn version_supports_multiple_controllers(&self) -> bool {
        static CONTROLLERS: Lazy<VersionReq> = Lazy::new(|| VersionReq::parse(">=0.2.0").unwrap());
        CONTROLLERS.matches(&self.version)
    }

    /// Gets whether the wallet version supports 128-bit cycle counts (introduced in 0.3.0).
    pub fn version_supports_u128_cycles(&self) -> bool {
        static U128_CYCLES: Lazy<VersionReq> = Lazy::new(|| VersionReq::parse(">=0.3.0").unwrap());
        U128_CYCLES.matches(&self.version)
    }
}
