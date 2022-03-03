//! The canister interface for the [cycles wallet] canister.
//!
//! [cycles wallet]: https://github.com/dfinity/cycles-wallet

use crate::{
    call::{AsyncCall, AsyncCaller, SyncCall},
    canister::{Argument, CanisterBuilder},
    interfaces::management_canister::{
        attributes::{ComputeAllocation, FreezingThreshold, MemoryAllocation},
        builders::CanisterSettings,
    },
    Canister,
};
use async_trait::async_trait;
use candid::{decode_args, utils::ArgumentDecoder, CandidType, Deserialize, Nat};
use garcon::{Delay, Waiter};
use ic_agent::{agent::UpdateBuilder, export::Principal, Agent, AgentError, RequestId};

const REPLICA_ERROR_NO_SUCH_QUERY_METHOD: &str = "has no query method 'wallet_api_version'";
const IC_REF_ERROR_NO_SUCH_QUERY_METHOD: &str = "query method does not exist";

/// An interface for forwarding a canister method call through the wallet canister via `wallet_canister_call`.
#[derive(Debug)]
pub struct CallForwarder<'agent, 'canister: 'agent, Out>
where
    Self: 'canister,
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    wallet: &'canister Canister<'agent, Wallet>,
    destination: Principal,
    method_name: String,
    amount: u64,
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
        struct In {
            canister: Principal,
            method_name: String,
            #[serde(with = "serde_bytes")]
            args: Vec<u8>,
            cycles: u64,
        }
        Ok(self
            .wallet
            .update_("wallet_call")
            .with_arg(In {
                canister: self.destination,
                method_name: self.method_name,
                args: self.arg.serialize()?.to_vec(),
                cycles: self.amount,
            })
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

    /// Calls the forwarded canister call on the wallet canister, and waits for the result. Equivalent to `.build().call_and_wait(waiter)`.
    pub async fn call_and_wait<W>(self, waiter: W) -> Result<Out, AgentError>
    where
        W: Waiter,
    {
        self.build()?.call_and_wait(waiter).await
    }
}

#[async_trait]
impl<'agent, 'canister: 'agent, Out> AsyncCall<Out> for CallForwarder<'agent, 'canister, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }

    async fn call_and_wait<W>(self, waiter: W) -> Result<Out, AgentError>
    where
        W: Waiter,
    {
        self.call_and_wait(waiter).await
    }
}

/// A wallet canister interface, for the standard wallet provided by DFINITY.
/// This interface implements most methods conveniently for the user.
#[derive(Debug, Copy, Clone)]
pub struct Wallet;

/// The possible kinds of events that can be stored in an [`Event`].
#[derive(CandidType, Debug, Deserialize)]
pub enum EventKind {
    /// Cycles were sent to a canister.
    CyclesSent {
        /// The canister the cycles were sent to.
        to: Principal,
        /// The number of cycles that were initially sent.
        amount: u64,
        /// The number of cycles that were refunded by the canister.
        refund: u64,
    },
    /// Cycles were received from a canister.
    CyclesReceived {
        /// The canister that sent the cycles.
        from: Principal,
        /// The number of cycles received.
        amount: u64,
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
        cycles: u64,
    },
    /// A call was forwarded to the canister.
    CanisterCalled {
        /// The canister that was called.
        canister: Principal,
        /// The name of the canister method that was called.
        method_name: String,
        /// The number of cycles that were supplied with the call.
        cycles: u64,
    },
}

/// A transaction event tracked by the wallet's history feature.
#[derive(CandidType, Debug, Deserialize)]
pub struct Event {
    /// An ID uniquely identifying this event.
    pub id: u32,
    /// The Unix timestamp that this event occurred at.
    pub timestamp: u64,
    /// The kind of event that occurred.
    pub kind: EventKind,
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

/// The result of a balance request.
#[derive(Debug, Copy, Clone, CandidType, Deserialize)]
pub struct BalanceResult {
    /// The balance of the wallet, in cycles.
    pub amount: u64,
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

impl Wallet {
    /// Create an instance of a [Canister] implementing the Wallet interface
    /// and pointing to the right Canister ID.
    pub fn create(agent: &Agent, canister_id: Principal) -> Canister<Wallet> {
        Canister::builder()
            .with_agent(agent)
            .with_canister_id(canister_id)
            .with_interface(Wallet)
            .build()
            .unwrap()
    }

    /// Creating a CanisterBuilder with the right interface and Canister Id. This can
    /// be useful, for example, for providing additional Builder information.
    pub fn with_agent(agent: &Agent) -> CanisterBuilder<Wallet> {
        Canister::builder().with_agent(agent).with_interface(Wallet)
    }
}

impl<'agent> Canister<'agent, Wallet> {
    /// Get the API version string of the wallet.
    pub fn wallet_api_version<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Option<String>,)> {
        self.query_("wallet_api_version").build()
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

    /// Get the balance.
    pub fn wallet_balance<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(BalanceResult,)> {
        self.query_("wallet_balance").build()
    }

    /// Send cycles to another (hopefully Wallet) canister.
    pub fn wallet_send<'canister: 'agent>(
        &'canister self,
        destination: &'_ Canister<'agent, Wallet>,
        amount: u64,
    ) -> impl 'agent + AsyncCall<(Result<(), String>,)> {
        #[derive(CandidType)]
        struct In {
            canister: Principal,
            amount: u64,
        }

        self.update_("wallet_send")
            .with_arg(In {
                canister: *destination.canister_id_(),
                amount,
            })
            .build()
    }

    /// Send cycles to another (hopefully Wallet) canister.
    pub fn wallet_receive<'canister: 'agent>(&'canister self) -> impl 'agent + AsyncCall<((),)> {
        self.update_("wallet_receive").build()
    }

    /// Wallet API version 0.1.0 only accepts a single controller
    pub fn wallet_create_canister_v1<'canister: 'agent>(
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

    /// Wallet API version >= 0.2.0 accepts multiple controllers
    pub fn wallet_create_canister_v2<'canister: 'agent>(
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

    /// Call wallet_create_canister_v1 or wallet_create_canister_v2, depending
    /// on the cycles wallet version.
    pub async fn wallet_create_canister<'canister: 'agent>(
        &'canister self,
        cycles: u64,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
        waiter: Delay,
    ) -> Result<CreateResult, AgentError> {
        match self.wallet_api_version().call().await {
            Ok(_) => self
                .wallet_create_canister_v2(
                    cycles,
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait(waiter)
                .await?
                .0
                .map_err(AgentError::WalletError),
            Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }) if reject_code == 3
                && (reject_message.contains(REPLICA_ERROR_NO_SUCH_QUERY_METHOD)
                    || reject_message.contains(IC_REF_ERROR_NO_SUCH_QUERY_METHOD)) =>
            {
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
                self.wallet_create_canister_v1(
                    cycles,
                    controller,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait(waiter)
                .await?
                .0
                .map_err(AgentError::WalletError)
            }
            Err(other_err) => Err(other_err),
        }
    }

    /// Create a wallet canister
    pub fn wallet_create_wallet_v1<'canister: 'agent>(
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

    /// Create a wallet canister
    pub fn wallet_create_wallet_v2<'canister: 'agent>(
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

    /// Call wallet_create_wallet_v1 or wallet_create_wallet_v2, depending
    /// on the cycles wallet version.
    pub async fn wallet_create_wallet<'canister: 'agent>(
        &'canister self,
        cycles: u64,
        controllers: Option<Vec<Principal>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        freezing_threshold: Option<FreezingThreshold>,
        waiter: Delay,
    ) -> Result<CreateResult, AgentError> {
        match self.wallet_api_version().call().await {
            Ok(_) => self
                .wallet_create_wallet_v2(
                    cycles,
                    controllers,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait(waiter)
                .await?
                .0
                .map_err(AgentError::WalletError),
            Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }) if reject_code == 3
                && (reject_message.contains("has no query method 'wallet_api_version'")
                    || reject_message.contains("query method does not exist")) =>
            // ic-ref
            {
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
                self.wallet_create_wallet_v1(
                    cycles,
                    controller,
                    compute_allocation,
                    memory_allocation,
                    freezing_threshold,
                )
                .call_and_wait(waiter)
                .await?
                .0
                .map_err(AgentError::WalletError)
            }
            Err(other_err) => Err(other_err),
        }
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

    /// Get a list of all transaction events this wallet remembers.
    pub fn get_events<'canister: 'agent>(
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

        self.query_("get_events").with_arg(arg).build()
    }

    /// Forward a call to another canister, including an amount of cycles
    /// from the wallet.
    pub fn call<'canister: 'agent, Out, M: Into<String>>(
        &'canister self,
        destination: &'canister Canister<'canister>,
        method_name: M,
        arg: Argument,
        amount: u64,
    ) -> CallForwarder<'agent, 'canister, Out>
    where
        Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        CallForwarder {
            wallet: self,
            destination: *destination.canister_id_(),
            method_name: method_name.into(),
            amount,
            arg,
            phantom_out: std::marker::PhantomData,
        }
    }

    /// Forward a call using another call's builder. This takes an UpdateBuilder,
    /// marshalls it to a buffer, and sends it through the wallet canister, adding
    /// a separate amount.
    pub fn call_forward<'canister: 'agent, Out: 'agent>(
        &'canister self,
        call: AsyncCaller<'agent, Out>,
        amount: u64,
    ) -> Result<impl 'agent + AsyncCall<Out>, AgentError>
    where
        Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        let UpdateBuilder {
            canister_id,
            method_name,
            arg,
            ..
        } = call.build_call()?;
        let mut argument = Argument::default();
        argument.set_raw_arg(arg);

        CallForwarder {
            wallet: self,
            destination: canister_id,
            method_name,
            amount,
            arg: argument,
            phantom_out: std::marker::PhantomData,
        }
        .build()
    }
}
