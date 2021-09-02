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
use candid::{decode_args, utils::ArgumentDecoder, CandidType, Deserialize};
use garcon::{Delay, Waiter};
use ic_agent::{agent::UpdateBuilder, export::Principal, Agent, AgentError, RequestId};

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

#[derive(CandidType, Deserialize)]
pub struct CanisterSettingsV1 {
    pub controller: Option<Principal>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
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

    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

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
pub struct Wallet;

#[derive(CandidType, Debug, Deserialize)]
pub enum EventKind {
    CyclesSent {
        to: Principal,
        amount: u64,
        refund: u64,
    },
    CyclesReceived {
        from: Principal,
        amount: u64,
    },
    AddressAdded {
        id: Principal,
        name: Option<String>,
        role: Role,
    },
    AddressRemoved {
        id: Principal,
    },
    CanisterCreated {
        canister: Principal,
        cycles: u64,
    },
    CanisterCalled {
        canister: Principal,
        method_name: String,
        cycles: u64,
    },
}

#[derive(CandidType, Debug, Deserialize)]
pub struct Event {
    pub id: u32,
    pub timestamp: u64,
    pub kind: EventKind,
}

#[derive(CandidType, Debug, Deserialize)]
pub enum Role {
    Contact,
    Custodian,
    Controller,
}

#[derive(CandidType, Debug, Deserialize)]
pub enum Kind {
    Unknown,
    User,
    Canister,
}

#[derive(CandidType, Debug, Deserialize)]
pub struct AddressEntry {
    pub id: Principal,
    pub name: Option<String>,
    pub kind: Kind,
    pub role: Role,
}

#[derive(CandidType, Deserialize)]
pub struct BalanceResult {
    pub amount: u64,
}

#[derive(CandidType, Deserialize)]
pub struct CreateResult {
    pub canister_id: Principal,
}

#[derive(CandidType, Deserialize)]
pub struct CallResult {
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
    pub fn wallet_api_version<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Option<String>,)> {
        self.query_("wallet_api_version").build()
    }

    pub fn name<'canister: 'agent>(&'canister self) -> impl 'agent + SyncCall<(Option<String>,)> {
        self.query_("name").build()
    }

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
            compute_allocation: compute_allocation.map(u8::from).map(candid::Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(candid::Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(candid::Nat::from),
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
            compute_allocation: compute_allocation.map(u8::from).map(candid::Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(candid::Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(candid::Nat::from),
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
                .map_err(AgentError::WalletCallFailed), // todo
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
                .map_err(AgentError::WalletCallFailed) // todo
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
            compute_allocation: compute_allocation.map(u8::from).map(candid::Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(candid::Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(candid::Nat::from),
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
            compute_allocation: compute_allocation.map(u8::from).map(candid::Nat::from),
            memory_allocation: memory_allocation.map(u64::from).map(candid::Nat::from),
            freezing_threshold: freezing_threshold.map(u64::from).map(candid::Nat::from),
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
                .map_err(AgentError::WalletCallFailed), // todo
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
                .map_err(AgentError::WalletCallFailed) // todo
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

    pub fn add_address<'canister: 'agent>(
        &'canister self,
        address: AddressEntry,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("add_address").with_arg(address).build()
    }

    pub fn list_addresses<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Vec<AddressEntry>,)> {
        self.query_("list_addresses").build()
    }

    pub fn remove_address<'canister: 'agent>(
        &'canister self,
        principal: Principal,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("remove_address").with_arg(principal).build()
    }

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
