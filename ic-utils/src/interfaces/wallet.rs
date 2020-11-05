use crate::call::{AsyncCall, AsyncCaller, SyncCall};
use crate::canister::{Argument, CanisterBuilder};
use crate::Canister;
use async_trait::async_trait;
use candid::de::ArgumentDecoder;
use candid::{decode_args, CandidType};
use delay::Waiter;
use ic_agent::agent::UpdateBuilder;
use ic_agent::export::Principal;
use ic_agent::{Agent, AgentError, RequestId};

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
        Ok(self
            .wallet
            .update_("call")
            .with_arg(self.destination)
            .with_arg(self.method_name)
            .with_arg(self.arg.serialize()?.to_vec())
            .with_arg(self.amount)
            .build()
            .and_then(|(result,): (Vec<u8>,)| async move {
                decode_args::<Out>(result.as_slice())
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
/// This interface implement most methods conveniently for the user.
pub struct Wallet;

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
    /// Get the current controller's principal ID.
    pub fn get_controller<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + SyncCall<(Principal,)> {
        self.query_("get_controller").build()
    }

    /// Transfer controller to another principal ID.
    pub fn set_controller<'canister: 'agent>(
        &'canister self,
        principal: Principal,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("set_controller").with_arg(principal).build()
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
    pub fn cycle_balance<'canister: 'agent>(&'canister self) -> impl 'agent + SyncCall<(u64,)> {
        self.query_("cycle_balance").build()
    }

    /// Send cycles to another (hopefully Wallet) canister.
    pub fn send_cycles<'canister: 'agent>(
        &'canister self,
        destination: &'_ Canister<'agent, Wallet>,
        amount: u64,
    ) -> impl 'agent + AsyncCall<()> {
        self.update_("send_cycles")
            .with_arg(destination.canister_id_())
            .with_arg(amount)
            .build()
    }

    /// Forward a call to another canister, including an amount of cycles
    /// from the wallet.
    pub fn call<'canister: 'agent, Out, M: Into<String>>(
        &'canister self,
        destination: &'canister Canister<'canister>,
        method_name: M,
        amount: u64,
    ) -> CallForwarder<'agent, 'canister, Out>
    where
        Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        CallForwarder {
            wallet: self,
            destination: destination.canister_id_().clone(),
            method_name: method_name.into(),
            amount,
            arg: Argument::default(),
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
