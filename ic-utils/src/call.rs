use async_trait::async_trait;
use candid::{CandidType, Decode, Encode};
use delay::Waiter;
use ic_agent::{Agent, AgentError, RequestId};
use ic_types::Principal;
use serde::de::DeserializeOwned;

#[async_trait]
pub trait SyncCall {
    async fn call<T: DeserializeOwned + Send + Sync>(&self) -> Result<T, AgentError>;
}

#[async_trait]
pub trait AsyncCall {
    async fn call(&self) -> Result<RequestId, AgentError>;
    async fn call_and_wait<O, W>(&self, mut waiter: W) -> Result<O, AgentError>
    where
        O: DeserializeOwned + Send + Sync,
        W: Waiter;
}

#[async_trait]
pub trait TypedAsyncCall<O>
where
    O: DeserializeOwned + Send + Sync,
{
    async fn call_and_wait<W>(&self, mut waiter: W) -> Result<O, AgentError>
    where
        W: Waiter;
}

pub struct SyncCaller<'agent, Arg: CandidType + Send + Sync> {
    agent: &'agent Agent,
    canister_id: Principal,
    method_name: String,
    arg: Arg,
}

#[async_trait]
impl<'agent, Arg: CandidType + Send + Sync> SyncCall for SyncCaller<'agent, Arg> {
    async fn call<R>(&self) -> Result<R, AgentError>
    where
        R: DeserializeOwned + Send + Sync,
    {
        let arg = Encode!(&self.arg)?;
        self.agent
            .query_raw(&self.canister_id, &self.method_name, &arg)
            .await
            .and_then(|r| Decode!(&r, R).map_err(AgentError::from))
    }
}

pub struct AsyncCaller<'agent, Arg: CandidType + Send + Sync> {
    pub(crate) agent: &'agent Agent,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Option<Arg>,
}

#[async_trait]
impl<'agent, Arg: CandidType + Send + Sync> AsyncCall for AsyncCaller<'agent, Arg> {
    async fn call(&self) -> Result<RequestId, AgentError> {
        let arg = if let Some(a) = &self.arg {
            Encode!(a)?
        } else {
            Encode!()?
        };
        self.agent
            .update_raw(&self.canister_id, &self.method_name, &arg)
            .await
    }

    async fn call_and_wait<O, W>(&self, waiter: W) -> Result<O, AgentError>
    where
        O: DeserializeOwned + Send + Sync,
        W: Waiter,
    {
        let arg = if let Some(a) = &self.arg {
            Encode!(a)?
        } else {
            Encode!()?
        };
        self.agent
            .update(&self.canister_id, &self.method_name)
            .with_arg(&arg)
            .call_and_wait(waiter)
            .await
            .and_then(|r| Decode!(&r, O).map_err(AgentError::from))
    }
}

pub struct TypedAsyncCaller<
    'agent,
    Arg: CandidType + Send + Sync,
    Out: DeserializeOwned + Send + Sync,
> {
    pub(crate) inner: AsyncCaller<'agent, Arg>,
    pub(crate) phantom_out: std::marker::PhantomData<Out>,
}

#[async_trait]
impl<'agent, Arg: CandidType + Send + Sync, Out: DeserializeOwned + Send + Sync> TypedAsyncCall<Out>
    for TypedAsyncCaller<'agent, Arg, Out>
{
    async fn call_and_wait<W>(&self, waiter: W) -> Result<Out, AgentError>
    where
        W: Waiter,
    {
        self.inner.call_and_wait(waiter).await
    }
}
