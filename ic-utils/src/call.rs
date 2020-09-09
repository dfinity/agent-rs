use async_trait::async_trait;
use candid::{CandidType, Decode, Encode};
use delay::Waiter;
use ic_agent::{Agent, AgentError, RequestId};
use ic_types::Principal;

/// A type that implements synchronous calls (ie. 'query' calls).
#[async_trait]
pub trait SyncCall {
    async fn call<T: serde::de::DeserializeOwned + Send + Sync>(&self) -> Result<T, AgentError>;
}

/// A type that implements asynchronous calls (ie. 'update' calls).
/// This can call synchronous and return a [RequestId], or it can wait for the result
/// by polling the agent, and return a type.
#[async_trait]
pub trait AsyncCall {
    async fn call(&self) -> Result<RequestId, AgentError>;
    async fn call_and_wait<O, W>(&self, mut waiter: W) -> Result<O, AgentError>
    where
        O: serde::de::DeserializeOwned + Send + Sync,
        W: Waiter;
}

/// A type that implements asynchronous calls, where the type of the result is
/// known ahead of time.
#[async_trait]
pub trait TypedAsyncCall<O>
where
    O: serde::de::DeserializeOwned + Send + Sync,
{
    async fn call_and_wait<W>(&self, mut waiter: W) -> Result<O, AgentError>
    where
        W: Waiter;
}

/// A synchronous call encapsulation.
pub struct SyncCaller<'agent, Arg: CandidType + Send + Sync> {
    agent: &'agent Agent,
    canister_id: Principal,
    method_name: String,
    arg: Arg,
}

impl<'agent, Arg: CandidType + Send + Sync> SyncCaller<'agent, Arg> {
    async fn call<R>(&self) -> Result<R, AgentError>
    where
        R: serde::de::DeserializeOwned + Send + Sync,
    {
        let arg = Encode!(&self.arg)?;
        self.agent
            .query_raw(&self.canister_id, &self.method_name, &arg)
            .await
            .and_then(|r| Decode!(&r, R).map_err(AgentError::from))
    }
}

#[async_trait]
impl<'agent, Arg: CandidType + Send + Sync> SyncCall for SyncCaller<'agent, Arg> {
    async fn call<R>(&self) -> Result<R, AgentError>
    where
        R: serde::de::DeserializeOwned + Send + Sync,
    {
        self.call().await
    }
}

/// An Asynchronous caller, implementing AsyncCall.
pub struct AsyncCaller<'agent, Arg: CandidType + Send + Sync> {
    pub(crate) agent: &'agent Agent,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Option<Arg>,
}

impl<'agent, Arg: CandidType + Send + Sync> AsyncCaller<'agent, Arg> {
    pub async fn call(&self) -> Result<RequestId, AgentError> {
        let arg = if let Some(a) = &self.arg {
            Encode!(a)?
        } else {
            Encode!()?
        };
        self.agent
            .update_raw(&self.canister_id, &self.method_name, &arg)
            .await
    }

    pub async fn call_and_wait<O, W>(&self, waiter: W) -> Result<O, AgentError>
    where
        O: serde::de::DeserializeOwned + Send + Sync,
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

#[async_trait]
impl<'agent, Arg: CandidType + Send + Sync> AsyncCall for AsyncCaller<'agent, Arg> {
    async fn call(&self) -> Result<RequestId, AgentError> {
        self.call().await
    }
    async fn call_and_wait<O, W>(&self, waiter: W) -> Result<O, AgentError>
    where
        O: serde::de::DeserializeOwned + Send + Sync,
        W: Waiter,
    {
        self.call_and_wait(waiter).await
    }
}

pub struct TypedAsyncCaller<'agent, Arg, Out>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
{
    pub(crate) inner: AsyncCaller<'agent, Arg>,
    pub(crate) phantom_out: std::marker::PhantomData<Out>,
}

impl<'agent, Arg, Out> TypedAsyncCaller<'agent, Arg, Out>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
{
    pub async fn call(&self) -> Result<RequestId, AgentError> {
        self.inner.call().await
    }

    pub async fn call_and_wait<W>(&self, waiter: W) -> Result<Out, AgentError>
    where
        W: Waiter,
    {
        self.inner.call_and_wait(waiter).await
    }

    pub fn and_then<Out2, AndThen>(
        self,
        and_then: AndThen,
    ) -> AndThenTypedAsyncCaller<'agent, Arg, Out, Out2, AndThen>
    where
        Out2: serde::de::DeserializeOwned + Send + Sync,
        AndThen: Sync + Send + Fn(Out) -> Out2,
    {
        AndThenTypedAsyncCaller {
            inner: self,
            and_then,
        }
    }
}

pub struct AndThenTypedAsyncCaller<
    'agent,
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
    Out2: serde::de::DeserializeOwned + Send + Sync,
    AndThen: Sync + Send + Fn(Out) -> Out2,
> {
    pub(crate) inner: TypedAsyncCaller<'agent, Arg, Out>,
    pub(crate) and_then: AndThen,
}

impl<'agent, Arg, Out, Out2, AndThen> AndThenTypedAsyncCaller<'agent, Arg, Out, Out2, AndThen>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
    Out2: serde::de::DeserializeOwned + Send + Sync,
    AndThen: Sync + Send + Fn(Out) -> Out2,
{
    pub async fn call_and_wait<W>(&self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        let v = self.inner.call_and_wait(waiter).await?;

        Ok((self.and_then)(v))
    }
}

#[async_trait]
impl<'agent, Arg, Out, Out2, AndThen> TypedAsyncCall<Out2>
    for AndThenTypedAsyncCaller<'agent, Arg, Out, Out2, AndThen>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
    Out2: serde::de::DeserializeOwned + Send + Sync,
    AndThen: Sync + Send + Fn(Out) -> Out2,
{
    async fn call_and_wait<W>(&self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        self.call_and_wait(waiter).await
    }
}
