use async_trait::async_trait;
use candid::{CandidType, Decode, Encode};
use delay::Waiter;
use ic_agent::{Agent, AgentError, RequestId};
use ic_types::Principal;
use serde::de::DeserializeOwned;
use std::future::Future;

/// A type that implements synchronous calls (ie. 'query' calls).
#[async_trait]
pub trait SyncCall {
    /// Execute the call, returning either the value returned by the canister, or an
    /// error returned by the Agent.
    async fn call<T: serde::de::DeserializeOwned + Send + Sync>(&self) -> Result<T, AgentError>;
}

/// A type that implements asynchronous calls (ie. 'update' calls).
/// This can call synchronous and return a [RequestId], or it can wait for the result
/// by polling the agent, and return a type.
#[async_trait]
pub trait AsyncCall<O>
where
    O: serde::de::DeserializeOwned + Send + Sync,
{
    /// Execute the call, but returns the RequestId. Waiting on the request Id must be
    /// managed by the caller using the Agent directly.
    ///
    /// Since the return type is encoded in the trait itself, this can lead to types
    /// that are not compatible to [O] when getting the result from the Request Id.
    /// For example, you might hold a [AsyncCall<u8>], use `call()` and poll for
    /// the result, and try to deserialize it as a [String]. This would be caught by
    /// Rust type system, but in this case it will be checked at runtime (as Request
    /// Id does not have a type associated with it).
    async fn call(&self) -> Result<RequestId, AgentError>;

    /// Execute the call, and wait for an answer using a [Waiter] strategy. The return
    /// type is encoded in the trait.
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

/// An async caller, encapsulating a call to an update method.
pub struct AsyncCaller<'agent, Arg, Out>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
{
    pub(crate) agent: &'agent Agent,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Option<Arg>,
    pub(crate) phantom_out: std::marker::PhantomData<Out>,
}

impl<'agent, Arg, Out> AsyncCaller<'agent, Arg, Out>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
{
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

    pub async fn call_and_wait<W>(&self, waiter: W) -> Result<Out, AgentError>
    where
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
            .and_then(|r| Decode!(&r, Out).map_err(AgentError::from))
    }

    pub fn and_then<Out2, R, AndThen>(
        self,
        and_then: AndThen,
    ) -> AndThenAsyncCaller<'agent, Arg, Out, Out2, R, AndThen>
    where
        Out2: serde::de::DeserializeOwned + Send + Sync,
        R: Future<Output = Result<Out2, AgentError>>,
        AndThen: Sync + Send + Fn(Out) -> R,
    {
        AndThenAsyncCaller {
            inner: self,
            and_then,
        }
    }
}

#[async_trait]
impl<'agent, Arg, Out> AsyncCall<Out> for AsyncCaller<'agent, Arg, Out>
where
    Arg: CandidType + Send + Sync,
    Out: DeserializeOwned + Send + Sync,
{
    async fn call(&self) -> Result<RequestId, AgentError> {
        self.call().await
    }
    async fn call_and_wait<W>(&self, waiter: W) -> Result<Out, AgentError>
    where
        W: Waiter,
    {
        self.call_and_wait(waiter).await
    }
}

/// A structure that applies a transform function to the result of a call. Because of constraints
/// on the type system in Rust, both the input and output to the function must be deserializable.
pub struct AndThenAsyncCaller<
    'agent,
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
    Out2: serde::de::DeserializeOwned + Send + Sync,
    R: Future<Output = Result<Out2, AgentError>>,
    AndThen: Sync + Send + Fn(Out) -> R,
> {
    pub(crate) inner: AsyncCaller<'agent, Arg, Out>,
    pub(crate) and_then: AndThen,
}

impl<'agent, Arg, Out, Out2, R, AndThen> AndThenAsyncCaller<'agent, Arg, Out, Out2, R, AndThen>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
    Out2: serde::de::DeserializeOwned + Send + Sync,
    R: Future<Output = Result<Out2, AgentError>>,
    AndThen: Sync + Send + Fn(Out) -> R,
{
    pub async fn call(&self) -> Result<RequestId, AgentError> {
        self.inner.call().await
    }
    pub async fn call_and_wait<W>(&self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        let v = self.inner.call_and_wait(waiter).await?;

        (self.and_then)(v).await
    }
}

#[async_trait]
impl<'agent, Arg, Out, Out2, R, AndThen> AsyncCall<Out2>
    for AndThenAsyncCaller<'agent, Arg, Out, Out2, R, AndThen>
where
    Arg: CandidType + Send + Sync,
    Out: serde::de::DeserializeOwned + Send + Sync,
    Out2: serde::de::DeserializeOwned + Send + Sync,
    AndThen: Sync + Send + Fn(Out) -> Out2,
{
    async fn call(&self) -> Result<RequestId, AgentError> {
        self.call().await
    }

    async fn call_and_wait<W>(&self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        self.call_and_wait(waiter).await
    }
}
