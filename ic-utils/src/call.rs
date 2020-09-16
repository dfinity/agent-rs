use async_trait::async_trait;
use candid::de::ArgumentDecoder;
use candid::{decode_args, decode_one};
use delay::Waiter;
use ic_agent::{Agent, AgentError, RequestId};
use ic_types::Principal;
use serde::de::DeserializeOwned;
use std::future::Future;

/// A type that implements synchronous calls (ie. 'query' calls).
#[async_trait]
pub trait SyncCall<O>
where
    O: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    /// Execute the call, returning either the value returned by the canister, or an
    /// error returned by the Agent.
    async fn call(self) -> Result<O, AgentError>;
}

/// A type that implements asynchronous calls (ie. 'update' calls).
/// This can call synchronous and return a [RequestId], or it can wait for the result
/// by polling the agent, and return a type.
///
/// The return type must be a tuple type that represents all the values the return
/// call should be returning.
#[async_trait]
pub trait AsyncCall<O>
where
    O: for<'de> ArgumentDecoder<'de> + Send + Sync,
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
    async fn call(self) -> Result<RequestId, AgentError>;

    /// Execute the call, and wait for an answer using a [Waiter] strategy. The return
    /// type is encoded in the trait.
    async fn call_and_wait<W>(self, mut waiter: W) -> Result<O, AgentError>
    where
        W: Waiter;
}

/// A synchronous call encapsulation.
#[derive(Clone)]
pub struct SyncCaller<'agent> {
    agent: &'agent Agent,
    canister_id: Principal,
    method_name: String,
    arg: Vec<u8>,
}

impl<'agent> SyncCaller<'agent> {
    /// Perform the call, consuming the the abstraction.
    async fn call<R>(self) -> Result<R, AgentError>
    where
        R: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        self.agent
            .query_raw(&self.canister_id, &self.method_name, &self.arg)
            .await
            .and_then(|r| decode_args(&r).map_err(AgentError::from))
    }
}

#[async_trait]
impl<'agent, O> SyncCall<O> for SyncCaller<'agent>
where
    O: 'agent + for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    async fn call(self) -> Result<O, AgentError> {
        Ok(self.call().await?)
    }
}

/// An async caller, encapsulating a call to an update method.
pub struct AsyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    pub(crate) agent: &'agent Agent,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Result<Vec<u8>, candid::Error>,
    pub(crate) phantom_out: std::marker::PhantomData<Out>,
}

impl<'agent, Out> AsyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
{
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.agent
            .update(&self.canister_id, &self.method_name)
            .with_arg(&self.arg?)
            .call()
            .await
    }

    pub async fn call_and_wait<W>(self, waiter: W) -> Result<Out, AgentError>
    where
        W: Waiter,
    {
        self.agent
            .update(&self.canister_id, &self.method_name)
            .with_arg(&self.arg?)
            .call_and_wait(waiter)
            .await
            .and_then(|r| decode_args(&r).map_err(AgentError::from))
    }

    pub async fn call_and_wait_one<W, T>(self, waiter: W) -> Result<T, AgentError>
    where
        W: Waiter,
        T: DeserializeOwned,
    {
        self.agent
            .update(&self.canister_id, &self.method_name)
            .with_arg(&self.arg?)
            .call_and_wait(waiter)
            .await
            .and_then(|r| decode_one(&r).map_err(AgentError::from))
    }

    pub fn and_then<Out2, R, AndThen>(
        self,
        and_then: AndThen,
    ) -> AndThenAsyncCaller<Out, Out2, Self, R, AndThen>
    where
        Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
        R: Future<Output = Result<Out2, AgentError>> + Send + Sync,
        AndThen: Sync + Send + Fn(Out) -> R,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    pub fn map<Out2, Map>(self, map: Map) -> MappedAsyncCaller<Out, Out2, Self, Map>
    where
        Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
        Map: Sync + Send + Fn(Out) -> Out2,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[async_trait]
impl<'agent, Out> AsyncCall<Out> for AsyncCaller<'agent, Out>
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

/// An AsyncCall that applies a transform function to the result of the call. Because of
/// constraints on the type system in Rust, both the input and output to the function must be
/// deserializable.
pub struct AndThenAsyncCaller<
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Inner: AsyncCall<Out> + Sync + Send,
    R: Future<Output = Result<Out2, AgentError>> + Send + Sync,
    AndThen: Sync + Send + Fn(Out) -> R,
> {
    inner: Inner,
    and_then: AndThen,
    _out: std::marker::PhantomData<Out>,
    _out2: std::marker::PhantomData<Out2>,
}

impl<Out, Out2, Inner, R, AndThen> AndThenAsyncCaller<Out, Out2, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Inner: AsyncCall<Out> + Sync + Send,
    R: Future<Output = Result<Out2, AgentError>> + Send + Sync,
    AndThen: Sync + Send + Fn(Out) -> R,
{
    pub fn new(inner: Inner, and_then: AndThen) -> Self {
        Self {
            inner,
            and_then,
            _out: std::marker::PhantomData,
            _out2: std::marker::PhantomData,
        }
    }

    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.inner.call().await
    }
    pub async fn call_and_wait<W>(self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        let v = self.inner.call_and_wait(waiter).await?;

        let f = (self.and_then)(v);

        f.await
    }

    pub fn and_then<Out3, R2, AndThen2>(
        self,
        and_then: AndThen2,
    ) -> AndThenAsyncCaller<Out2, Out3, Self, R2, AndThen2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + Sync,
        R2: Future<Output = Result<Out3, AgentError>> + Send + Sync,
        AndThen2: Sync + Send + Fn(Out2) -> R2,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    pub fn map<Out3, Map>(self, map: Map) -> MappedAsyncCaller<Out2, Out3, Self, Map>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + Sync,
        Map: Sync + Send + Fn(Out2) -> Out3,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[async_trait]
impl<Out, Out2, Inner, R, AndThen> AsyncCall<Out2>
    for AndThenAsyncCaller<Out, Out2, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Inner: AsyncCall<Out> + Sync + Send,
    R: Future<Output = Result<Out2, AgentError>> + Send + Sync,
    AndThen: Sync + Send + Fn(Out) -> R,
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }

    async fn call_and_wait<W>(self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        self.call_and_wait(waiter).await
    }
}

/// A structure that applies a transform function to the result of a call. Because of constraints
/// on the type system in Rust, both the input and output to the function must be deserializable.
pub struct MappedAsyncCaller<
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Inner: AsyncCall<Out> + Sync + Send,
    Map: Sync + Send + Fn(Out) -> Out2,
> {
    inner: Inner,
    map: Map,
    _out: std::marker::PhantomData<Out>,
    _out2: std::marker::PhantomData<Out2>,
}

impl<Out, Out2, Inner, Map> MappedAsyncCaller<Out, Out2, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Inner: AsyncCall<Out> + Sync + Send,
    Map: Sync + Send + Fn(Out) -> Out2,
{
    pub fn new(inner: Inner, map: Map) -> Self {
        Self {
            inner,
            map,
            _out: std::marker::PhantomData,
            _out2: std::marker::PhantomData,
        }
    }

    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.inner.call().await
    }
    pub async fn call_and_wait<W>(self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        let v = self.inner.call_and_wait(waiter).await?;
        Ok((self.map)(v))
    }

    pub fn and_then<Out3, R2, AndThen2>(
        self,
        and_then: AndThen2,
    ) -> AndThenAsyncCaller<Out2, Out3, Self, R2, AndThen2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + Sync,
        R2: Future<Output = Result<Out3, AgentError>> + Send + Sync,
        AndThen2: Sync + Send + Fn(Out2) -> R2,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    pub fn map<Out3, Map2>(self, map: Map2) -> MappedAsyncCaller<Out2, Out3, Self, Map2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + Sync,
        Map2: Sync + Send + Fn(Out2) -> Out3,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[async_trait]
impl<Out, Out2, Inner, Map> AsyncCall<Out2> for MappedAsyncCaller<Out, Out2, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Out2: for<'de> ArgumentDecoder<'de> + Send + Sync,
    Inner: AsyncCall<Out> + Sync + Send,
    Map: Sync + Send + Fn(Out) -> Out2,
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }

    async fn call_and_wait<W>(self, waiter: W) -> Result<Out2, AgentError>
    where
        W: Waiter,
    {
        self.call_and_wait(waiter).await
    }
}
