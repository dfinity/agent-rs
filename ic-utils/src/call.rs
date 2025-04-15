use async_trait::async_trait;
use candid::{decode_args, decode_one, utils::ArgumentDecoder, CandidType};
use ic_agent::{
    agent::{CallResponse, UpdateBuilder},
    export::Principal,
    Agent,
};
use serde::de::DeserializeOwned;
use std::error::Error;
use std::fmt;
use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::pin::Pin;

mod expiry;
pub use expiry::Expiry;

/// A type that implements synchronous calls (ie. 'query' calls).
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait SyncCall: CallIntoFuture<Output = Result<Self::Value, Self::Error>> {
    /// The return type of the Candid function being called.
    type Value: for<'de> ArgumentDecoder<'de> + Send;
    /// The error type of the operation.
    type Error: Error;
    /// Execute the call, returning an array of bytes directly from the canister.
    #[cfg(feature = "raw")]
    async fn call_raw(self) -> Result<Vec<u8>, Self::Error>;

    /// Execute the call, returning a decoded response object.
    async fn call(self) -> Result<Self::Value, Self::Error>
    where
        Self: Sized + Send,
        Self::Value: 'async_trait;

    /// Apply a transformation function to the error after the call fails.
    fn map_err<'a, E, F>(self, f: F) -> MapErrSyncCaller<'a, Self, E, F>
    where
        Self: Sized + Send + 'a,
        E: CanisterError + 'a,
        F: FnOnce(Self::Error) -> E + Send + 'a,
    {
        MapErrSyncCaller::new(self, f)
    }
}

/// A type that implements asynchronous calls (ie. 'update' calls).
/// This can call synchronous and return a [`RequestId`](ic_agent::RequestId), or it can wait for the result
/// by polling the agent, and return a type.
///
/// The return type must be a tuple type that represents all the values the return
/// call should be returning.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait AsyncCall: CallIntoFuture<Output = Result<Self::Value, Self::Error>> {
    /// The return type of the Candid function being called.
    type Value: for<'de> ArgumentDecoder<'de> + Send;
    /// The error type of the operation.
    type Error: CanisterError;
    /// Execute the call, but returns the `RequestId`. Waiting on the request Id must be
    /// managed by the caller using the Agent directly.
    ///
    /// Since the return type is encoded in the trait itself, this can lead to types
    /// that are not compatible to `Out` when getting the result from the Request Id.
    /// For example, you might hold a [`AsyncCall<u8>`], use `call()` and poll for
    /// the result, and try to deserialize it as a [`String`]. This would be caught by
    /// Rust type system, but in this case it will be checked at runtime (as `RequestId`
    /// does not have a type associated with it).
    async fn call(self) -> Result<CallResponse<Self::Value>, Self::Error>;

    /// Execute the call, and wait for an answer using an exponential-backoff strategy. The return
    /// type is encoded in the trait.
    async fn call_and_wait(self) -> Result<Self::Value, Self::Error>;

    /// Apply a transformation function after the call has been successful. The transformation
    /// is applied with the result.
    ///
    /// ```ignore
    /// # // This test is ignored because it requires an ic to be running. We run these
    /// # // in the ic-ref workflow.
    /// use ic_agent::Agent;
    /// # use ic_agent::identity::{Identity, BasicIdentity};
    /// use ic_utils::{Canister, interfaces, call::AsyncCall};
    /// use candid::{Encode, Decode, CandidType, Principal};
    ///
    /// async fn create_a_canister() -> Result<Principal, Box<dyn std::error::Error>> {
    /// # let canister_wasm = b"\0asm\x01\0\0\0";
    /// # fn create_identity() -> impl Identity {
    /// #     BasicIdentity::from_signing_key(
    /// #         ed25519_consensus::SigningKey::new(rand::thread_rng()),
    /// #     )
    /// # }
    /// #
    /// # let url = format!("http://localhost:{}", option_env!("IC_REF_PORT").unwrap_or("4943"));
    /// #
    /// # let effective_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    ///   let agent = Agent::builder()
    ///     .with_url(url)
    ///     .with_identity(create_identity())
    ///     .build()?;
    ///   agent.fetch_root_key().await?;
    ///   let management_canister = interfaces::ManagementCanister::create(&agent);
    ///   let management_canister = &management_canister; // needed for `async move`
    ///
    ///   // Create a canister, then call the management canister to install a base canister
    ///   // WASM. This is to show how this API would be used, but is probably not a good
    ///   // real use case.
    ///   let (canister_id,) = management_canister
    ///     .create_canister()
    ///     .as_provisional_create_with_amount(None)
    ///     .with_effective_canister_id(effective_id)
    ///     .and_then(|(canister_id,)| async move {
    ///       management_canister
    ///         .install_code(&canister_id, canister_wasm)
    ///         .build()
    ///         .unwrap()
    ///         .await?;
    ///       Ok((canister_id,))
    ///     })
    ///     .await?;
    ///
    ///   Ok(canister_id)
    /// }
    ///
    /// # let mut runtime = tokio::runtime::Runtime::new().unwrap();
    /// # runtime.block_on(async {
    /// let canister_id = create_a_canister().await.unwrap();
    /// eprintln!("{}", canister_id);
    /// # });
    /// ```
    fn and_then<'a, Out2, R, AndThen>(
        self,
        and_then: AndThen,
    ) -> AndThenAsyncCaller<'a, Self::Value, Out2, Self::Error, Self, R, AndThen>
    where
        Self: Sized + Send + 'a,
        Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
        R: Future<Output = Result<Out2, Self::Error>> + Send + 'a,
        AndThen: Send + Fn(Self::Value) -> R + 'a,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    /// Apply a transformation function after the call has been successful. Equivalent to `.and_then(|x| async { map(x) })`.
    fn map<'a, Out, Map>(
        self,
        map: Map,
    ) -> MappedAsyncCaller<'a, Self::Value, Out, Self::Error, Self, Map>
    where
        Self: Sized + Send + 'a,
        Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
        Map: Send + Fn(Self::Value) -> Out + 'a,
    {
        MappedAsyncCaller::new(self, map)
    }

    /// Apply a transformation function to the error after the call fails.
    fn map_err<'a, E, F>(self, f: F) -> MapErrAsyncCaller<'a, Self, E, F>
    where
        Self: Sized + Send + 'a,
        E: CanisterError + 'a,
        F: FnOnce(Self::Error) -> E + Send + 'a,
    {
        MapErrAsyncCaller::new(self, f)
    }
}

#[cfg(target_family = "wasm")]
pub(crate) type CallFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + 'a>>;
#[cfg(not(target_family = "wasm"))]
pub(crate) type CallFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;
#[cfg(not(target_family = "wasm"))]
#[doc(hidden)]
pub trait CallIntoFuture: IntoFuture<IntoFuture = <Self as CallIntoFuture>::IntoFuture> {
    type IntoFuture: Future<Output = Self::Output> + Send;
}
#[cfg(not(target_family = "wasm"))]
impl<T> CallIntoFuture for T
where
    T: IntoFuture + ?Sized,
    T::IntoFuture: Send,
{
    type IntoFuture = T::IntoFuture;
}
#[cfg(target_family = "wasm")]
use IntoFuture as CallIntoFuture;

use crate::error::CanisterError;

/// A synchronous call encapsulation.
#[derive(Debug)]
pub struct SyncCaller<'agent, Out, Err>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
{
    pub(crate) agent: &'agent Agent,
    pub(crate) effective_canister_id: Principal,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Result<Vec<u8>, candid::Error>,
    pub(crate) expiry: Expiry,
    pub(crate) phantom_out: PhantomData<Result<Out, Err>>,
}

impl<'agent, Out, Err> SyncCaller<'agent, Out, Err>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
{
    /// Perform the call, consuming the the abstraction. This is a private method.
    async fn call_raw(self) -> Result<Vec<u8>, Err> {
        let mut builder = self.agent.query(&self.canister_id, &self.method_name);
        builder = self.expiry.apply_to_query(builder);
        builder
            .with_arg(self.arg.map_err(Err::from_candid)?)
            .with_effective_canister_id(self.effective_canister_id)
            .call()
            .await
            .map_err(Err::from_agent)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, Out, Err> SyncCall for SyncCaller<'agent, Out, Err>
where
    Self: Sized,
    Out: 'agent + for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
{
    type Value = Out;
    type Error = Err;
    #[cfg(feature = "raw")]
    async fn call_raw(self) -> Result<Vec<u8>, Err> {
        Ok(self.call_raw().await?)
    }

    async fn call(self) -> Result<Out, Err> {
        let result = self.call_raw().await?;

        decode_args(&result).map_err(|e| Err::from_candid(e))
    }
}

impl<'agent, Out, Err> IntoFuture for SyncCaller<'agent, Out, Err>
where
    Self: Sized,
    Out: 'agent + for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
{
    type IntoFuture = CallFuture<'agent, Out, Err>;
    type Output = Result<Out, Err>;
    fn into_future(self) -> Self::IntoFuture {
        SyncCall::call(self)
    }
}

/// An async caller, encapsulating a call to an update method.
#[derive(Debug)]
pub struct AsyncCaller<'agent, Out, Err>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
{
    pub(crate) agent: &'agent Agent,
    pub(crate) effective_canister_id: Principal,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Result<Vec<u8>, candid::Error>,
    pub(crate) expiry: Expiry,
    pub(crate) phantom_out: PhantomData<Result<Out, Err>>,
}

impl<'agent, Out, Err> AsyncCaller<'agent, Out, Err>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'agent,
    Err: CanisterError,
{
    /// Build an `UpdateBuilder` call that can be used directly with the [Agent]. This is
    /// essentially downleveling this type into the lower level [ic-agent] abstraction.
    pub fn build_call(self) -> Result<UpdateBuilder<'agent>, Err> {
        let mut builder = self.agent.update(&self.canister_id, &self.method_name);
        builder = self.expiry.apply_to_update(builder);
        builder = builder
            .with_arg(self.arg.map_err(Err::from_candid)?)
            .with_effective_canister_id(self.effective_canister_id);
        Ok(builder)
    }

    /// See [`AsyncCall::call`].
    pub async fn call(self) -> Result<CallResponse<Out>, Err> {
        let response_bytes = match self.build_call()?.call().await.map_err(Err::from_agent)? {
            CallResponse::Response((response_bytes, _)) => response_bytes,
            CallResponse::Poll(request_id) => return Ok(CallResponse::Poll(request_id)),
        };

        let decoded_response = decode_args(&response_bytes).map_err(Err::from_candid)?;

        Ok(CallResponse::Response(decoded_response))
    }

    /// See [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<Out, Err> {
        self.build_call()?
            .call_and_wait()
            .await
            .map_err(Err::from_agent)
            .and_then(|r| decode_args(&r).map_err(Err::from_candid))
    }

    /// Equivalent to calling [`AsyncCall::call_and_wait`] with the expected return type `(T,)`.
    pub async fn call_and_wait_one<T>(self) -> Result<T, Err>
    where
        T: DeserializeOwned + CandidType,
    {
        self.build_call()?
            .call_and_wait()
            .await
            .map_err(Err::from_agent)
            .and_then(|r| decode_one(&r).map_err(Err::from_candid))
    }

    /// See [`AsyncCall::map`].
    pub fn map<Out2, Map>(self, map: Map) -> MappedAsyncCaller<'agent, Out, Out2, Err, Self, Map>
    where
        Out2: for<'de> ArgumentDecoder<'de> + Send,
        Map: Send + Fn(Out) -> Out2,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, Out, Err> AsyncCall for AsyncCaller<'agent, Out, Err>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'agent,
    Err: CanisterError,
{
    type Value = Out;
    type Error = Err;
    async fn call(self) -> Result<CallResponse<Out>, Err> {
        self.call().await
    }
    async fn call_and_wait(self) -> Result<Out, Err> {
        self.call_and_wait().await
    }
}

impl<'agent, Out, Err> IntoFuture for AsyncCaller<'agent, Out, Err>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'agent,
    Err: CanisterError,
{
    type IntoFuture = CallFuture<'agent, Out, Err>;
    type Output = Result<Out, Err>;
    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}

/// An `AsyncCall` that applies a transform function to the result of the call. Because of
/// constraints on the type system in Rust, both the input and output to the function must be
/// deserializable.
pub struct AndThenAsyncCaller<
    'a,
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    R: Future<Output = Result<Out2, Err>> + Send,
    AndThen: Send + Fn(Out) -> R,
> {
    inner: Inner,
    and_then: AndThen,
    _out: PhantomData<Result<Out, Err>>,
    _out2: PhantomData<Result<Out2, Err>>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, Out, Out2, Err, Inner, R, AndThen> fmt::Debug
    for AndThenAsyncCaller<'a, Out, Out2, Err, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out> + Send + fmt::Debug + 'a,
    R: Future<Output = Result<Out2, Err>> + Send,
    AndThen: Send + Fn(Out) -> R + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndThenAsyncCaller")
            .field("inner", &self.inner as &dyn fmt::Debug)
            .field("and_then", &self.and_then)
            .field("_out", &self._out)
            .field("_out2", &self._out2)
            .finish()
    }
}

impl<'a, Out, Out2, Err, Inner, R, AndThen>
    AndThenAsyncCaller<'a, Out, Out2, Err, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out, Error = Err> + Send + 'a,
    R: Future<Output = Result<Out2, Err>> + Send + 'a,
    AndThen: Send + Fn(Out) -> R + 'a,
{
    /// Equivalent to `inner.and_then(and_then)`.
    pub fn new(inner: Inner, and_then: AndThen) -> Self {
        Self {
            inner,
            and_then,
            _out: PhantomData,
            _out2: PhantomData,
            _lifetime: PhantomData,
        }
    }

    /// See [`AsyncCall::call`].
    pub async fn call(self) -> Result<CallResponse<Out2>, Err> {
        let raw_response = self.inner.call().await?;

        let response = match raw_response {
            CallResponse::Response(response_bytes) => {
                let mapped_response = (self.and_then)(response_bytes);
                CallResponse::Response(mapped_response.await?)
            }
            CallResponse::Poll(request_id) => CallResponse::Poll(request_id),
        };

        Ok(response)
    }
    /// See [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<Out2, Err> {
        let v = self.inner.call_and_wait().await?;

        let f = (self.and_then)(v);

        f.await
    }

    /// See [`AsyncCall::and_then`].
    pub fn and_then<Out3, R2, AndThen2>(
        self,
        and_then: AndThen2,
    ) -> AndThenAsyncCaller<'a, Out2, Out3, Err, Self, R2, AndThen2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + 'a,
        R2: Future<Output = Result<Out3, Err>> + Send + 'a,
        AndThen2: Send + Fn(Out2) -> R2 + 'a,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    /// See [`AsyncCall::map`].
    pub fn map<Out3, Map>(self, map: Map) -> MappedAsyncCaller<'a, Out2, Out3, Err, Self, Map>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send,
        Map: Send + Fn(Out2) -> Out3,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'a, Out, Out2, Err, Inner, R, AndThen> AsyncCall
    for AndThenAsyncCaller<'a, Out, Out2, Err, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    R: Future<Output = Result<Out2, Err>> + Send + 'a,
    AndThen: Send + Fn(Out) -> R + 'a,
{
    type Value = Out2;
    type Error = Err;

    async fn call(self) -> Result<CallResponse<Out2>, Err> {
        self.call().await
    }

    async fn call_and_wait(self) -> Result<Out2, Err> {
        self.call_and_wait().await
    }
}

impl<'a, Out, Out2, Err, Inner, R, AndThen> IntoFuture
    for AndThenAsyncCaller<'a, Out, Out2, Err, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    R: Future<Output = Result<Out2, Err>> + Send + 'a,
    AndThen: Send + Fn(Out) -> R + 'a,
{
    type IntoFuture = CallFuture<'a, Out2, Err>;
    type Output = Result<Out2, Err>;
    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}

/// A structure that applies a transform function to the result of a call. Because of constraints
/// on the type system in Rust, both the input and output to the function must be deserializable.
pub struct MappedAsyncCaller<
    'a,
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    Map: Send + Fn(Out) -> Out2,
> {
    inner: Inner,
    map: Map,
    _out: PhantomData<Result<Out, Err>>,
    _out2: PhantomData<Result<Out2, Err>>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, Out, Out2, Err, Inner, Map> fmt::Debug
    for MappedAsyncCaller<'a, Out, Out2, Err, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out> + Send + fmt::Debug + 'a,
    Map: Send + Fn(Out) -> Out2 + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappedAsyncCaller")
            .field("inner", &self.inner as &dyn fmt::Debug)
            .field("map", &self.map)
            .field("_out", &self._out)
            .field("_out2", &self._out2)
            .finish()
    }
}

impl<'a, Out, Out2, Err, Inner, Map> MappedAsyncCaller<'a, Out, Out2, Err, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out, Error = Err> + Send + 'a,
    Map: Send + Fn(Out) -> Out2,
{
    /// Equivalent to `inner.map(map)`.
    pub fn new(inner: Inner, map: Map) -> Self {
        Self {
            inner,
            map,
            _out: PhantomData,
            _out2: PhantomData,
            _lifetime: PhantomData,
        }
    }

    /// See [`AsyncCall::call`].
    pub async fn call(self) -> Result<CallResponse<Out2>, Err> {
        self.inner.call().await.map(|response| match response {
            CallResponse::Response(response_bytes) => {
                let mapped_response = (self.map)(response_bytes);
                CallResponse::Response(mapped_response)
            }
            CallResponse::Poll(request_id) => CallResponse::Poll(request_id),
        })
    }

    /// See [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<Out2, Err> {
        let v = self.inner.call_and_wait().await?;
        Ok((self.map)(v))
    }

    /// See [`AsyncCall::and_then`].
    pub fn and_then<Out3, R2, AndThen2>(
        self,
        and_then: AndThen2,
    ) -> AndThenAsyncCaller<'a, Out2, Out3, Err, Self, R2, AndThen2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + 'a,
        R2: Future<Output = Result<Out3, Err>> + Send + 'a,
        AndThen2: Send + Fn(Out2) -> R2 + 'a,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    /// See [`AsyncCall::map`].
    pub fn map<Out3, Map2>(self, map: Map2) -> MappedAsyncCaller<'a, Out2, Out3, Err, Self, Map2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send,
        Map2: Send + Fn(Out2) -> Out3,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'a, Out, Out2, Err, Inner, Map> AsyncCall for MappedAsyncCaller<'a, Out, Out2, Err, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out, Error = Err> + Send + 'a,
    Map: Send + Fn(Out) -> Out2 + 'a,
{
    type Value = Out2;
    type Error = Err;

    async fn call(self) -> Result<CallResponse<Out2>, Err> {
        self.call().await
    }

    async fn call_and_wait(self) -> Result<Out2, Err> {
        self.call_and_wait().await
    }
}

impl<'a, Out, Out2, Err, Inner, Map> IntoFuture
    for MappedAsyncCaller<'a, Out, Out2, Err, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Err: CanisterError,
    Inner: AsyncCall<Value = Out, Error = Err> + Send + 'a,
    Map: Send + Fn(Out) -> Out2 + 'a,
{
    type IntoFuture = CallFuture<'a, Out2, Err>;
    type Output = Result<Out2, Err>;

    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}

/// A [`SyncCall`] with a transformed error type.
#[derive(Debug)]
pub struct MapErrSyncCaller<'a, Inner, Err, Func>
where
    Inner: SyncCall + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    inner: Inner,
    func: Func,
    lifetime: PhantomData<&'a ()>,
}

impl<'a, Inner, Err, Func> MapErrSyncCaller<'a, Inner, Err, Func>
where
    Inner: SyncCall + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    fn new(inner: Inner, func: Func) -> Self {
        Self {
            inner,
            func,
            lifetime: PhantomData,
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'a, Inner, Err, Func> SyncCall for MapErrSyncCaller<'a, Inner, Err, Func>
where
    Inner: SyncCall + Send + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    type Value = Inner::Value;
    type Error = Err;
    async fn call(self) -> Result<Inner::Value, Err> {
        self.inner.call().await.map_err(self.func)
    }

    #[cfg(feature = "raw")]
    async fn call_raw(self) -> Result<Vec<u8>, Err> {
        self.inner.call_raw().await.map_err(self.func)
    }
}

impl<'a, Inner, Err, Func> IntoFuture for MapErrSyncCaller<'a, Inner, Err, Func>
where
    Inner: SyncCall + Send + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    type IntoFuture = CallFuture<'a, Inner::Value, Err>;
    type Output = Result<Inner::Value, Err>;
    fn into_future(self) -> Self::IntoFuture {
        self.call()
    }
}

/// An [`AsyncCall`] with a transformed error type.
#[derive(Debug)]
pub struct MapErrAsyncCaller<'a, Inner, Err, Func>
where
    Inner: AsyncCall + Send + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    inner: Inner,
    func: Func,
    lifetime: PhantomData<&'a ()>,
}

impl<'a, Inner, Err, Func> MapErrAsyncCaller<'a, Inner, Err, Func>
where
    Inner: AsyncCall + Send + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    fn new(inner: Inner, func: Func) -> Self {
        Self {
            inner,
            func,
            lifetime: PhantomData,
        }
    }
}
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'a, Inner, Err, Func> AsyncCall for MapErrAsyncCaller<'a, Inner, Err, Func>
where
    Inner: AsyncCall + Send + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    type Value = Inner::Value;
    type Error = Err;
    async fn call(self) -> Result<CallResponse<Inner::Value>, Err> {
        self.inner.call().await.map_err(self.func)
    }

    async fn call_and_wait(self) -> Result<Inner::Value, Err> {
        self.inner.call_and_wait().await.map_err(self.func)
    }
}

impl<'a, Inner, Err, Func> IntoFuture for MapErrAsyncCaller<'a, Inner, Err, Func>
where
    Inner: AsyncCall + Send + 'a,
    Err: CanisterError + 'a,
    Func: FnOnce(Inner::Error) -> Err + Send + 'a,
{
    type Output = Result<Inner::Value, Err>;
    type IntoFuture = CallFuture<'a, Inner::Value, Err>;
    fn into_future(self) -> Self::IntoFuture {
        self.call_and_wait()
    }
}
