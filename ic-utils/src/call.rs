use async_trait::async_trait;
use candid::{decode_args, decode_one, utils::ArgumentDecoder, CandidType};
use ic_agent::{agent::UpdateBuilder, export::Principal, Agent, AgentError, RequestId};
use serde::de::DeserializeOwned;
use std::fmt;
use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::pin::Pin;

mod expiry;
pub use expiry::Expiry;

/// A type that implements synchronous calls (ie. 'query' calls).
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait SyncCall: CallIntoFuture<Output = Result<Self::Value, AgentError>> {
    /// The return type of the Candid function being called.
    type Value: for<'de> ArgumentDecoder<'de> + Send;
    /// Execute the call, return an array of bytes directly from the canister.
    #[cfg(feature = "raw")]
    async fn call_raw(self) -> Result<Vec<u8>, AgentError>;

    /// Execute the call, returning either the value returned by the canister, or an
    /// error returned by the Agent.
    async fn call(self) -> Result<Self::Value, AgentError>
    where
        Self: Sized + Send,
        Self::Value: 'async_trait;
}

/// A type that implements asynchronous calls (ie. 'update' calls).
/// This can call synchronous and return a [RequestId], or it can wait for the result
/// by polling the agent, and return a type.
///
/// The return type must be a tuple type that represents all the values the return
/// call should be returning.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait AsyncCall: CallIntoFuture<Output = Result<Self::Value, AgentError>> {
    /// The return type of the Candid function being called.
    type Value: for<'de> ArgumentDecoder<'de> + Send;
    /// Execute the call, but returns the RequestId. Waiting on the request Id must be
    /// managed by the caller using the Agent directly.
    ///
    /// Since the return type is encoded in the trait itself, this can lead to types
    /// that are not compatible to `Out` when getting the result from the Request Id.
    /// For example, you might hold a [`AsyncCall<u8>`], use `call()` and poll for
    /// the result, and try to deserialize it as a [String]. This would be caught by
    /// Rust type system, but in this case it will be checked at runtime (as Request
    /// Id does not have a type associated with it).
    async fn call(self) -> Result<RequestId, AgentError>;

    /// Execute the call, and wait for an answer using an exponential-backoff strategy. The return
    /// type is encoded in the trait.
    async fn call_and_wait(self) -> Result<Self::Value, AgentError>;

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
    /// #     let rng = ring::rand::SystemRandom::new();
    /// #     let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
    /// #         .expect("Could not generate a key pair.");
    /// #
    /// #     BasicIdentity::from_key_pair(
    /// #         ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
    /// #           .expect("Could not read the key pair."),
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
    ) -> AndThenAsyncCaller<'a, Self::Value, Out2, Self, R, AndThen>
    where
        Self: Sized + Send + 'a,
        Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
        R: Future<Output = Result<Out2, AgentError>> + Send + 'a,
        AndThen: Send + Fn(Self::Value) -> R + 'a,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    /// Apply a transformation function after the call has been successful. Equivalent to `.and_then(|x| async { map(x) })`.
    fn map<'a, Out, Map>(self, map: Map) -> MappedAsyncCaller<'a, Self::Value, Out, Self, Map>
    where
        Self: Sized + Send + 'a,
        Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
        Map: Send + Fn(Self::Value) -> Out + 'a,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[cfg(target_family = "wasm")]
pub(crate) type CallFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AgentError>> + 'a>>;
#[cfg(not(target_family = "wasm"))]
pub(crate) type CallFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AgentError>> + Send + 'a>>;
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
pub use IntoFuture as CallIntoFuture;

/// A synchronous call encapsulation.
#[derive(Debug)]
pub struct SyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
{
    pub(crate) agent: &'agent Agent,
    pub(crate) effective_canister_id: Principal,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Result<Vec<u8>, AgentError>,
    pub(crate) expiry: Expiry,
    pub(crate) phantom_out: PhantomData<Out>,
}

impl<'agent, Out> SyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
{
    /// Perform the call, consuming the the abstraction. This is a private method.
    async fn call_raw(self) -> Result<Vec<u8>, AgentError> {
        let mut builder = self.agent.query(&self.canister_id, &self.method_name);
        builder = self.expiry.apply_to_query(builder);
        builder
            .with_arg(self.arg?)
            .with_effective_canister_id(self.effective_canister_id)
            .call()
            .await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, Out> SyncCall for SyncCaller<'agent, Out>
where
    Self: Sized,
    Out: 'agent + for<'de> ArgumentDecoder<'de> + Send,
{
    type Value = Out;
    #[cfg(feature = "raw")]
    async fn call_raw(self) -> Result<Vec<u8>, AgentError> {
        Ok(self.call_raw().await?)
    }

    async fn call(self) -> Result<Out, AgentError> {
        let result = self.call_raw().await?;

        decode_args(&result).map_err(|e| AgentError::CandidError(Box::new(e)))
    }
}

impl<'agent, Out> IntoFuture for SyncCaller<'agent, Out>
where
    Self: Sized,
    Out: 'agent + for<'de> ArgumentDecoder<'de> + Send,
{
    type IntoFuture = CallFuture<'agent, Out>;
    type Output = Result<Out, AgentError>;
    fn into_future(self) -> Self::IntoFuture {
        SyncCall::call(self)
    }
}

/// An async caller, encapsulating a call to an update method.
#[derive(Debug)]
pub struct AsyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
{
    pub(crate) agent: &'agent Agent,
    pub(crate) effective_canister_id: Principal,
    pub(crate) canister_id: Principal,
    pub(crate) method_name: String,
    pub(crate) arg: Result<Vec<u8>, AgentError>,
    pub(crate) expiry: Expiry,
    pub(crate) phantom_out: PhantomData<Out>,
}

impl<'agent, Out> AsyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'agent,
{
    /// Build an UpdateBuilder call that can be used directly with the [Agent]. This is
    /// essentially downleveling this type into the lower level [ic-agent] abstraction.
    pub fn build_call(self) -> Result<UpdateBuilder<'agent>, AgentError> {
        let mut builder = self.agent.update(&self.canister_id, &self.method_name);
        builder = self.expiry.apply_to_update(builder);
        builder = builder
            .with_arg(self.arg?)
            .with_effective_canister_id(self.effective_canister_id);
        Ok(builder)
    }

    /// See [`AsyncCall::call`].
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build_call()?.call().await
    }

    /// See [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<Out, AgentError> {
        self.build_call()?
            .call_and_wait()
            .await
            .and_then(|r| decode_args(&r).map_err(|e| AgentError::CandidError(Box::new(e))))
    }

    /// Equivalent to calling [`AsyncCall::call_and_wait`] with the expected return type `(T,)`.
    pub async fn call_and_wait_one<T>(self) -> Result<T, AgentError>
    where
        T: DeserializeOwned + CandidType,
    {
        self.build_call()?
            .call_and_wait()
            .await
            .and_then(|r| decode_one(&r).map_err(|e| AgentError::CandidError(Box::new(e))))
    }

    /// See [`AsyncCall::map`].
    pub fn map<Out2, Map>(self, map: Map) -> MappedAsyncCaller<'agent, Out, Out2, Self, Map>
    where
        Out2: for<'de> ArgumentDecoder<'de> + Send,
        Map: Send + Fn(Out) -> Out2,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'agent, Out> AsyncCall for AsyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'agent,
{
    type Value = Out;
    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }
    async fn call_and_wait(self) -> Result<Out, AgentError> {
        self.call_and_wait().await
    }
}

impl<'agent, Out> IntoFuture for AsyncCaller<'agent, Out>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'agent,
{
    type IntoFuture = CallFuture<'agent, Out>;
    type Output = Result<Out, AgentError>;
    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}

/// An AsyncCall that applies a transform function to the result of the call. Because of
/// constraints on the type system in Rust, both the input and output to the function must be
/// deserializable.
pub struct AndThenAsyncCaller<
    'a,
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    R: Future<Output = Result<Out2, AgentError>> + Send,
    AndThen: Send + Fn(Out) -> R,
> {
    inner: Inner,
    and_then: AndThen,
    _out: PhantomData<Out>,
    _out2: PhantomData<Out2>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, Out, Out2, Inner, R, AndThen> fmt::Debug
    for AndThenAsyncCaller<'a, Out, Out2, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Inner: AsyncCall<Value = Out> + Send + fmt::Debug + 'a,
    R: Future<Output = Result<Out2, AgentError>> + Send,
    AndThen: Send + Fn(Out) -> R + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndThenAsyncCaller")
            .field("inner", &self.inner)
            .field("and_then", &self.and_then)
            .field("_out", &self._out)
            .field("_out2", &self._out2)
            .finish()
    }
}

impl<'a, Out, Out2, Inner, R, AndThen> AndThenAsyncCaller<'a, Out, Out2, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    R: Future<Output = Result<Out2, AgentError>> + Send + 'a,
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
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.inner.call().await
    }
    /// See [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<Out2, AgentError> {
        let v = self.inner.call_and_wait().await?;

        let f = (self.and_then)(v);

        f.await
    }

    /// See [`AsyncCall::and_then`].
    pub fn and_then<Out3, R2, AndThen2>(
        self,
        and_then: AndThen2,
    ) -> AndThenAsyncCaller<'a, Out2, Out3, Self, R2, AndThen2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + 'a,
        R2: Future<Output = Result<Out3, AgentError>> + Send + 'a,
        AndThen2: Send + Fn(Out2) -> R2 + 'a,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    /// See [`AsyncCall::map`].
    pub fn map<Out3, Map>(self, map: Map) -> MappedAsyncCaller<'a, Out2, Out3, Self, Map>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send,
        Map: Send + Fn(Out2) -> Out3,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'a, Out, Out2, Inner, R, AndThen> AsyncCall
    for AndThenAsyncCaller<'a, Out, Out2, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    R: Future<Output = Result<Out2, AgentError>> + Send + 'a,
    AndThen: Send + Fn(Out) -> R + 'a,
{
    type Value = Out2;

    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }

    async fn call_and_wait(self) -> Result<Out2, AgentError> {
        self.call_and_wait().await
    }
}

impl<'a, Out, Out2, Inner, R, AndThen> IntoFuture
    for AndThenAsyncCaller<'a, Out, Out2, Inner, R, AndThen>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    R: Future<Output = Result<Out2, AgentError>> + Send + 'a,
    AndThen: Send + Fn(Out) -> R + 'a,
{
    type IntoFuture = CallFuture<'a, Out2>;
    type Output = Result<Out2, AgentError>;
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
    Inner: AsyncCall<Value = Out> + Send + 'a,
    Map: Send + Fn(Out) -> Out2,
> {
    inner: Inner,
    map: Map,
    _out: PhantomData<Out>,
    _out2: PhantomData<Out2>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, Out, Out2, Inner, Map> fmt::Debug for MappedAsyncCaller<'a, Out, Out2, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Inner: AsyncCall<Value = Out> + Send + fmt::Debug + 'a,
    Map: Send + Fn(Out) -> Out2 + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappedAsyncCaller")
            .field("inner", &self.inner)
            .field("map", &self.map)
            .field("_out", &self._out)
            .field("_out2", &self._out2)
            .finish()
    }
}

impl<'a, Out, Out2, Inner, Map> MappedAsyncCaller<'a, Out, Out2, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send,
    Out2: for<'de> ArgumentDecoder<'de> + Send,
    Inner: AsyncCall<Value = Out> + Send + 'a,
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
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.inner.call().await
    }

    /// See [`AsyncCall::call_and_wait`].
    pub async fn call_and_wait(self) -> Result<Out2, AgentError> {
        let v = self.inner.call_and_wait().await?;
        Ok((self.map)(v))
    }

    /// See [`AsyncCall::and_then`].
    pub fn and_then<Out3, R2, AndThen2>(
        self,
        and_then: AndThen2,
    ) -> AndThenAsyncCaller<'a, Out2, Out3, Self, R2, AndThen2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send + 'a,
        R2: Future<Output = Result<Out3, AgentError>> + Send + 'a,
        AndThen2: Send + Fn(Out2) -> R2 + 'a,
    {
        AndThenAsyncCaller::new(self, and_then)
    }

    /// See [`AsyncCall::map`].
    pub fn map<Out3, Map2>(self, map: Map2) -> MappedAsyncCaller<'a, Out2, Out3, Self, Map2>
    where
        Out3: for<'de> ArgumentDecoder<'de> + Send,
        Map2: Send + Fn(Out2) -> Out3,
    {
        MappedAsyncCaller::new(self, map)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'a, Out, Out2, Inner, Map> AsyncCall for MappedAsyncCaller<'a, Out, Out2, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    Map: Send + Fn(Out) -> Out2 + 'a,
{
    type Value = Out2;

    async fn call(self) -> Result<RequestId, AgentError> {
        self.call().await
    }

    async fn call_and_wait(self) -> Result<Out2, AgentError> {
        self.call_and_wait().await
    }
}

impl<'a, Out, Out2, Inner, Map> IntoFuture for MappedAsyncCaller<'a, Out, Out2, Inner, Map>
where
    Out: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Out2: for<'de> ArgumentDecoder<'de> + Send + 'a,
    Inner: AsyncCall<Value = Out> + Send + 'a,
    Map: Send + Fn(Out) -> Out2 + 'a,
{
    type IntoFuture = CallFuture<'a, Out2>;
    type Output = Result<Out2, AgentError>;

    fn into_future(self) -> Self::IntoFuture {
        AsyncCall::call_and_wait(self)
    }
}
