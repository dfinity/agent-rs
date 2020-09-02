use async_trait::async_trait;
use candid::{CandidType, Decode, Encode};
use delay::Waiter;
use ic_agent::{Agent, AgentError, RequestId};
use ic_types::Principal;
use serde::de::DeserializeOwned;
use typed_builder::TypedBuilder;

#[async_trait]
pub trait SyncCall {
    async fn call<T: DeserializeOwned>(&self) -> Result<T, AgentError>;
}

#[async_trait]
pub trait AsyncCall {
    async fn call(&self) -> Result<RequestId, AgentError>;
    async fn call_and_wait<T, W>(&self, mut waiter: W) -> Result<T, AgentError>
    where
        T: DeserializeOwned,
        W: Waiter;
}

#[derive(TypedBuilder)]
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
        R: DeserializeOwned,
    {
        let arg = Encode!(&self.arg)?;
        self.agent
            .query_raw(&self.canister_id, &self.method_name, &arg)
            .await
            .and_then(|r| Decode!(&r, R).map_err(AgentError::from))
    }
}

#[derive(TypedBuilder)]
pub struct AsyncCaller<'agent, Arg: CandidType + Send + Sync> {
    agent: &'agent Agent,
    canister_id: Principal,
    method_name: String,
    #[builder(default, setter(strip_option))]
    arg: Option<Arg>,
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

    async fn call_and_wait<R, W>(&self, waiter: W) -> Result<R, AgentError>
    where
        R: DeserializeOwned,
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
            .and_then(|r| Decode!(&r, R).map_err(AgentError::from))
    }
}

pub struct MappedAsyncCall<'agent, Inner, ArgIn, ArgOut, MappingFunc>
where
    ArgIn: DeserializeOwned,
    ArgOut: DeserializeOwned,
    Inner: AsyncCall,
    MappingFunc: Fn(ArgIn) -> ArgOut,
{
    inner: Inner,
    mapping_fn: MappingFunc,
}

impl<'agent, Inner, ArgIn, ArgOut, MappingFunc>
    MappedAsyncCall<'agent, Inner, ArgIn, ArgOut, MappingFunc>
where
    ArgIn: DeserializeOwned,
    ArgOut: DeserializeOwned,
    Inner: AsyncCall,
    MappingFunc: Fn(ArgIn) -> ArgOut,
{
    pub fn new(
        inner: Inner,
        mapping_fn: MappingFunc,
    ) -> MappedAsyncCall<'agent, Inner, ArgIn, ArgOut, MappingFunc> {
        Self { inner, mapping_fn }
    }
}

#[async_trait]
impl<'agent, Inner, ArgIn, ArgOut, MappingFunc> AsyncCall
    for MappedAsyncCall<'agent, Inner, ArgIn, ArgOut, MappingFunc>
where
    ArgIn: DeserializeOwned,
    ArgOut: DeserializeOwned,
    Inner: AsyncCall,
    MappingFunc: Fn(ArgIn) -> ArgOut,
{
    async fn call(&self) -> Result<RequestId, AgentError> {
        self.inner.call()
    }

    async fn call_and_wait<T, W>(&self, mut waiter: W) -> Result<T, AgentError>
    where
        T: DeserializeOwned,
        W: Waiter,
    {
        self.inner.call_and_wait(waiter).await.map(&self.mapping_fn)
    }
}
