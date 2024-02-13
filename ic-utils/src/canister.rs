use crate::call::{AsyncCaller, SyncCaller};
use candid::utils::ArgumentEncoder;
use candid::{ser::IDLBuilder, types::value::IDLValue, utils::ArgumentDecoder, CandidType, Encode};
use ic_agent::{export::Principal, Agent, AgentError, RequestId};
use std::convert::TryInto;
use thiserror::Error;

/// An error happened while building a canister.
#[derive(Debug, Error)]
pub enum CanisterBuilderError {
    /// There was an error parsing the canister ID.
    #[error("Getting the Canister ID returned an error: {0}")]
    PrincipalError(#[from] Box<dyn std::error::Error + std::marker::Send + std::marker::Sync>),

    /// The agent was not provided.
    #[error("Must specify an Agent")]
    MustSpecifyAnAgent(),

    /// The canister ID was not provided.
    #[error("Must specify a Canister ID")]
    MustSpecifyCanisterId(),
}

/// A canister builder, which can be used to create a canister abstraction.
#[derive(Debug, Default)]
pub struct CanisterBuilder<'agent> {
    agent: Option<&'agent Agent>,
    canister_id: Option<Result<Principal, CanisterBuilderError>>,
}

impl<'agent> CanisterBuilder<'agent> {
    /// Create a canister builder with no value.
    pub fn new() -> CanisterBuilder<'static> {
        Default::default()
    }

    /// Attach a canister ID to this canister.
    pub fn with_canister_id<E, P>(self, canister_id: P) -> Self
    where
        E: 'static + std::error::Error + std::marker::Send + std::marker::Sync,
        P: TryInto<Principal, Error = E>,
    {
        Self {
            canister_id: Some(
                canister_id
                    .try_into()
                    .map_err(|e| CanisterBuilderError::PrincipalError(Box::new(e))),
            ),
            ..self
        }
    }

    /// Assign an agent to the canister being built.
    pub fn with_agent(self, agent: &'agent Agent) -> Self {
        CanisterBuilder {
            agent: Some(agent),
            ..self
        }
    }

    /// Create this canister abstraction after passing in all the necessary state.
    pub fn build(self) -> Result<Canister<'agent>, CanisterBuilderError> {
        let canister_id = if let Some(cid) = self.canister_id {
            cid?
        } else {
            return Err(CanisterBuilderError::MustSpecifyCanisterId());
        };

        let agent = self
            .agent
            .ok_or(CanisterBuilderError::MustSpecifyAnAgent())?;
        Ok(Canister { agent, canister_id })
    }
}

/// Create an encapsulation of a Canister running on the Internet Computer.
/// This supports making calls to methods, installing code if needed, and various
/// utilities related to a canister.
///
/// This is the higher level construct for talking to a canister on the Internet
/// Computer.
#[derive(Debug, Clone)]
pub struct Canister<'agent> {
    pub(super) agent: &'agent Agent,
    pub(super) canister_id: Principal,
}

impl<'agent> Canister<'agent> {
    /// Get the canister ID of this canister.
    /// Prefer using [`canister_id`](Canister::canister_id) instead.
    pub fn canister_id_(&self) -> &Principal {
        &self.canister_id
    }

    /// Get the canister ID of this canister.
    pub fn canister_id(&self) -> &Principal {
        &self.canister_id
    }

    /// Create an AsyncCallBuilder to do an update call.
    pub fn update_<'canister>(
        &'canister self,
        method_name: &str,
    ) -> AsyncCallBuilder<'agent, 'canister> {
        AsyncCallBuilder::new(self, method_name)
    }

    /// Create an AsyncCallBuilder to do an update call.
    /// Prefer using [`update`](Canister::update) instead.
    pub fn update<'canister>(
        &'canister self,
        method_name: &str,
    ) -> AsyncCallBuilder<'agent, 'canister> {
        AsyncCallBuilder::new(self, method_name)
    }

    /// Create a SyncCallBuilder to do a query call.
    /// Prefer using [`query`](Canister::query) instead.
    pub fn query_<'canister>(
        &'canister self,
        method_name: &str,
    ) -> SyncCallBuilder<'agent, 'canister> {
        SyncCallBuilder::new(self, method_name)
    }

    /// Create a SyncCallBuilder to do a query call.
    pub fn query<'canister>(
        &'canister self,
        method_name: &str,
    ) -> SyncCallBuilder<'agent, 'canister> {
        SyncCallBuilder::new(self, method_name)
    }

    /// Call request_status on the RequestId in a loop and return the response as a byte vector.
    pub async fn wait<'canister>(
        &'canister self,
        request_id: RequestId,
    ) -> Result<Vec<u8>, AgentError> {
        self.agent.wait(request_id, self.canister_id).await
    }

    /// Creates a copy of this canister, changing the canister ID to the provided principal.
    /// Prefer using [`clone_with`](Canister::clone_with) instead.
    pub fn clone_with_(&self, id: Principal) -> Self {
        Self {
            agent: self.agent,
            canister_id: id,
        }
    }
    /// Creates a copy of this canister, changing the canister ID to the provided principal.
    pub fn clone_with(&self, id: Principal) -> Self {
        Self {
            agent: self.agent,
            canister_id: id,
        }
    }

    /// Create a CanisterBuilder instance to build a canister abstraction.
    pub fn builder() -> CanisterBuilder<'agent> {
        Default::default()
    }
}

/// A buffer to hold canister argument blob.
#[derive(Debug, Default)]
pub struct Argument(pub(crate) Option<Result<Vec<u8>, AgentError>>);

impl Argument {
    /// Set an IDL Argument. Can only be called at most once.
    pub fn set_idl_arg<A: CandidType>(&mut self, arg: A) {
        match self.0 {
            None => self.0 = Some(Encode!(&arg).map_err(|e| e.into())),
            Some(_) => panic!("argument is being set more than once"),
        }
    }

    /// Set an IDLValue Argument. Can only be called at most once.
    pub fn set_value_arg(&mut self, arg: IDLValue) {
        match self.0 {
            None => {
                let mut builder = IDLBuilder::new();
                let result = builder
                    .value_arg(&arg)
                    .and_then(|builder| builder.serialize_to_vec())
                    .map_err(|e| e.into());
                self.0 = Some(result);
            }
            Some(_) => panic!("argument is being set more than once"),
        }
    }

    /// Set the argument as raw. Can only be called at most once.
    pub fn set_raw_arg(&mut self, arg: Vec<u8>) {
        match self.0 {
            None => self.0 = Some(Ok(arg)),
            Some(_) => panic!("argument is being set more than once"),
        }
    }

    /// Return the argument blob.
    pub fn serialize(self) -> Result<Vec<u8>, AgentError> {
        self.0.unwrap_or_else(|| Ok(Encode!()?))
    }

    /// Resets the argument to an empty message.
    pub fn reset(&mut self) {
        *self = Default::default();
    }

    /// Creates an empty argument.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates an argument from an arbitrary blob. Equivalent to [`set_raw_arg`](Argument::set_raw_arg).
    pub fn from_raw(raw: Vec<u8>) -> Self {
        Self(Some(Ok(raw)))
    }

    /// Creates an argument from an existing Candid ArgumentEncoder.
    pub fn from_candid(tuple: impl ArgumentEncoder) -> Self {
        let mut builder = IDLBuilder::new();
        let result = tuple
            .encode(&mut builder)
            .and_then(|_| builder.serialize_to_vec())
            .map_err(|e| e.into());
        Self(Some(result))
    }
}

/// A builder for a synchronous call (ie. query) to the Internet Computer.
///
/// See [SyncCaller] for a description of this structure once built.
#[derive(Debug)]
pub struct SyncCallBuilder<'agent, 'canister> {
    canister: &'canister Canister<'agent>,
    method_name: String,
    effective_canister_id: Principal,
    arg: Argument,
}

impl<'agent: 'canister, 'canister> SyncCallBuilder<'agent, 'canister> {
    /// Create a new instance of an AsyncCallBuilder.
    pub(super) fn new<M: Into<String>>(
        canister: &'canister Canister<'agent>,
        method_name: M,
    ) -> Self {
        Self {
            canister,
            method_name: method_name.into(),
            effective_canister_id: canister.canister_id().to_owned(),
            arg: Default::default(),
        }
    }
}

impl<'agent: 'canister, 'canister> SyncCallBuilder<'agent, 'canister> {
    /// Set the argument with candid argument. Can be called at most once.
    pub fn with_arg<Argument>(mut self, arg: Argument) -> Self
    where
        Argument: CandidType + Sync + Send,
    {
        self.arg.set_idl_arg(arg);
        self
    }
    /// Set the argument with multiple arguments as tuple. Can be called at most once.
    pub fn with_args(mut self, tuple: impl ArgumentEncoder) -> Self {
        if self.arg.0.is_some() {
            panic!("argument is being set more than once");
        }
        self.arg = Argument::from_candid(tuple);
        self
    }

    /// Set the argument with IDLValue argument. Can be called at most once.
    ///
    /// TODO: make this method unnecessary ([#132](https://github.com/dfinity/agent-rs/issues/132))
    pub fn with_value_arg(mut self, arg: IDLValue) -> Self {
        self.arg.set_value_arg(arg);
        self
    }

    /// Set the argument with raw argument bytes. Can be called at most once.
    pub fn with_arg_raw(mut self, arg: Vec<u8>) -> Self {
        self.arg.set_raw_arg(arg);
        self
    }

    /// Sets the [effective canister ID](https://internetcomputer.org/docs/references/current/ic-interface-spec#http-effective-canister-id) of the destination.
    pub fn with_effective_canister_id(mut self, canister_id: Principal) -> Self {
        self.effective_canister_id = canister_id;
        self
    }

    /// Builds a [SyncCaller] from this builder's state.
    pub fn build<Output>(self) -> SyncCaller<'agent, Output>
    where
        Output: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        let c = self.canister;
        SyncCaller {
            agent: c.agent,
            effective_canister_id: self.effective_canister_id,
            canister_id: c.canister_id,
            method_name: self.method_name.clone(),
            arg: self.arg.serialize(),
            expiry: Default::default(),
            phantom_out: std::marker::PhantomData,
        }
    }
}

/// A builder for an asynchronous call (ie. update) to the Internet Computer.
///
/// See [AsyncCaller] for a description of this structure.
#[derive(Debug)]
pub struct AsyncCallBuilder<'agent, 'canister> {
    canister: &'canister Canister<'agent>,
    method_name: String,
    effective_canister_id: Principal,
    arg: Argument,
}

impl<'agent: 'canister, 'canister> AsyncCallBuilder<'agent, 'canister> {
    /// Create a new instance of an AsyncCallBuilder.
    pub(super) fn new(
        canister: &'canister Canister<'agent>,
        method_name: &str,
    ) -> AsyncCallBuilder<'agent, 'canister> {
        Self {
            canister,
            method_name: method_name.to_string(),
            effective_canister_id: canister.canister_id().to_owned(),
            arg: Default::default(),
        }
    }
}

impl<'agent: 'canister, 'canister> AsyncCallBuilder<'agent, 'canister> {
    /// Set the argument with Candid argument. Can be called at most once.
    pub fn with_arg<Argument>(mut self, arg: Argument) -> Self
    where
        Argument: CandidType + Sync + Send,
    {
        self.arg.set_idl_arg(arg);
        self
    }
    /// Set the argument with multiple arguments as tuple. Can be called at most once.
    pub fn with_args(mut self, tuple: impl ArgumentEncoder) -> Self {
        if self.arg.0.is_some() {
            panic!("argument is being set more than once");
        }
        self.arg = Argument::from_candid(tuple);
        self
    }

    /// Set the argument with raw argument bytes. Can be called at most once.
    pub fn with_arg_raw(mut self, arg: Vec<u8>) -> Self {
        self.arg.set_raw_arg(arg);
        self
    }

    /// Sets the [effective canister ID](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-effective-canister-id) of the destination.
    pub fn with_effective_canister_id(mut self, canister_id: Principal) -> Self {
        self.effective_canister_id = canister_id;
        self
    }

    /// Builds an [AsyncCaller] from this builder's state.
    pub fn build<Output>(self) -> AsyncCaller<'agent, Output>
    where
        Output: for<'de> ArgumentDecoder<'de> + Send + Sync,
    {
        let c = self.canister;
        AsyncCaller {
            agent: c.agent,
            effective_canister_id: self.effective_canister_id,
            canister_id: c.canister_id,
            method_name: self.method_name.clone(),
            arg: self.arg.serialize(),
            expiry: Default::default(),
            phantom_out: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::interfaces::ManagementCanister;
    use crate::call::AsyncCall;
    use candid::Principal;
    use ic_agent::agent::http_transport::ReqwestTransport;
    use ic_agent::identity::BasicIdentity;

    fn get_effective_canister_id() -> Principal {
        Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap()
    }

    #[ignore]
    #[tokio::test]
    async fn simple() {
        use super::Canister;

        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("Could not generate a key pair.");

        let identity = BasicIdentity::from_key_pair(
            ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
                .expect("Could not read the key pair."),
        );

        let port = std::env::var("IC_REF_PORT").unwrap_or_else(|_| "8001".into());

        let agent = ic_agent::Agent::builder()
            .with_transport(ReqwestTransport::create(format!("http://localhost:{port}")).unwrap())
            .with_identity(identity)
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let management_canister = ManagementCanister::from_canister(
            Canister::builder()
                .with_agent(&agent)
                .with_canister_id("aaaaa-aa")
                .build()
                .unwrap(),
        );

        let (new_canister_id,) = management_canister
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(get_effective_canister_id())
            .call_and_wait()
            .await
            .unwrap();

        let (status,) = management_canister
            .canister_status(&new_canister_id)
            .call_and_wait()
            .await
            .unwrap();

        assert_eq!(format!("{}", status.status), "Running");

        let canister_wasm = b"\0asm\x01\0\0\0";
        management_canister
            .install_code(&new_canister_id, canister_wasm)
            .call_and_wait()
            .await
            .unwrap();

        let canister = Canister::builder()
            .with_agent(&agent)
            .with_canister_id(new_canister_id)
            .build()
            .unwrap();

        assert!(canister
            .update("hello")
            .build::<()>()
            .call_and_wait()
            .await
            .is_err());
    }
}
