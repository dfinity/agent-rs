use crate::call::{AsyncCaller, SyncCaller};
use candid::{parser::value::IDLValue, ser::IDLBuilder, utils::ArgumentDecoder, CandidType};
use ic_agent::{ic_types::Principal, Agent, AgentError};
use std::convert::TryInto;
use thiserror::Error;

/// An error happened while building a canister.
#[derive(Debug, Error)]
pub enum CanisterBuilderError {
    #[error("Getting the Canister ID returned an error: {0}")]
    PrincipalError(#[from] Box<dyn std::error::Error + std::marker::Send + std::marker::Sync>),

    #[error("Must specify an Agent")]
    MustSpecifyAnAgent(),

    #[error("Must specify a Canister ID")]
    MustSpecifyCanisterId(),
}

/// A canister builder, which can be used to create a canister abstraction.
pub struct CanisterBuilder<'agent, T = ()> {
    agent: Option<&'agent Agent>,
    canister_id: Option<Result<Principal, CanisterBuilderError>>,
    interface: T,
}

impl<'agent, T> CanisterBuilder<'agent, T> {
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
    pub fn build(self) -> Result<Canister<'agent, T>, CanisterBuilderError> {
        let canister_id = if let Some(cid) = self.canister_id {
            cid?
        } else {
            return Err(CanisterBuilderError::MustSpecifyCanisterId());
        };

        let agent = self
            .agent
            .ok_or(CanisterBuilderError::MustSpecifyAnAgent())?;
        Ok(Canister {
            agent,
            canister_id,
            interface: self.interface,
        })
    }
}

impl Default for CanisterBuilder<'static, ()> {
    fn default() -> Self {
        CanisterBuilder {
            agent: None,
            canister_id: None,
            interface: (),
        }
    }
}

impl<'agent> CanisterBuilder<'agent, ()> {
    /// Create a canister builder with no value.
    pub fn new() -> CanisterBuilder<'static, ()> {
        Default::default()
    }

    /// Apply an interface to this canister. An interface can add methods to the canister's
    /// type. For example, see the Management Canister.
    pub fn with_interface<T>(self, interface: T) -> CanisterBuilder<'agent, T> {
        CanisterBuilder {
            agent: self.agent,
            canister_id: self.canister_id,
            interface,
        }
    }
}

/// Create an encapsulation of a Canister running on the Internet Computer.
/// This supports making calls to methods, installing code if needed, and various
/// utilities related to a canister.
///
/// This is the higher level construct for talking to a canister on the Internet
/// Computer.
pub struct Canister<'agent, T = ()> {
    pub(super) agent: &'agent Agent,
    pub(super) canister_id: Principal,
    interface: T,
}

impl<'agent, T> Canister<'agent, T> {
    /// Get the canister ID of this canister.
    pub fn canister_id_<'canister: 'agent>(&'canister self) -> &Principal {
        &self.canister_id
    }

    /// Get the interface object from this canister. Sometimes those interfaces might have
    /// custom methods that are useful.
    pub fn interface_<'canister: 'agent>(&'canister self) -> &T {
        &self.interface
    }

    /// Create an AsyncCallBuilder to do an update call.
    pub fn update_<'canister: 'agent>(
        &'canister self,
        method_name: &str,
    ) -> AsyncCallBuilder<'agent, 'canister, T> {
        AsyncCallBuilder::new(self, method_name)
    }

    /// Create a SyncCallBuilder to do a query call.
    pub fn query_<'canister: 'agent>(
        &'canister self,
        method_name: &str,
    ) -> SyncCallBuilder<'agent, 'canister, T> {
        SyncCallBuilder::new(self, method_name)
    }
}

impl<'agent, T> Canister<'agent, T>
where
    T: Clone,
{
    pub fn clone_with_(&self, id: Principal) -> Self {
        Self {
            agent: self.agent,
            canister_id: id,
            interface: self.interface.clone(),
        }
    }
}

impl<'agent> Canister<'agent, ()> {
    /// Create a CanisterBuilder instance to build a canister abstraction.
    pub fn builder() -> CanisterBuilder<'agent, ()> {
        Default::default()
    }
}

/// The type of argument passed to a canister call. This can either be a raw argument,
/// in which case it's a vector of bytes that will be passed verbatim, or an IDL
/// Builder which will result in an error or a raw argument at the call site.
///
/// This enumeration is meant to be private. You should use [Argument] for holding
/// argument values.
enum ArgumentType {
    Raw(Vec<u8>),
    Idl(candid::ser::IDLBuilder),
}

pub struct Argument(Result<ArgumentType, AgentError>);

impl Argument {
    /// Add an IDL Argument. If the current value of Argument is Raw, will set the
    /// result to an error. If the current value is an error, will do nothing.
    pub fn push_idl_arg<A: CandidType>(&mut self, arg: A) {
        match self.0 {
            Ok(ArgumentType::Idl(ref mut idl_builder)) => {
                let result = idl_builder.arg(&arg);
                if let Err(e) = result {
                    self.0 = Err(AgentError::CandidError(Box::new(e)))
                }
            }
            Ok(ArgumentType::Raw(_)) => {
                self.0 = Err(AgentError::MessageError(
                    "Cannot overwrite a Raw Argument with a non-raw argument.".to_owned(),
                ))
            }
            _ => {}
        }
    }

    /// Add an IDLValue Argument. If the current value of Argument is Raw, will set the
    /// result to an error. If the current value is an error, will do nothing.
    pub fn push_value_arg(&mut self, arg: IDLValue) {
        match self.0 {
            Ok(ArgumentType::Idl(ref mut idl_builder)) => {
                let result = idl_builder.value_arg(&arg);
                if let Err(e) = result {
                    self.0 = Err(AgentError::CandidError(Box::new(e)))
                }
            }
            Ok(ArgumentType::Raw(_)) => {
                self.0 = Err(AgentError::MessageError(
                    "Cannot overwrite a Raw Argument with a non-raw argument.".to_owned(),
                ))
            }
            _ => {}
        }
    }

    /// Set the argument as raw, replacing any value that was there before. If the
    /// current argument was an error, does nothing.
    pub fn set_raw_arg(&mut self, arg: Vec<u8>) {
        if self.0.is_ok() {
            self.0 = Ok(ArgumentType::Raw(arg));
        }
    }

    pub fn serialize(self) -> Result<Vec<u8>, AgentError> {
        match self.0 {
            Ok(ArgumentType::Idl(mut idl_builder)) => idl_builder
                .serialize_to_vec()
                .map_err(|e| AgentError::CandidError(Box::new(e))),
            Ok(ArgumentType::Raw(vec)) => Ok(vec),
            Err(e) => Err(e),
        }
    }

    pub fn reset(&mut self) {
        *self = Default::default();
    }
}

impl Default for Argument {
    fn default() -> Self {
        Argument(Ok(ArgumentType::Idl(IDLBuilder::new())))
    }
}

/// A builder for a synchronous call (ie. query) to the Internet Computer.
///
/// See [SyncCaller] for a description of this structure once built.
pub struct SyncCallBuilder<'agent, 'canister: 'agent, T> {
    canister: &'canister Canister<'agent, T>,
    method_name: String,
    effective_canister_id: Principal,
    arg: Argument,
}

impl<'agent, 'canister: 'agent, T> SyncCallBuilder<'agent, 'canister, T> {
    /// Create a new instance of an AsyncCallBuilder.
    pub(super) fn new<M: Into<String>>(
        canister: &'canister Canister<'agent, T>,
        method_name: M,
    ) -> Self {
        Self {
            canister,
            method_name: method_name.into(),
            effective_canister_id: canister.canister_id_().to_owned(),
            arg: Default::default(),
        }
    }
}

impl<'agent, 'canister: 'agent, Interface> SyncCallBuilder<'agent, 'canister, Interface> {
    /// Add an argument to the candid argument list. This requires Candid arguments, if
    /// there is a raw argument set (using [with_arg_raw]), this will fail.
    pub fn with_arg<Argument>(
        mut self,
        arg: Argument,
    ) -> SyncCallBuilder<'agent, 'canister, Interface>
    where
        Argument: CandidType + Sync + Send,
    {
        self.arg.push_idl_arg(arg);
        self
    }

    /// Add an argument to the candid argument list. This requires Candid arguments, if
    /// there is a raw argument set (using [with_arg_raw]), this will fail.
    /// TODO: make this method unnecessary https://github.com/dfinity/agent-rs/issues/132
    pub fn with_value_arg(
        mut self,
        arg: IDLValue,
    ) -> SyncCallBuilder<'agent, 'canister, Interface> {
        self.arg.push_value_arg(arg);
        self
    }

    /// Replace the argument with raw argument bytes. This will overwrite the current
    /// argument set, so calling this method twice will discard the first argument.
    pub fn with_arg_raw(mut self, arg: Vec<u8>) -> SyncCallBuilder<'agent, 'canister, Interface> {
        self.arg.set_raw_arg(arg);
        self
    }

    pub fn with_effective_canister_id(
        mut self,
        canister_id: Principal,
    ) -> SyncCallBuilder<'agent, 'canister, Interface> {
        self.effective_canister_id = canister_id;
        self
    }

    /// Builds an [SyncCaller] from this builder's state.
    pub fn build<Output>(self) -> SyncCaller<'canister, Output>
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
pub struct AsyncCallBuilder<'agent, 'canister: 'agent, T> {
    canister: &'canister Canister<'agent, T>,
    method_name: String,
    effective_canister_id: Principal,
    arg: Argument,
}

impl<'agent, 'canister: 'agent, T> AsyncCallBuilder<'agent, 'canister, T> {
    /// Create a new instance of an AsyncCallBuilder.
    pub(super) fn new(
        canister: &'canister Canister<'agent, T>,
        method_name: &str,
    ) -> AsyncCallBuilder<'agent, 'canister, T> {
        Self {
            canister,
            method_name: method_name.to_string(),
            effective_canister_id: canister.canister_id_().to_owned(),
            arg: Default::default(),
        }
    }
}

impl<'agent, 'canister: 'agent, Interface> AsyncCallBuilder<'agent, 'canister, Interface> {
    /// Add an argument to the candid argument list. This requires Candid arguments, if
    /// there is a raw argument set (using [with_arg_raw]), this will fail.
    pub fn with_arg<Argument>(
        mut self,
        arg: Argument,
    ) -> AsyncCallBuilder<'agent, 'canister, Interface>
    where
        Argument: CandidType + Sync + Send,
    {
        self.arg.push_idl_arg(arg);
        self
    }

    /// Replace the argument with raw argument bytes. This will overwrite the current
    /// argument set, so calling this method twice will discard the first argument.
    pub fn with_arg_raw(mut self, arg: Vec<u8>) -> AsyncCallBuilder<'agent, 'canister, Interface> {
        self.arg.set_raw_arg(arg);
        self
    }

    pub fn with_effective_canister_id(
        mut self,
        canister_id: Principal,
    ) -> AsyncCallBuilder<'agent, 'canister, Interface> {
        self.effective_canister_id = canister_id;
        self
    }

    /// Builds an [AsyncCaller] from this builder's state.
    pub fn build<Output>(self) -> AsyncCaller<'canister, Output>
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
    use ic_agent::identity::BasicIdentity;

    #[ignore]
    #[tokio::test]
    async fn simple() {
        use super::Canister;
        use garcon::Delay;

        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("Could not generate a key pair.");

        let identity = BasicIdentity::from_key_pair(
            ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
                .expect("Could not read the key pair."),
        );

        let agent = ic_agent::Agent::builder()
            .with_url("http://localhost:8001")
            .with_identity(identity)
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let management_canister = Canister::builder()
            .with_agent(&agent)
            .with_canister_id("aaaaa-aa")
            .with_interface(ManagementCanister)
            .build()
            .unwrap();

        let (new_canister_id,) = management_canister
            .create_canister()
            .call_and_wait(Delay::throttle(std::time::Duration::from_secs(1)))
            .await
            .unwrap();

        let (status,) = management_canister
            .canister_status(&new_canister_id)
            .call_and_wait(Delay::throttle(std::time::Duration::from_secs(1)))
            .await
            .unwrap();

        assert_eq!(format!("{}", status.status), "Running");

        let canister_wasm = b"\0asm\x01\0\0\0";
        management_canister
            .install_code(&new_canister_id, canister_wasm)
            .call_and_wait(Delay::throttle(std::time::Duration::from_secs(1)))
            .await
            .unwrap();

        let canister = Canister::builder()
            .with_agent(&agent)
            .with_canister_id(new_canister_id)
            .build()
            .unwrap();

        assert!(canister
            .update_("hello")
            .build::<()>()
            .call_and_wait(Delay::throttle(std::time::Duration::from_secs(1)))
            .await
            .is_err());
    }
}
