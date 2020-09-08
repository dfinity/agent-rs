use crate::call::{AsyncCaller, TypedAsyncCaller};
use candid::CandidType;
use ic_agent::Agent;
use ic_types::{Principal, PrincipalError};
use serde::de::DeserializeOwned;
use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanisterBuilderError {
    #[error("Getting the Canister ID returned an error: {0}")]
    PrincipalError(#[from] PrincipalError),

    #[error("Must specify an Agent")]
    MustSpecifyAnAgent(),

    #[error("Must specify a Canister ID")]
    MustSpecifyCanisterId(),
}

pub struct CanisterBuilder<'agent, T = ()> {
    agent: Option<&'agent Agent>,
    canister_id: Option<Result<Principal, PrincipalError>>,
    interface: T,
}

pub trait CanisterIdProvider {
    fn get_canister_id(&self) -> Option<Result<Principal, CanisterBuilderError>> {
        None
    }
}

impl CanisterIdProvider for () {}

impl<'agent, T> CanisterBuilder<'agent, T> {
    pub fn with_canister_id<E, P>(self, canister_id: P) -> Self
    where
        E: std::error::Error,
        P: TryInto<Principal, Error = E>,
    {
        Self {
            canister_id: Some(
                canister_id
                    .try_into()
                    .map_err(|e| PrincipalError::ExternalError(format!("{}", e))),
            ),
            ..self
        }
    }

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
    pub fn new() -> CanisterBuilder<'static, ()> {
        Default::default()
    }

    pub fn with_interface<T>(self, interface: T) -> CanisterBuilder<'agent, T> {
        CanisterBuilder {
            agent: self.agent,
            canister_id: self.canister_id,
            interface,
        }
    }
}

impl<'agent, T> CanisterBuilder<'agent, T> {
    pub fn with_agent(self, agent: &'agent Agent) -> Self {
        CanisterBuilder {
            agent: Some(agent),
            ..self
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

impl<'agent> Canister<'agent, ()> {
    pub fn builder() -> CanisterBuilder<'agent, ()> {
        Default::default()
    }
}

pub struct AsyncCallBuilder<'canister, I, T> {
    canister: &'canister Canister<'canister, T>,
    method_name: String,
    arg: I,
}

impl<'canister, T> AsyncCallBuilder<'canister, (), T> {
    pub fn new(
        canister: &'canister Canister<'canister, T>,
        method_name: &str,
    ) -> AsyncCallBuilder<'canister, (), T> {
        Self {
            canister,
            method_name: method_name.to_string(),
            arg: (),
        }
    }
}

impl<'canister, I: CandidType + Sync + Send, T> AsyncCallBuilder<'canister, I, T> {
    pub fn build(self) -> AsyncCaller<'canister, I> {
        let c = self.canister;
        AsyncCaller {
            agent: c.agent,
            canister_id: c.canister_id.clone(),
            method_name: self.method_name.clone(),
            arg: None,
        }
    }

    pub fn build_typed<O: DeserializeOwned + Send + Sync>(
        self,
    ) -> TypedAsyncCaller<'canister, I, O> {
        TypedAsyncCaller {
            inner: self.build(),
            phantom_out: std::marker::PhantomData,
        }
    }
}

impl<'agent, T> Canister<'agent, T> {
    pub fn update_(&self, method_name: &str) -> AsyncCallBuilder<'_, (), T> {
        AsyncCallBuilder::new(self, method_name)
    }
}

#[cfg(test)]
mod tests {
    use super::super::canisters::{ManagementCanister, ManagementCanisterInterface};
    use crate::call::TypedAsyncCall;

    #[tokio::test]
    async fn simple() {
        use super::Canister;
        use delay::Delay;

        let agent = ic_agent::Agent::builder()
            .with_url("http://localhost:8001")
            .build()
            .unwrap();

        let management_canister = Canister::builder()
            .with_agent(&agent)
            .with_interface(ManagementCanister)
            .build()
            .unwrap();

        let new_canister_id: ic_types::Principal = management_canister
            .create_canister()
            .call_and_wait(Delay::throttle(std::time::Duration::from_secs(1)))
            .await
            .unwrap();

        eprintln!("Here's your canister: {}", new_canister_id);
    }
}
