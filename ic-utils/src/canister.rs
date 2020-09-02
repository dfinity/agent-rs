use crate::call::{AsyncCall, SyncCall};
use ic_agent::{Agent, AgentError};
use ic_types::{Principal, PrincipalError};
use std::convert::TryInto;
use std::ops::Deref;
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

struct CanisterBuilder<'agent, T = ()> {
    agent: Option<&'agent Agent>,
    canister_id: Option<Result<Principal, PrincipalError>>,
    interface: T,
}

pub trait CanisterIdProvider {
    fn get_canister_id(&self) -> Option<Result<Principal, CanisterBuilderError>> {
        None
    }
}

impl<'agent, T> CanisterIdProvider for CanisterBuilder<'agent, T> {}

impl<'agent, T> CanisterBuilder<'agent, T> {
    pub fn with_canister_id<P: TryInto<Principal>>(self, canister_id: P) -> Self {
        Self {
            canister_id: Some(canister_id.try_into()),
            ..self
        }
    }

    pub fn build(self) -> Result<Canister<'agent, T>, CanisterBuilderError> {
        let canister_id = if let Some(cid) = self.canister_id {
            cid?
        } else if let Some(maybe_cid) = self.t.get_canister_id() {
            maybe_cid?
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
        CanisterBuilder { interface, ..self }
    }
}

/// Create an encapsulation of a Canister running on the Internet Computer.
/// This supports making calls to methods, installing code if needed, and various
/// utilities related to a canister.
///
/// This is the higher level construct for talking to a canister on the Internet
/// Computer.
pub struct Canister<'agent, T = ()> {
    agent: &'agent Agent,
    canister_id: Principal,
    interface: T,
}

impl<'agent> Canister<'agent, ()> {
    pub fn builder() -> Result<CanisterBuilder<'agent, ()>, String> {
        Ok(CanisterBuilder {
            agent: None,
            canister_id: None,
            interface: (),
        })
    }
}

pub struct MappedAsyncCallBuilder<'agent, 'canister, I, O, Mapping>
where
    Mapping: Fn(I) -> O,
{
    builder: AsyncCallBuilder<'agent, 'canister, I>,
    map: Mapping,
}

pub struct AsyncCallBuilder<'canister, 'agent, O> {
    canister: &'canister Canister<'agent>,
    method_name: String,
}

impl<'agent, 'canister, I, O, Mapping> AsyncCallBuilder<'canister, 'agent, O> {
    pub fn build(self) -> impl AsyncCall {}
}

impl<'agent, T> Canister<'agent, T> {
    pub fn update_<T>(&self, method_name: &str) -> AsyncCallBuilder<T, T, std::convert::identity> {
        AsyncCallBuilder {
            canister: self,
            method_name: method_name.into_string(),
            map: std::convert::identity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::canisters::ManagementCanister;

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
            .build();

        #[canister_import(candid_path = "../some/path/candid.did")]
        trait SomeCandidImport {}

        let basic_api = Canister::builder()
            .with_canister_id("aaaaa-aa")
            .with_interface(SomeCandidImport)
            .build();

        basic_api.count().await?;

        let nat = basic_api
            .query_("count", (1))
            .call_and_wait(some_waiter)
            .await?;

        basic_api
            .install_code()
            .with_canister_id("abcde-qw")
            .with_bytecode(&wasm);

        let new_canister_id: ic_types::Principal = management_canister
            .create_canister()
            .call_and_wait(Delay::throttle(std::time::Duration::from_secs(1)))
            .await
            .unwrap();

        eprintln!("Here's your canister: {}", new_canister_id);
    }
}
