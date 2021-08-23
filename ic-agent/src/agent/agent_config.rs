use crate::{
    agent::{NonceFactory, NonceGenerator, ReplicaV2Transport},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

/// A configuration for an agent.

pub type AgentConfig =
    AgentConfigImpl<NonceFactory, Arc<dyn Identity>, Arc<dyn ReplicaV2Transport>>;

pub struct AgentConfigImpl<N: NonceGenerator, I: Identity, T: ReplicaV2Transport> {
    pub nonce_factory: N,
    pub identity: I,
    pub ingress_expiry_duration: Option<Duration>,
    pub transport: Option<T>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            nonce_factory: NonceFactory::random(),
            identity: Arc::new(AnonymousIdentity {}),
            ingress_expiry_duration: None,
            transport: None,
        }
    }
}
