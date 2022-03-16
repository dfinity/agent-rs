use crate::{
    agent::{NonceFactory, NonceGenerator, ReplicaV2Transport},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

/// A configuration for an agent.
#[derive(Debug)]
pub struct AgentConfig {
    /// See [`with_nonce_factory`](super::AgentBuilder::with_nonce_factory).
    pub nonce_factory: Arc<dyn NonceGenerator>,
    /// See [`with_identity`](super::AgentBuilder::with_identity).
    pub identity: Arc<dyn Identity>,
    /// See [`with_ingress_expiry`](super::AgentBuilder::with_ingress_expiry).
    pub ingress_expiry_duration: Option<Duration>,
    /// The [`with_transport`](super::AgentBuilder::with_transport).
    pub transport: Option<Arc<dyn ReplicaV2Transport>>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            nonce_factory: Arc::new(NonceFactory::random()),
            identity: Arc::new(AnonymousIdentity {}),
            ingress_expiry_duration: None,
            transport: None,
        }
    }
}
