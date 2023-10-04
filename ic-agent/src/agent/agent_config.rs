use crate::{
    agent::{NonceFactory, NonceGenerator, Transport},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

/// A configuration for an agent.
pub struct AgentConfig {
    /// See [`with_nonce_factory`](super::AgentBuilder::with_nonce_factory).
    pub nonce_factory: Arc<dyn NonceGenerator>,
    /// See [`with_identity`](super::AgentBuilder::with_identity).
    pub identity: Arc<dyn Identity>,
    /// See [`with_ingress_expiry`](super::AgentBuilder::with_ingress_expiry).
    pub ingress_expiry: Option<Duration>,
    /// See [`with_transport`](super::AgentBuilder::with_transport).
    pub transport: Option<Arc<dyn Transport>>,
    /// See [`verify_query_signatures`](super::AgentBuilder::with_verify_query_signatures).
    pub verify_query_signatures: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            nonce_factory: Arc::new(NonceFactory::random()),
            identity: Arc::new(AnonymousIdentity {}),
            ingress_expiry: None,
            transport: None,
            verify_query_signatures: false,
        }
    }
}
