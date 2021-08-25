use crate::{
    agent::{NonceFactory, NonceGenerator, ReplicaV2Transport},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

/// A configuration for an agent.

pub type AgentConfig = AgentConfigImpl<NonceFactory>;

pub struct AgentConfigImpl<N: NonceGenerator> {
    pub nonce_factory: N,
    pub identity: Arc<dyn Identity>,
    pub ingress_expiry_duration: Option<Duration>,
    pub transport: Option<Arc<dyn ReplicaV2Transport>>,
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
