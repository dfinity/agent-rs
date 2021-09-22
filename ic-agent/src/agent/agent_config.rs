use crate::{
    agent::{NonceFactory, NonceGenerator, ReplicaV2Transport},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

/// A configuration for an agent.

pub struct AgentConfig {
    pub nonce_factory: Arc<dyn NonceGenerator>,
    pub identity: Arc<dyn Identity>,
    pub ingress_expiry_duration: Option<Duration>,
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
