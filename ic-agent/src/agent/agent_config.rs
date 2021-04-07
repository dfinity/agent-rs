use crate::agent::{NonceFactory, ReplicaV2Transport};
use crate::identity::anonymous::AnonymousIdentity;
use crate::identity::Identity;
use std::sync::Arc;

/// A configuration for an agent.
pub struct AgentConfig {
    pub nonce_factory: NonceFactory,
    pub identity: Arc<dyn Identity + Send + Sync>,
    pub ingress_expiry_duration: Option<std::time::Duration>,
    pub transport: Option<Arc<dyn ReplicaV2Transport + Send + Sync>>,
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
