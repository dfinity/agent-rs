use crate::{
    agent::{NonceFactory, NonceGenerator, Transport},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

/// A configuration for an agent.
#[derive(Clone)]
pub struct AgentConfig {
    /// See [`with_nonce_factory`](super::AgentBuilder::with_nonce_factory).
    pub nonce_factory: Arc<dyn NonceGenerator>,
    /// See [`with_identity`](super::AgentBuilder::with_identity).
    pub identity: Arc<dyn Identity>,
    /// See [`with_ingress_expiry`](super::AgentBuilder::with_ingress_expiry).
    pub ingress_expiry: Option<Duration>,
    /// The [`with_transport`](super::AgentBuilder::with_transport).
    pub transport: Option<Arc<dyn Transport>>,
    /// The initial retry interval.
    pub backoff_initial_interval: Duration,
    /// The maximum elapsed time for which a retry loop would run.
    pub backoff_max_elapsed_time: Duration,
    /// The maximum value of the back off period.
    pub backoff_max_interval: Duration,
    /// The value to multiply the current interval with for each retry attempt.
    pub backoff_multiplier: f64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            nonce_factory: Arc::new(NonceFactory::random()),
            identity: Arc::new(AnonymousIdentity {}),
            ingress_expiry: None,
            transport: None,
            backoff_initial_interval: Duration::from_millis(500),
            backoff_max_elapsed_time: Duration::from_secs(60 * 5),
            backoff_max_interval: Duration::from_secs(1),
            backoff_multiplier: 1.4,
        }
    }
}
