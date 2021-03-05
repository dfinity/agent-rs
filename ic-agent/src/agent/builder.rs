use crate::agent::http_facade::ReqwestHttpReplicaV1Facade;
use crate::agent::{AgentConfig, ReplicaV1Facade};
use crate::{Agent, AgentError, Identity, NonceFactory};
use std::sync::Arc;

pub struct AgentBuilder {
    config: AgentConfig,
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self {
            config: Default::default(),
        }
    }
}

impl AgentBuilder {
    /// Create an instance of [Agent] with the information from this builder.
    pub fn build(self) -> Result<Agent, AgentError> {
        Agent::new(self.config)
    }

    /// Set the URL of the [Agent].
    #[cfg(feature = "reqwest")]
    #[deprecated(since = "0.3.0", note = "Prefer using with_facade now.")]
    pub fn with_url<S: Into<String>>(self, url: S) -> Self {
        self.with_facade(ReqwestHttpReplicaV1Facade::create(url).unwrap())
    }

    /// Set a Replica facade to talk to serve as the replica interface.
    pub fn with_facade<F: 'static + ReplicaV1Facade + Send + Sync>(self, facade: F) -> Self {
        Self {
            config: AgentConfig {
                facade: Some(Arc::new(facade)),
                ..self.config
            },
        }
    }

    /// Add a NonceFactory to this Agent. By default, no nonce is produced.
    pub fn with_nonce_factory(self, nonce_factory: NonceFactory) -> Self {
        AgentBuilder {
            config: AgentConfig {
                nonce_factory,
                ..self.config
            },
        }
    }

    /// Add an identity provider for signing messages. This is required.
    pub fn with_identity<I>(self, identity: I) -> Self
    where
        I: 'static + Identity + Send + Sync,
    {
        AgentBuilder {
            config: AgentConfig {
                identity: Arc::new(identity),
                ..self.config
            },
        }
    }

    /// Same as [with_identity], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_identity(self, identity: Box<dyn Identity + Send + Sync>) -> Self {
        AgentBuilder {
            config: AgentConfig {
                identity: Arc::from(identity),
                ..self.config
            },
        }
    }

    /// Provides a _default_ ingress expiry. This is the delta that will be applied
    /// at the time an update or query is made. The default expiry cannot be a
    /// fixed system time.
    pub fn with_ingress_expiry(self, duration: Option<std::time::Duration>) -> Self {
        AgentBuilder {
            config: AgentConfig {
                ingress_expiry_duration: duration,
                ..self.config
            },
        }
    }
}
