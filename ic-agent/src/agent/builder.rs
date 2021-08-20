use crate::{
    agent::{agent_config::AgentConfigImpl, AgentImpl, ReplicaV2Transport},
    AgentError, Identity, NonceFactory, NonceGenerator,
};
use std::sync::Arc;

pub type AgentBuilder = AgentBuilderImpl<NonceFactory>;

pub struct AgentBuilderImpl<N: NonceGenerator> {
    config: AgentConfigImpl<N>,
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self {
            config: Default::default(),
        }
    }
}

impl<N: NonceGenerator> AgentBuilderImpl<N> {
    /// Create an instance of [AgentImpl] with the information from this builder.
    pub fn build(self) -> Result<AgentImpl<N>, AgentError> {
        AgentImpl::new(self.config)
    }

    /// Set the URL of the [AgentImpl].
    #[cfg(feature = "reqwest")]
    #[deprecated(since = "0.3.0", note = "Prefer using with_transport().")]
    pub fn with_url<S: Into<String>>(self, url: S) -> Self {
        use crate::agent::http_transport::ReqwestHttpReplicaV2Transport;

        self.with_transport(ReqwestHttpReplicaV2Transport::create(url).unwrap())
    }

    /// Set a Replica transport to talk to serve as the replica interface.
    pub fn with_transport<F: 'static + ReplicaV2Transport>(self, transport: F) -> Self {
        Self {
            config: AgentConfigImpl {
                transport: Some(Arc::new(transport)),
                ..self.config
            },
        }
    }

    /// Add a NonceFactory to this AgentImpl. By default, no nonce is produced.
    pub fn with_nonce_factory(self, nonce_factory: NonceFactory) -> AgentBuilderImpl<NonceFactory> {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                nonce_factory,
                identity: self.config.identity,
                ingress_expiry_duration: self.config.ingress_expiry_duration,
                transport: self.config.transport,
            },
        }
    }

    /// Add a NonceFactory to this AgentImpl. By default, no nonce is produced.
    pub fn with_nonce_generator<N1: NonceGenerator>(
        self,
        nonce_factory: N1,
    ) -> AgentBuilderImpl<N1> {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                nonce_factory,
                identity: self.config.identity,
                ingress_expiry_duration: self.config.ingress_expiry_duration,
                transport: self.config.transport,
            },
        }
    }

    /// Add an identity provider for signing messages. This is required.
    pub fn with_identity<I>(self, identity: I) -> Self
    where
        I: 'static + Identity,
    {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                identity: Arc::new(identity),
                ..self.config
            },
        }
    }

    /// Same as [with_identity], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_identity(self, identity: Box<dyn Identity>) -> Self {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                identity: Arc::from(identity),
                ..self.config
            },
        }
    }

    /// Provides a _default_ ingress expiry. This is the delta that will be applied
    /// at the time an update or query is made. The default expiry cannot be a
    /// fixed system time.
    pub fn with_ingress_expiry(self, duration: Option<std::time::Duration>) -> Self {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                ingress_expiry_duration: duration,
                ..self.config
            },
        }
    }
}
