use crate::{
    agent::{agent_config::AgentConfigImpl, AgentImpl, ReplicaV2Transport},
    AgentError, Identity, NonceFactory, NonceGenerator,
};
use std::sync::Arc;

pub type AgentBuilder =
    AgentBuilderImpl<NonceFactory, Arc<dyn Identity>, Arc<dyn ReplicaV2Transport>>;

pub struct AgentBuilderImpl<N: NonceGenerator, I: Identity, T: ReplicaV2Transport> {
    config: AgentConfigImpl<N, I, T>,
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self {
            config: Default::default(),
        }
    }
}

impl<N: NonceGenerator, I: Identity, T: ReplicaV2Transport> AgentBuilderImpl<N, I, T> {
    /// Create an instance of [AgentImpl] with the information from this builder.
    pub fn build(self) -> Result<AgentImpl<N, I, T>, AgentError> {
        AgentImpl::new(self.config)
    }

    /// Set a Replica transport to talk to serve as the replica interface.
    pub fn with_transport<T1: ReplicaV2Transport>(
        self,
        transport: T1,
    ) -> AgentBuilderImpl<N, I, T1> {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                nonce_factory: self.config.nonce_factory,
                identity: self.config.identity,
                ingress_expiry_duration: self.config.ingress_expiry_duration,
                transport: Some(transport),
            },
        }
    }

    /// Add a NonceFactory to this AgentImpl. By default, no nonce is produced.
    pub fn with_nonce_factory(
        self,
        nonce_factory: NonceFactory,
    ) -> AgentBuilderImpl<NonceFactory, I, T> {
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
    ) -> AgentBuilderImpl<N1, I, T> {
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
    pub fn with_identity<I1: Identity>(self, identity: I1) -> AgentBuilderImpl<N, I1, T> {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                nonce_factory: self.config.nonce_factory,
                identity,
                ingress_expiry_duration: self.config.ingress_expiry_duration,
                transport: self.config.transport,
            },
        }
    }

    /// Same as [with_identity], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_identity(
        self,
        identity: Box<dyn Identity>,
    ) -> AgentBuilderImpl<N, Arc<dyn Identity>, T> {
        AgentBuilderImpl {
            config: AgentConfigImpl {
                nonce_factory: self.config.nonce_factory,
                identity: Arc::from(identity),
                ingress_expiry_duration: self.config.ingress_expiry_duration,
                transport: self.config.transport,
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
