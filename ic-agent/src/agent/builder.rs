use crate::{
    agent::{agent_config::AgentConfig, Agent, Transport},
    AgentError, Identity, NonceFactory, NonceGenerator,
};
use std::sync::Arc;
use std::time::Duration;

/// A builder for an [`Agent`].
#[derive(Default)]
pub struct AgentBuilder {
    config: AgentConfig,
}

impl AgentBuilder {
    /// Create an instance of [Agent] with the information from this builder.
    pub fn build(self) -> Result<Agent, AgentError> {
        Agent::new(self.config)
    }

    /// Set the URL of the [Agent].
    #[cfg(feature = "reqwest")]
    pub fn with_url<S: Into<String>>(self, url: S) -> Self {
        use crate::agent::http_transport::ReqwestTransport;

        self.with_transport(ReqwestTransport::create(url).unwrap())
    }

    /// Set a Replica transport to talk to serve as the replica interface.
    pub fn with_transport<T: 'static + Transport>(self, transport: T) -> Self {
        self.with_arc_transport(Arc::new(transport))
    }

    /// Same as [Self::with_transport], but provides a `Arc` boxed implementation instead
    /// of a direct type.
    pub fn with_arc_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.config.transport = Some(transport);
        self
    }

    /// Add a NonceFactory to this Agent. By default, no nonce is produced.
    pub fn with_nonce_factory(self, nonce_factory: NonceFactory) -> AgentBuilder {
        self.with_nonce_generator(nonce_factory)
    }

    /// Same as [Self::with_nonce_factory], but for any `NonceGenerator` type
    pub fn with_nonce_generator<N: 'static + NonceGenerator>(
        self,
        nonce_factory: N,
    ) -> AgentBuilder {
        self.with_arc_nonce_generator(Arc::new(nonce_factory))
    }

    /// Same as [Self::with_nonce_generator], but provides a `Arc` boxed implementation instead
    /// of a direct type.
    pub fn with_arc_nonce_generator(
        mut self,
        nonce_factory: Arc<dyn NonceGenerator>,
    ) -> AgentBuilder {
        self.config.nonce_factory = Arc::new(nonce_factory);
        self
    }

    /// Add an identity provider for signing messages. This is required.
    pub fn with_identity<I>(self, identity: I) -> Self
    where
        I: 'static + Identity,
    {
        self.with_arc_identity(Arc::new(identity))
    }

    /// Same as [Self::with_identity], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_identity(self, identity: Box<dyn Identity>) -> Self {
        self.with_arc_identity(Arc::from(identity))
    }

    /// Same as [Self::with_identity], but provides a `Arc` boxed implementation instead
    /// of a direct type.
    pub fn with_arc_identity(mut self, identity: Arc<dyn Identity>) -> Self {
        self.config.identity = identity;
        self
    }

    /// Provides a _default_ ingress expiry. This is the delta that will be applied
    /// at the time an update or query is made. The default expiry cannot be a
    /// fixed system time.
    pub fn with_ingress_expiry(mut self, ingress_expiry: Option<std::time::Duration>) -> Self {
        self.config.ingress_expiry = ingress_expiry;
        self
    }

    /// Sets the initial backoff interval used for polling the IC when awaiting a response.
    pub fn set_backoff_initial_interval(mut self, initial_interval: Duration) -> Self {
        self.config.backoff_initial_interval = initial_interval;
        self
    }

    /// Sets the max backoff interval used for polling the IC when awaiting a response.
    pub fn set_backoff_max_interval(mut self, max_interval: Duration) -> Self {
        self.config.backoff_max_interval = max_interval;
        self
    }

    /// Sets the value to multiply the current interval with for each retry attempt
    /// when polling the IC for a response.
    pub fn set_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.config.backoff_multiplier = multiplier;
        self
    }
}
