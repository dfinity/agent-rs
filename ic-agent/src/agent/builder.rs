use crate::{Agent, AgentConfig, AgentError, Identity, NonceFactory, PasswordManager};

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
    pub fn build(self) -> Result<Agent, AgentError> {
        Agent::new(self.config)
    }

    pub fn with_url<S: ToString>(self, url: S) -> Self {
        AgentBuilder {
            config: AgentConfig {
                url: url.to_string(),
                ..self.config
            },
        }
    }

    pub fn with_nonce_factory(self, nonce_factory: NonceFactory) -> Self {
        AgentBuilder {
            config: AgentConfig {
                nonce_factory,
                ..self.config
            },
        }
    }

    pub fn with_identity<I: 'static + Identity>(self, identity: I) -> Self {
        AgentBuilder {
            config: AgentConfig {
                identity: Box::new(identity),
                ..self.config
            },
        }
    }

    pub fn with_waiter(self, waiter: delay::Delay) -> Self {
        AgentBuilder {
            config: AgentConfig {
                default_waiter: waiter,
                ..self.config
            },
        }
    }

    pub fn with_password_manager<P: 'static + PasswordManager>(self, password_manager: P) -> Self {
        AgentBuilder {
            config: AgentConfig {
                password_manager: Some(Box::new(password_manager)),
                ..self.config
            },
        }
    }

    pub fn with_expiry(self, ingress_expiry: u64) -> Self {
        AgentBuilder {
            config: AgentConfig {
                ingress_expiry,
                ..self.config
            },
        }
    }
}
