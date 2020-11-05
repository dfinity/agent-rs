use crate::agent::AgentConfig;
use crate::{Agent, AgentError, Identity, NonceFactory, PasswordManager};

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
    pub fn with_url<S: Into<String>>(self, url: S) -> Self {
        AgentBuilder {
            config: AgentConfig {
                url: url.into(),
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
                identity: Box::new(identity),
                ..self.config
            },
        }
    }

    /// Same as [with_identity], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_identity(self, identity: Box<impl 'static + Identity + Send + Sync>) -> Self {
        AgentBuilder {
            config: AgentConfig {
                identity,
                ..self.config
            },
        }
    }

    /// Set the password manager. If the Agent makes a connection which requires an
    /// HTTP Authentication, it will ask this provider for a username and password
    /// pair.
    pub fn with_password_manager<P>(self, password_manager: P) -> Self
    where
        P: 'static + PasswordManager + Send + Sync,
    {
        AgentBuilder {
            config: AgentConfig {
                password_manager: Some(Box::new(password_manager)),
                ..self.config
            },
        }
    }

    /// Same as [with_password_manager], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_password_manager(
        self,
        password_manager: Box<impl 'static + PasswordManager + Send + Sync>,
    ) -> Self {
        AgentBuilder {
            config: AgentConfig {
                password_manager: Some(password_manager),
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
