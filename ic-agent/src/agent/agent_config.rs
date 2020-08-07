use crate::identity::dummy::DummyIdentity;
use crate::identity::Identity;
use crate::NonceFactory;

/// Implemented by the Agent environment to cache and update an HTTP Auth password.
/// It returns a tuple of `(username, password)`.
pub trait PasswordManager {
    /// Retrieve the cached value for a user. If no cache value exists for this URL,
    /// the manager can return [`None`].
    fn cached(&self, url: &str) -> Result<Option<(String, String)>, String>;

    /// A call to the replica failed, so in order to succeed a username and password
    /// is required. If one cannot be provided (for example, there's no terminal),
    /// this should return an error.
    /// If the username and password provided by this method does not work (the next
    /// request still returns UNAUTHORIZED), this will be called and the request will
    /// be retried in a loop.
    fn required(&self, url: &str) -> Result<(String, String), String>;
}

pub struct AgentConfig<'a> {
    pub url: &'a str,
    pub nonce_factory: NonceFactory,
    pub identity: Box<dyn Identity>,
    pub default_waiter: delay::Delay,
    pub password_manager: Option<Box<dyn PasswordManager>>,
}

impl Default for AgentConfig<'_> {
    fn default() -> Self {
        Self {
            // Making sure this is invalid so users have to overwrite it.
            url: "-",
            nonce_factory: NonceFactory::random(),
            identity: Box::new(DummyIdentity {}),
            default_waiter: delay::Delay::instant(),
            password_manager: None,
        }
    }
}
