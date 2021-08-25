use ic_agent::agent::{NonceGenerator, QueryBuilder, UpdateBuilder};

/// An expiry value. Either not specified (the default), a delay relative to the time the
/// call is made, or a specific date time.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Expiry {
    /// Unspecified. Will not try to override the Agent's value, which might itself have
    /// its own default value.
    Unspecified,

    /// A duration that will be added to the system time when the call is made.
    Delay(std::time::Duration),

    /// A specific date and time to use for the expiry of the request.
    DateTime(std::time::SystemTime),
}

impl Expiry {
    /// Create an expiry that happens after a duration.
    #[inline]
    pub fn after(d: std::time::Duration) -> Self {
        Self::Delay(d)
    }

    /// Set the expiry field to a specific date and time.
    #[inline]
    pub fn at(dt: std::time::SystemTime) -> Self {
        Self::DateTime(dt)
    }

    pub(crate) fn apply_to_update<N: NonceGenerator>(self, u: &mut UpdateBuilder<'_, N>) {
        match self {
            Expiry::Unspecified => {}
            Expiry::Delay(d) => {
                u.expire_after(d);
            }
            Expiry::DateTime(dt) => {
                u.expire_at(dt);
            }
        }
    }

    pub(crate) fn apply_to_query<N: NonceGenerator>(self, u: &mut QueryBuilder<'_, N>) {
        match self {
            Expiry::Unspecified => {}
            Expiry::Delay(d) => {
                u.expire_after(d);
            }
            Expiry::DateTime(dt) => {
                u.expire_at(dt);
            }
        }
    }
}

impl From<std::time::Duration> for Expiry {
    fn from(d: std::time::Duration) -> Self {
        Self::Delay(d)
    }
}

impl From<std::time::SystemTime> for Expiry {
    fn from(dt: std::time::SystemTime) -> Self {
        Self::DateTime(dt)
    }
}

impl Default for Expiry {
    fn default() -> Self {
        Expiry::Unspecified
    }
}
