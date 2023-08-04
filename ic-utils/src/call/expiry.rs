use std::time::{Duration, SystemTime};

use ic_agent::agent::{QueryBuilder, UpdateBuilder};
use time::OffsetDateTime;

/// An expiry value. Either not specified (the default), a delay relative to the time the
/// call is made, or a specific date time.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Default)]
pub enum Expiry {
    /// Unspecified. Will not try to override the Agent's value, which might itself have
    /// its own default value.
    #[default]
    Unspecified,

    /// A duration that will be added to the system time when the call is made.
    Delay(Duration),

    /// A specific date and time to use for the expiry of the request.
    DateTime(OffsetDateTime),
}

impl Expiry {
    /// Create an expiry that happens after a duration.
    #[inline]
    pub fn after(d: Duration) -> Self {
        Self::Delay(d)
    }

    /// Set the expiry field to a specific date and time.
    #[inline]
    pub fn at(dt: impl Into<OffsetDateTime>) -> Self {
        Self::DateTime(dt.into())
    }

    pub(crate) fn apply_to_update(self, u: UpdateBuilder<'_>) -> UpdateBuilder<'_> {
        match self {
            Expiry::Unspecified => u,
            Expiry::Delay(d) => u.expire_after(d),
            Expiry::DateTime(dt) => u.expire_at(dt),
        }
    }

    pub(crate) fn apply_to_query(self, u: QueryBuilder<'_>) -> QueryBuilder<'_> {
        match self {
            Expiry::Unspecified => u,
            Expiry::Delay(d) => u.expire_after(d),
            Expiry::DateTime(dt) => u.expire_at(dt),
        }
    }
}

impl From<Duration> for Expiry {
    fn from(d: Duration) -> Self {
        Self::Delay(d)
    }
}

impl From<SystemTime> for Expiry {
    fn from(dt: SystemTime) -> Self {
        Self::DateTime(dt.into())
    }
}

impl From<OffsetDateTime> for Expiry {
    fn from(dt: OffsetDateTime) -> Self {
        Self::DateTime(dt)
    }
}
