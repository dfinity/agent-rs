use std::time::Duration;
use garcon::Delay;

pub(crate) fn waiter_with_timeout(duration: Duration) -> Delay {
    Delay::builder().timeout(duration).build()
}

