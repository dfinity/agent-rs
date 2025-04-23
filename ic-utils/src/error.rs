use std::error::Error;

use ic_agent::AgentError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BaseError {
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),
    #[error("{0}")]
    Candid(#[from] candid::Error),
}

pub trait CanisterError: std::error::Error + Send + Sync + 'static {
    fn from_candid(err: candid::Error) -> Self;
    fn from_agent(err: AgentError) -> Self;
    fn as_agent(&self) -> Option<&AgentError>;
}

macro_rules! impl_canister_error {
    (@ $name:path) => {
        impl $crate::error::CanisterError for $name {
            fn from_agent(err: ic_agent::AgentError) -> Self {
                Self::from(err)
            }
            fn from_candid(err: candid::Error) -> Self {
                Self::from(err)
            }
            fn as_agent(&self) -> Option<&ic_agent::AgentError> {
                match self {
                    Self::Agent(err) => Some(err),
                    _ => None,
                }
            }
        }
    };
    ($name:path) => {
        impl From<$crate::error::BaseError> for $name {
            fn from(base: BaseError) -> Self {
                match base {
                    BaseError::Agent(a) => Self::Agent(a),
                    BaseError::Candid(c) => Self::Candid(c),
                }
            }
        }
        $crate::error::impl_canister_error!(@ $name);
    };
}
pub(crate) use impl_canister_error;

impl_canister_error!(@ BaseError);
