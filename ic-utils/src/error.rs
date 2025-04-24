use ic_agent::AgentError;
use thiserror::Error;

/// A canister error for canisters that don't have any custom error cases.
#[derive(Debug, Error)]
pub enum BaseError {
    /// Agent error.
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),
    /// Candid error.
    #[error("{0}")]
    Candid(#[from] candid::Error),
}

/// Trait implemented by canister errors.
pub trait CanisterError: std::error::Error + Send + Sync + 'static {
    /// Creates an error from a context-free Candid error.
    fn from_candid(err: candid::Error) -> Self;
    /// Creates an error from a context-free agent error.
    fn from_agent(err: AgentError) -> Self;
    /// If this error wraps an agent error, returns it.
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
