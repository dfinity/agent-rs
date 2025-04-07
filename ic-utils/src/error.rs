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
}

impl<T: Error + From<AgentError> + From<candid::Error> + Send + Sync + 'static> CanisterError
    for T
{
    fn from_agent(err: AgentError) -> Self {
        Self::from(err)
    }
    fn from_candid(err: candid::Error) -> Self {
        Self::from(err)
    }
}
