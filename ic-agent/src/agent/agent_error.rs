use crate::{Replied, RequestIdError};
use ic_types::PrincipalError;
use serde::export::Formatter;
use serde_cbor::error::Error as SerdeError;
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub enum AgentError {
    InvalidClientUrl(String),
    InvalidClientResponse,
    CannotCalculateRequestId(RequestIdError),
    EmptyResponse(),
    TimeoutWaitingForResponse,

    SigningError(String),

    InvalidCborData(serde_cbor::Error),
    ReqwestError(reqwest::Error),
    SerdeError(SerdeError),
    UrlParseError(url::ParseError),

    ReplicaError {
        reject_code: u64,
        reject_message: String,
    },
    HttpError {
        status: u16,
        content_type: Option<String>,
        content: Vec<u8>,
    },

    UnexpectedReply(Replied),

    CandidError(candid::Error),
    PrincipalError(PrincipalError),

    InstallModeError(String),

    CannotUseAuthenticationOnNonSecureUrl(),
    PasswordError(String),
}

impl Display for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for AgentError {}

impl From<SerdeError> for AgentError {
    fn from(err: SerdeError) -> Self {
        Self::SerdeError(err)
    }
}

impl From<reqwest::Error> for AgentError {
    fn from(err: reqwest::Error) -> Self {
        Self::ReqwestError(err)
    }
}

impl From<candid::Error> for AgentError {
    fn from(err: candid::Error) -> Self {
        Self::CandidError(err)
    }
}

impl From<url::ParseError> for AgentError {
    fn from(err: url::ParseError) -> Self {
        Self::UrlParseError(err)
    }
}

impl From<RequestIdError> for AgentError {
    fn from(err: RequestIdError) -> Self {
        Self::CannotCalculateRequestId(err)
    }
}

impl From<PrincipalError> for AgentError {
    fn from(err: PrincipalError) -> Self {
        Self::PrincipalError(err)
    }
}

impl From<AgentError> for String {
    fn from(err: AgentError) -> Self {
        format!("{:?}", err)
    }
}
