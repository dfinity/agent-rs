use crate::RequestIdError;
use thiserror::Error;
use crate::hash_tree::InvalidHashTreeError;
use leb128::read;
use std::str::Utf8Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error(r#"Invalid Replica URL: "{0}""#)]
    InvalidReplicaUrl(String),

    #[error("The request timed out.")]
    TimeoutWaitingForResponse(),

    #[error("Identity had a signing error: {0}")]
    SigningError(String),

    #[error("Invalid CBOR data, could not deserialize: {0}")]
    InvalidCborData(#[from] serde_cbor::Error),

    #[error("Invalid HashTree")]
    HashTreeError(InvalidHashTreeError),

    #[error("Cannot calculate a RequestID: {0}")]
    CannotCalculateRequestId(#[from] RequestIdError),

    #[error("Could not reach the server")]
    ReqwestError(#[from] reqwest::Error),

    #[error("Candid returned an error: {0}")]
    CandidError(Box<dyn Send + Sync + std::error::Error>),

    #[error(r#"Cannot parse url: "{0}""#)]
    UrlParseError(#[from] url::ParseError),

    #[error("Cannot parse Principal: {0}")]
    PrincipalError(#[from] crate::export::PrincipalError),

    #[error(r#"The Replica returned an error: code {reject_code}, message: "{reject_message}""#)]
    ReplicaError {
        reject_code: u64,
        reject_message: String,
    },

    #[error(r#"The replica returned an HTTP Error: status code {status}"#)]
    HttpError {
        status: u16,
        content_type: Option<String>,
        content: Vec<u8>,
    },

    #[error("HTTP Authentication cannot be used in a non-secure URL (either HTTPS or localhost)")]
    CannotUseAuthenticationOnNonSecureUrl(),

    #[error("Password Manager returned an error: {0}")]
    AuthenticationError(String),

    #[error("Status endpoint returned an invalid status.")]
    InvalidReplicaStatus,

    #[error("Call was marked as done but we never saw the reply. Request ID: {0}")]
    RequestStatusDoneNoReply(String),

    #[error("A tool returned a string message error: {0}")]
    MessageError(String),

    #[error("A tool returned a custom error: {0}")]
    CustomError(#[from] Box<dyn Send + Sync + std::error::Error>),

    #[error("Error read LEB128 value: {0}")]
    Leb128ReadError(#[from] read::Error),

    #[error("Error in UTF-8 string: {0}")]
    Utf8ReadError(#[from] Utf8Error),
}

impl PartialEq for AgentError {
    fn eq(&self, other: &Self) -> bool {
        // Verify the debug string is the same. Some of the subtypes of this error
        // don't implement Eq or PartialEq, so we cannot rely on derive.
        format!("{:?}", self) == format!("{:?}", other)
    }
}
