use crate::RequestIdError;
use thiserror::Error;

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

    #[error("Cannot calculate a RequestID: {0}")]
    CannotCalculateRequestId(#[from] RequestIdError),

    #[error("Could not reach the server")]
    ReqwestError(#[from] reqwest::Error),

    #[error("Candid returned an error: {0}")]
    CandidError(#[from] candid::Error),

    #[error(r#"Cannot parse url: "{0}""#)]
    UrlParseError(#[from] url::ParseError),

    #[error("Cannot parse Principal: {0}")]
    PrincipalError(#[from] ic_types::principal::PrincipalError),

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
}
