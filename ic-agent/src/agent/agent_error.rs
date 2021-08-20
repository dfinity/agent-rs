use crate::{agent::status::Status, hash_tree::Label, RequestIdError};
use leb128::read;
use std::{
    fmt::{Debug, Display, Formatter},
    str::Utf8Error,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error(r#"Invalid Replica URL: "{0}""#)]
    InvalidReplicaUrl(String),

    #[error("The request timed out.")]
    TimeoutWaitingForResponse(),

    #[error("The waiter was restarted without being started first.")]
    WaiterRestartError(),

    #[error("Identity had a signing error: {0}")]
    SigningError(String),

    #[error("Invalid CBOR data, could not deserialize: {0}")]
    InvalidCborData(#[from] serde_cbor::Error),

    #[error("Cannot calculate a RequestID: {0}")]
    CannotCalculateRequestId(#[from] RequestIdError),

    #[error("Candid returned an error: {0}")]
    CandidError(Box<dyn Send + Sync + std::error::Error>),

    #[error(r#"Cannot parse url: "{0}""#)]
    UrlParseError(#[from] url::ParseError),

    #[error(r#"Invalid method: "{0}""#)]
    InvalidMethodError(#[from] http::method::InvalidMethod),

    #[error("Cannot parse Principal: {0}")]
    PrincipalError(#[from] crate::export::PrincipalError),

    #[error(r#"The Replica returned an error: code {reject_code}, message: "{reject_message}""#)]
    ReplicaError {
        reject_code: u64,
        reject_message: String,
    },

    #[error("The replica returned an HTTP Error: {0}")]
    HttpError(HttpErrorPayload),

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

    #[error("Error reading LEB128 value: {0}")]
    Leb128ReadError(#[from] read::Error),

    #[error("Error in UTF-8 string: {0}")]
    Utf8ReadError(#[from] Utf8Error),

    #[error("The lookup path ({0:?}) is absent in the certificate.")]
    LookupPathAbsent(Vec<Label>),

    #[error("The lookup path ({0:?}) is unknown in the certificate.")]
    LookupPathUnknown(Vec<Label>),

    #[error("The lookup path ({0:?}) does not make sense for the certificate.")]
    LookupPathError(Vec<Label>),

    #[error("The request status ({1}) at path {0:?} is invalid.")]
    InvalidRequestStatus(Vec<Label>, String),

    #[error("Certificate verification failed.")]
    CertificateVerificationFailed(),

    #[error(
        r#"BLS DER-encoded public key must be ${expected} bytes long, but is {actual} bytes long."#
    )]
    DerKeyLengthMismatch { expected: usize, actual: usize },

    #[error("BLS DER-encoded public key is invalid. Expected the following prefix: ${expected:?}, but got ${actual:?}")]
    DerPrefixMismatch { expected: Vec<u8>, actual: Vec<u8> },

    #[error("The status response did not contain a root key.  Status: {0}")]
    NoRootKeyInStatus(Status),

    #[error("Could not read the root key")]
    CouldNotReadRootKey(),

    #[error("Failed to initialize the BLS library")]
    BlsInitializationFailure(),

    #[error("The invocation to the wallet call forward method failed with the error: {0}")]
    WalletCallFailed(String),

    #[error("Missing replica transport in the Agent Builder.")]
    MissingReplicaTransport(),

    #[error("An error happened during communication with the replica: {0}")]
    TransportError(Box<dyn std::error::Error + Send + Sync>),

    #[error("There is a mismatch between the CBOR encoded call and the arguments: field {field}, value in argument is {value_arg}, value in CBOR is {value_cbor}")]
    CallDataMismatch {
        field: String,
        value_arg: String,
        value_cbor: String,
    },
}

impl PartialEq for AgentError {
    fn eq(&self, other: &Self) -> bool {
        // Verify the debug string is the same. Some of the subtypes of this error
        // don't implement Eq or PartialEq, so we cannot rely on derive.
        format!("{:?}", self) == format!("{:?}", other)
    }
}

pub struct HttpErrorPayload {
    pub status: u16,
    pub content_type: Option<String>,
    pub content: Vec<u8>,
}

impl HttpErrorPayload {
    fn fmt_human_readable(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        // No matter content_type is TEXT or not,
        // always try to parse it as a String.
        // When fail, print the raw byte array
        f.write_fmt(format_args!(
            "Http Error: status {}, content type {:?}, content: {}",
            http::StatusCode::from_u16(self.status)
                .map_or_else(|_| format!("{}", self.status), |code| format!("{}", code)),
            self.content_type.clone().unwrap_or_else(|| "".to_string()),
            String::from_utf8(self.content.clone()).unwrap_or_else(|_| format!(
                "(unable to decode content as UTF-8: {:?})",
                self.content
            ))
        ))?;
        Ok(())
    }
}

impl Debug for HttpErrorPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.fmt_human_readable(f)
    }
}

impl Display for HttpErrorPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.fmt_human_readable(f)
    }
}

#[cfg(test)]
mod tests {
    use super::HttpErrorPayload;
    use crate::AgentError;

    #[test]
    fn content_type_none_valid_utf8() {
        let payload = HttpErrorPayload {
            status: 420,
            content_type: None,
            content: vec![104, 101, 108, 108, 111],
        };

        assert_eq!(
            format!("{}", AgentError::HttpError(payload)),
            r#"The replica returned an HTTP Error: Http Error: status 420 <unknown status code>, content type "", content: hello"#,
        );
    }

    #[test]
    fn content_type_none_invalid_utf8() {
        let payload = HttpErrorPayload {
            status: 420,
            content_type: None,
            content: vec![195, 40],
        };

        assert_eq!(
            format!("{}", AgentError::HttpError(payload)),
            r#"The replica returned an HTTP Error: Http Error: status 420 <unknown status code>, content type "", content: (unable to decode content as UTF-8: [195, 40])"#,
        );
    }

    #[test]
    fn formats_text_plain() {
        let payload = HttpErrorPayload {
            status: 420,
            content_type: Some("text/plain".to_string()),
            content: vec![104, 101, 108, 108, 111],
        };

        assert_eq!(
            format!("{}", AgentError::HttpError(payload)),
            r#"The replica returned an HTTP Error: Http Error: status 420 <unknown status code>, content type "text/plain", content: hello"#,
        );
    }

    #[test]
    fn formats_text_plain_charset_utf8() {
        let payload = HttpErrorPayload {
            status: 420,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content: vec![104, 101, 108, 108, 111],
        };

        assert_eq!(
            format!("{}", AgentError::HttpError(payload)),
            r#"The replica returned an HTTP Error: Http Error: status 420 <unknown status code>, content type "text/plain; charset=utf-8", content: hello"#,
        );
    }

    #[test]
    fn formats_text_html() {
        let payload = HttpErrorPayload {
            status: 420,
            content_type: Some("text/html".to_string()),
            content: vec![119, 111, 114, 108, 100],
        };

        assert_eq!(
            format!("{}", AgentError::HttpError(payload)),
            r#"The replica returned an HTTP Error: Http Error: status 420 <unknown status code>, content type "text/html", content: world"#,
        );
    }
}
