//! Errors that can occur when using the replica agent.

use crate::{agent::status::Status, hash_tree::Label, RequestIdError};
use leb128::read;
use std::{
    fmt::{Debug, Display, Formatter},
    str::Utf8Error,
};
use thiserror::Error;

/// An error that occurred when using the agent.
#[derive(Error, Debug)]
pub enum AgentError {
    /// The replica URL was invalid.
    #[error(r#"Invalid Replica URL: "{0}""#)]
    InvalidReplicaUrl(String),

    /// The request timed out.
    #[error("The request timed out.")]
    TimeoutWaitingForResponse(),

    /// The waiter was restarted without being started first.
    #[error("The waiter was restarted without being started first.")]
    WaiterRestartError(),

    /// An error occurred when signing with the identity.
    #[error("Identity had a signing error: {0}")]
    SigningError(String),

    /// The data fetched was invalid CBOR.
    #[error("Invalid CBOR data, could not deserialize: {0}")]
    InvalidCborData(#[from] serde_cbor::Error),

    /// There was an error calculating a request ID.
    #[error("Cannot calculate a RequestID: {0}")]
    CannotCalculateRequestId(#[from] RequestIdError),

    /// There was an error when de/serializing with Candid.
    #[error("Candid returned an error: {0}")]
    CandidError(Box<dyn Send + Sync + std::error::Error>),

    /// There was an error parsing a URL.
    #[error(r#"Cannot parse url: "{0}""#)]
    UrlParseError(#[from] url::ParseError),

    /// The HTTP method was invalid.
    #[error(r#"Invalid method: "{0}""#)]
    InvalidMethodError(#[from] http::method::InvalidMethod),

    /// The principal string was not a valid principal.
    #[error("Cannot parse Principal: {0}")]
    PrincipalError(#[from] crate::export::PrincipalError),

    /// The replica rejected the message.
    #[error(r#"The Replica returned an error: code {reject_code}, message: "{reject_message}""#)]
    ReplicaError {
        /// The [reject code](https://smartcontracts.org/docs/interface-spec/index.html#reject-codes) returned by the replica.
        reject_code: u64,
        /// The rejection message.
        reject_message: String,
    },

    /// The replica returned an HTTP error.
    #[error("The replica returned an HTTP Error: {0}")]
    HttpError(HttpErrorPayload),

    /// Attempted to use HTTP authentication in a non-secure URL (either HTTPS or localhost).
    #[error("HTTP Authentication cannot be used in a non-secure URL (either HTTPS or localhost)")]
    CannotUseAuthenticationOnNonSecureUrl(),

    /// The password manager returned an error.
    #[error("Password Manager returned an error: {0}")]
    AuthenticationError(String),

    /// The status endpoint returned an invalid status.
    #[error("Status endpoint returned an invalid status.")]
    InvalidReplicaStatus,

    /// The call was marked done, but no reply was provided.
    #[error("Call was marked as done but we never saw the reply. Request ID: {0}")]
    RequestStatusDoneNoReply(String),

    /// A string error occurred in an external tool.
    #[error("A tool returned a string message error: {0}")]
    MessageError(String),

    /// An error occurred in an external tool.
    #[error("A tool returned a custom error: {0}")]
    CustomError(#[from] Box<dyn Send + Sync + std::error::Error>),

    /// There was an error reading a LEB128 value.
    #[error("Error reading LEB128 value: {0}")]
    Leb128ReadError(#[from] read::Error),

    /// A string was invalid UTF-8.
    #[error("Error in UTF-8 string: {0}")]
    Utf8ReadError(#[from] Utf8Error),

    /// The lookup path was absent in the certificate.
    #[error("The lookup path ({0:?}) is absent in the certificate.")]
    LookupPathAbsent(Vec<Label>),

    /// The lookup path was unknown in the certificate.
    #[error("The lookup path ({0:?}) is unknown in the certificate.")]
    LookupPathUnknown(Vec<Label>),

    /// The lookup path did not make sense for the certificate.
    #[error("The lookup path ({0:?}) does not make sense for the certificate.")]
    LookupPathError(Vec<Label>),

    /// The request status at the requested path was invalid.
    #[error("The request status ({1}) at path {0:?} is invalid.")]
    InvalidRequestStatus(Vec<Label>, String),

    /// The certificate verification failed.
    #[error("Certificate verification failed.")]
    CertificateVerificationFailed(),

    /// There was a length mismatch between the expected and actual length of the BLS DER-encoded public key.
    #[error(
        r#"BLS DER-encoded public key must be ${expected} bytes long, but is {actual} bytes long."#
    )]
    DerKeyLengthMismatch {
        /// The expected length of the key.
        expected: usize,
        /// The actual length of the key.
        actual: usize,
    },

    /// There was a mismatch between the expected and actual prefix of the BLS DER-encoded public key.
    #[error("BLS DER-encoded public key is invalid. Expected the following prefix: ${expected:?}, but got ${actual:?}")]
    DerPrefixMismatch {
        /// The expected key prefix.
        expected: Vec<u8>,
        /// The actual key prefix.
        actual: Vec<u8>,
    },

    /// The status response did not contain a root key.
    #[error("The status response did not contain a root key.  Status: {0}")]
    NoRootKeyInStatus(Status),

    /// Could not read the replica root key.
    #[error("Could not read the root key")]
    CouldNotReadRootKey(),

    /// Failed to initialize the BLS library.
    #[error("Failed to initialize the BLS library")]
    BlsInitializationFailure(),

    /// The invocation to the wallet call forward method failed with an error.
    #[error("The invocation to the wallet call forward method failed with the error: {0}")]
    WalletCallFailed(String),

    /// The wallet operation failed.
    #[error("The  wallet operation failed: {0}")]
    WalletError(String),

    /// The wallet canister must be upgraded. See [`dfx wallet upgrade`](https://smartcontracts.org/docs/developers-guide/cli-reference/dfx-wallet.html)
    #[error("The wallet canister must be upgraded: {0}")]
    WalletUpgradeRequired(String),

    /// The transport was not specified in the [`AgentBuilder`](super::AgentBuilder).
    #[error("Missing replica transport in the Agent Builder.")]
    MissingReplicaTransport(),

    /// An unknown error occurred during communication with the replica.
    #[error("An error happened during communication with the replica: {0}")]
    TransportError(Box<dyn std::error::Error + Send + Sync>),

    /// There was a mismatch between the expected and actual CBOR data during inspection.
    #[error("There is a mismatch between the CBOR encoded call and the arguments: field {field}, value in argument is {value_arg}, value in CBOR is {value_cbor}")]
    CallDataMismatch {
        /// The field that was mismatched.
        field: String,
        /// The value that was expected to be in the CBOR.
        value_arg: String,
        /// The value that was actually in the CBOR.
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

/// A HTTP error from the replica.
pub struct HttpErrorPayload {
    /// The HTTP status code.
    pub status: u16,
    /// The MIME type of `content`.
    pub content_type: Option<String>,
    /// The body of the error.
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
