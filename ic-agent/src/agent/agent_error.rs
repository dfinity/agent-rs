//! Errors that can occur when using the replica agent.

use crate::{agent::status::Status, RequestIdError};
use candid::Principal;
use ic_certification::Label;
use ic_transport_types::{InvalidRejectCodeError, RejectResponse};
use leb128::read;
use snafu::Snafu;
use std::error::Error;
use std::time::Duration;
use std::{
    fmt::{Debug, Display, Formatter},
    str::Utf8Error,
};
use thiserror::Error;
use time::OffsetDateTime;

use super::CURRENT_OPERATION;

/// An error that occurred when using the agent.
#[derive(Snafu, Debug)]
#[snafu(visibility(pub(crate)), context(suffix(Err)))]
pub(crate) enum AgentErrorInner {
    /// The request timed out.
    #[snafu(display("The request timed out."))]
    TimeoutWaitingForResponse,

    /// An error occurred when signing with the identity.
    #[snafu(display("Identity had a signing error: {message}"))]
    SigningError { message: String },

    /// The data fetched was invalid CBOR.
    #[snafu(display("Invalid CBOR data, could not deserialize: {source}"))]
    InvalidCborData { source: serde_cbor::Error },

    /// There was an error calculating a request ID.
    #[snafu(display("Failed to calculate request ID: {source}"))]
    CannotCalculateRequestId { source: RequestIdError },

    /// There was an error when de/serializing with Candid.
    #[snafu(display("Candid returned an error: {source}"))]
    CandidError {
        source: Box<dyn Send + Sync + std::error::Error>,
    },

    /// There was an error parsing a URL.
    #[snafu(display(r#"Cannot parse url "{input}": {source}"#))]
    UrlParseError {
        input: String,
        source: url::ParseError,
    },

    /// The HTTP method was invalid.
    #[snafu(display(r#"Invalid method "{input}""#))]
    InvalidMethod {
        input: String,
        source: http::method::InvalidMethod,
    },

    /// The principal string was not a valid principal.
    #[snafu(display(r#"Cannot parse principal "{input}": {source}"#))]
    PrincipalError {
        input: String,
        source: crate::export::PrincipalError,
    },

    /// The subnet rejected the message.
    #[snafu(display("The replica returned a rejection error: reject code {:?}, reject message {}, error code {:?}", reject.reject_code, reject.reject_message, reject.error_code))]
    CertifiedReject {
        /// The rejection returned by the replica.
        reject: RejectResponse,
        /// The operation that was rejected. Not always available.
        operation: Option<Operation>,
    },

    /// The subnet may have rejected the message. This rejection cannot be verified as authentic.
    #[snafu(display("The replica returned a rejection error: reject code {:?}, reject message {}, error code {:?}", reject.reject_code, reject.reject_message, reject.error_code))]
    UncertifiedReject {
        /// The rejection returned by the boundary node.
        reject: RejectResponse,
        /// The operation that was rejected. Not always available.
        operation: Option<Operation>,
    },

    /// The replica returned an HTTP error.
    #[snafu(display("The replica returned an HTTP Error: {payload}"))]
    HttpError { payload: HttpErrorPayload },

    /// The status endpoint returned an invalid status.
    #[snafu(display("Status endpoint returned an invalid status."))]
    InvalidReplicaStatus,

    /// The call was marked done, but no reply was provided.
    #[snafu(display(
        "Call was marked as done but we never saw the reply. Request ID: {request_id}"
    ))]
    RequestStatusDoneNoReply { request_id: String },

    /// A string error occurred in an external tool.
    #[snafu(display("A tool returned an error: {message}"))]
    MessageError { message: String },

    /// There was an error reading a LEB128 value.
    #[snafu(display("Error reading LEB128 value: {source}"))]
    Leb128ReadError { source: read::Error },

    /// A string was invalid UTF-8.
    #[snafu(display("Error in UTF-8 parsing: {source}"))]
    Utf8ReadError { source: Utf8Error },

    /// The lookup path was absent in the certificate.
    #[snafu(display("The lookup path ({path:?}) is absent in the certificate."))]
    LookupPathAbsent { path: Vec<Label> },

    /// The lookup path was unknown in the certificate.
    #[snafu(display("The lookup path ({path:?}) is unknown in the certificate."))]
    LookupPathUnknown { path: Vec<Label> },

    /// The lookup path did not make sense for the certificate.
    #[snafu(display("The lookup path ({path:?}) does not make sense for the certificate."))]
    LookupPathError { path: Vec<Label> },

    /// The request status at the requested path was invalid.
    #[snafu(display("The request status ({status}) at path {path:?} is invalid."))]
    InvalidRequestStatus { path: Vec<Label>, status: String },

    /// The certificate verification for a `read_state` call failed.
    #[snafu(display("Certificate verification failed."))]
    CertificateVerificationFailed,

    /// The signature verification for a query call failed.
    #[snafu(display("Query signature verification failed."))]
    QuerySignatureVerificationFailed,

    /// The certificate contained a delegation that does not include the `effective_canister_id` in the `canister_ranges` field.
    #[snafu(display("Certificate is not authorized to respond to queries for this canister. While developing: Did you forget to set effective_canister_id?"))]
    CertificateNotAuthorized,

    /// The certificate was older than allowed by the `ingress_expiry`.
    #[snafu(display(
        "Certificate is stale (over {}s). Is the computer's clock synchronized?", max_age.as_secs()
    ))]
    CertificateOutdated { max_age: Duration },

    /// The certificate contained more than one delegation.
    #[snafu(display("The certificate contained more than one delegation"))]
    CertificateHasTooManyDelegations,

    /// The query response did not contain any node signatures.
    #[snafu(display("Query response did not contain any node signatures"))]
    MissingSignature,

    /// The query response contained a malformed signature.
    #[snafu(display("Query response contained a malformed signature"))]
    MalformedSignature { source: ed25519_consensus::Error },

    /// The read-state response contained a malformed public key.
    #[snafu(display("Read state response contained a malformed public key"))]
    MalformedPublicKey { source: ed25519_consensus::Error },

    /// The query response contained more node signatures than the subnet has nodes.
    #[snafu(display("Query response contained too many signatures ({had}, exceeding the subnet's total nodes: {needed})"))]
    TooManySignatures {
        /// The number of provided signatures.
        had: usize,
        /// The number of nodes on the subnet.
        needed: usize,
    },

    /// There was a length mismatch between the expected and actual length of the BLS DER-encoded public key.
    #[snafu(display(
        r#"BLS DER-encoded public key must be {expected} bytes long, but was {actual} bytes long."#
    ))]
    DerKeyLengthMismatch {
        /// The expected length of the key.
        expected: usize,
        /// The actual length of the key.
        actual: usize,
    },

    /// There was a mismatch between the expected and actual prefix of the BLS DER-encoded public key.
    #[snafu(display(
        "BLS DER-encoded public key was invalid. Expected the following prefix: {}, but got {}",
        hex::encode(expected),
        hex::encode(actual)
    ))]
    DerPrefixMismatch {
        /// The expected key prefix.
        expected: Vec<u8>,
        /// The actual key prefix.
        actual: Vec<u8>,
    },

    /// The status response did not contain a root key.
    #[snafu(display("The status response did not contain a root key.  Status: {status}"))]
    NoRootKeyInStatus { status: Status },

    /// The invocation to the wallet call forward method failed with an error.
    #[snafu(display(
        "The invocation to the wallet call forward method failed with the error: {message}"
    ))]
    WalletCallFailed { message: String },

    /// The wallet operation failed.
    #[snafu(display("The  wallet operation failed: {message}"))]
    WalletError { message: String },

    /// The wallet canister must be upgraded. See [`dfx wallet upgrade`](https://internetcomputer.org/docs/current/references/cli-reference/dfx-wallet)
    #[snafu(display("The wallet canister must be upgraded: {message}"))]
    WalletUpgradeRequired { message: String },

    /// The response size exceeded the provided limit.
    #[snafu(display("Response size exceeded limit."))]
    ResponseSizeExceededLimit,

    /// An unknown error occurred during communication with the replica.
    #[snafu(display("An error happened during communication with the replica: {source}"))]
    TransportError { source: reqwest::Error },

    /// There was a mismatch between the expected and actual CBOR data during inspection.
    #[snafu(display("There is a mismatch between the CBOR encoded call and the arguments: field {field}, value in argument is {value_arg}, value in CBOR is {value_cbor}"))]
    CallDataMismatch {
        /// The field that was mismatched.
        field: String,
        /// The value that was expected to be in the CBOR.
        value_arg: String,
        /// The value that was actually in the CBOR.
        value_cbor: String,
    },

    /// The rejected call had an invalid reject code (valid range 1..5).
    #[snafu(transparent)]
    InvalidRejectCode { source: InvalidRejectCodeError },

    /// Route provider failed to generate a url for some reason.
    #[snafu(display("Route provider failed to generate url: {message}"))]
    RouteProviderError { message: String },

    /// Invalid HTTP response.
    #[snafu(display("Invalid HTTP response: {message}"))]
    InvalidHttpResponse { message: String },
}

impl AgentErrorInner {
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {}
    }

    pub(crate) fn op_context(self) -> AgentError {
        let operation_info = CURRENT_OPERATION.try_with(|op| (*op.borrow()).clone()).ok();
        AgentError {
            operation_info,
            kind: self.kind(),
            inner: Box::new(self),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    Trust,
    Protocol,
    Reject,
    Transport,
    Timeout,
    Size,
}

#[derive(Debug)]
pub struct AgentError {
    inner: Box<AgentErrorInner>,
    kind: ErrorKind,
    operation_info: Option<OperationInfo>,
}

impl AgentError {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
    pub fn operation_info(&self) -> Option<&OperationInfo> {
        self.operation_info.as_ref()
    }
    pub fn new_tool_error_in_context(message: String) -> Self {
        AgentErrorInner::MessageError { message }.op_context()
    }
    pub fn new_transport_error_in_context(source: reqwest::Error) -> Self {
        AgentErrorInner::TransportError { source }.op_context()
    }
}

impl Display for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error for AgentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source()
    }
}

impl PartialEq for AgentErrorInner {
    fn eq(&self, other: &Self) -> bool {
        // Verify the debug string is the same. Some of the subtypes of this error
        // don't implement Eq or PartialEq, so we cannot rely on derive.
        format!("{self:?}") == format!("{other:?}")
    }
}

pub(crate) trait ResultExt<T> {
    fn op_context(self) -> Result<T, AgentError>;
}

impl<T> ResultExt<T> for Result<T, AgentErrorInner> {
    fn op_context(self) -> Result<T, AgentError> {
        self.map_err(|e| e.op_context())
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
                .map_or_else(|_| format!("{}", self.status), |code| format!("{code}")),
            self.content_type.clone().unwrap_or_default(),
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
    use super::AgentError;
    use super::HttpErrorPayload;

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
