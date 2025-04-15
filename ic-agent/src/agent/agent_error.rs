//! Errors that can occur when using the replica agent.

use ic_certification::Label;
use ic_transport_types::RejectResponse;
use std::{
    error::Error,
    fmt::{Debug, Display, Formatter},
    time::Duration,
};
use thiserror::Error;

use super::{status::Status, Operation, OperationInfo, CURRENT_OPERATION};

pub struct AgentError {
    inner: Box<AgentErrorInner>,
}

#[derive(Debug)]
struct AgentErrorInner {
    source: Option<Box<dyn Error + Send + Sync>>,
    kind: ErrorKind,
    operation_info: Option<OperationInfo>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    Trust,
    Protocol,
    Reject,
    Transport,
    External,
    Limit,
    Input,
    Unknown,
}

impl AgentError {
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }
    pub fn operation_info(&self) -> Option<&OperationInfo> {
        self.inner.operation_info.as_ref()
    }
    pub fn new_tool_error_in_context(message: String) -> Self {
        todo!()
    }
    pub(crate) fn from_boxed_in_context(
        inner: Box<dyn Error + Send + Sync>,
        kind: ErrorKind,
    ) -> Self {
        match inner.downcast::<AgentError>() {
            Ok(agent_err) => *agent_err,
            Err(source) => AgentError {
                inner: Box::new(AgentErrorInner {
                    kind,
                    operation_info: CURRENT_OPERATION.try_with(|op| (*op.borrow()).clone()).ok(),
                    source: Some(source),
                }),
            },
        }
    }
}

impl Debug for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.inner, f)
    }
}

/// An error that occurred when using the agent.
#[derive(Error, Debug)]
pub(crate) enum ErrorCode {
    /// The replica URL was invalid.
    #[error(r#"Invalid Replica URL: "{0}""#)]
    InvalidReplicaUrl(String),

    /// The request timed out.
    #[error("The request timed out.")]
    TimeoutWaitingForResponse,

    /// An error occurred when signing with the identity.
    #[error("Identity had a signing error: {0}")]
    SigningError(String),

    /// The subnet rejected the message.
    #[error("The replica returned a rejection error: reject code {:?}, reject message {}, error code {:?}", .reject.reject_code, .reject.reject_message, .reject.error_code)]
    CertifiedReject {
        /// The rejection returned by the replica.
        reject: RejectResponse,
        /// The operation that was rejected. Not always available.
        operation: Option<Operation>,
    },

    /// The subnet may have rejected the message. This rejection cannot be verified as authentic.
    #[error("The replica returned a rejection error: reject code {:?}, reject message {}, error code {:?}", .reject.reject_code, .reject.reject_message, .reject.error_code)]
    UncertifiedReject {
        /// The rejection returned by the boundary node.
        reject: RejectResponse,
        /// The operation that was rejected. Not always available.
        operation: Option<Operation>,
    },

    /// The replica returned an HTTP error.
    #[error("The replica returned an HTTP Error: {0}")]
    HttpError(HttpErrorPayload),

    /// The status endpoint returned an invalid status.
    #[error("Status endpoint returned an invalid status.")]
    InvalidReplicaStatus,

    /// The call was marked done, but no reply was provided.
    #[error("Call was marked as done but we never saw the reply. Request ID: {0}")]
    RequestStatusDoneNoReply(String),

    /// A string error occurred in an external tool.
    #[error("A tool returned a string message error: {0}")]
    MessageError(String),

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

    /// The certificate verification for a `read_state` call failed.
    #[error("Certificate verification failed.")]
    CertificateVerificationFailed,

    /// The signature verification for a query call failed.
    #[error("Query signature verification failed.")]
    QuerySignatureVerificationFailed,

    /// The certificate contained a delegation that does not include the `effective_canister_id` in the `canister_ranges` field.
    #[error("Certificate is not authorized to respond to queries for this canister. While developing: Did you forget to set effective_canister_id?")]
    CertificateNotAuthorized,

    /// The certificate was older than allowed by the `ingress_expiry`.
    #[error("Certificate is stale (over {}s). Is the computer's clock synchronized?", .0.as_secs())]
    CertificateOutdated(Duration),

    /// The certificate contained more than one delegation.
    #[error("The certificate contained more than one delegation")]
    CertificateHasTooManyDelegations,

    /// The query response did not contain any node signatures.
    #[error("Query response did not contain any node signatures")]
    MissingSignature,

    /// The query response contained a malformed signature.
    #[error("Query response contained a malformed signature")]
    MalformedSignature,

    /// The read-state response contained a malformed public key.
    #[error("Read state response contained a malformed public key")]
    MalformedPublicKey,

    /// The query response contained more node signatures than the subnet has nodes.
    #[error("Query response contained too many signatures ({had}, exceeding the subnet's total nodes: {needed})")]
    TooManySignatures {
        /// The number of provided signatures.
        had: usize,
        /// The number of nodes on the subnet.
        needed: usize,
    },

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

    /// The response size exceeded the provided limit.
    #[error("Response size exceeded limit.")]
    ResponseSizeExceededLimit,

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

    /// Route provider failed to generate a url for some reason.
    #[error("Route provider failed to generate url: {0}")]
    RouteProviderError(String),

    /// Invalid HTTP response.
    #[error("Invalid HTTP response: {0}")]
    InvalidHttpResponse(String),
}

impl Error for AgentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source.as_ref().map(|s| &**s as _)
    }
}

impl Display for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl PartialEq for AgentError {
    fn eq(&self, other: &Self) -> bool {
        // Verify the debug string is the same. Some of the subtypes of this error
        // don't implement Eq or PartialEq, so we cannot rely on derive.
        format!("{self:?}") == format!("{other:?}")
    }
}

pub(crate) trait ResultExt<T> {
    fn context(self, kind: ErrorKind) -> Result<T, AgentError>;
}

impl<T, E: Error + Send + Sync + 'static> ResultExt<T> for Result<T, E> {
    fn context(self, kind: ErrorKind) -> Result<T, AgentError> {
        self.map_err(|e| AgentError::from_boxed_in_context(Box::new(e), kind))
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
            "Replica HTTP error: status {}, content type {:?}, content: {}",
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
    use super::HttpErrorPayload;

    #[test]
    fn content_type_none_valid_utf8() {
        let payload = HttpErrorPayload {
            status: 420,
            content_type: None,
            content: vec![104, 101, 108, 108, 111],
        };

        assert_eq!(
            format!("{payload}"),
            r#"Replica HTTP error: status 420 <unknown status code>, content type "", content: hello"#,
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
            format!("{payload}"),
            r#"Replica HTTP rror: status 420 <unknown status code>, content type "", content: (unable to decode content as UTF-8: [195, 40])"#,
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
            format!("{payload}"),
            r#"Replica HTTP error: status 420 <unknown status code>, content type "text/plain", content: hello"#,
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
            format!("{payload}"),
            r#"Replica HTTP error: status 420 <unknown status code>, content type "text/plain; charset=utf-8", content: hello"#,
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
            format!("{payload}"),
            r#"Replica HTTP error: status 420 <unknown status code>, content type "text/html", content: world"#,
        );
    }
}
