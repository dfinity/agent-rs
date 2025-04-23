//! Errors that can occur when using the agent.

use ic_certification::Label;
use ic_transport_types::RejectResponse;
use std::{
    error::Error,
    fmt::{Debug, Display, Formatter},
    time::Duration,
};
use thiserror::Error;

use super::{status::Status, Operation, OperationInfo, CURRENT_OPERATION};

/// An error that can occur when using an `Agent`. Includes partial operation info.
/// 
/// If (say) a deserialization hiccup occurred after a call returned, you can call the
/// [`operation_info()`](Self::operation_info) method to learn whether the call failed or succeeded,
/// and (if possible) what the response was.
pub struct AgentError {
    inner: Box<AgentErrorInner>,
}

#[derive(Debug)]
struct AgentErrorInner {
    source: Option<Box<dyn Error + Send + Sync>>,
    kind: ErrorKind,
    operation_info: Option<OperationInfo>,
}

/// What category of error occurred.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    /// Errors relating to certificate and signature verification. Plausibly due to malicious nodes,
    /// but far more likely due to running mainnet-targeting code against a dev instance.
    Trust,
    /// Errors relating to the IC protocol as defined by the specification (e.g. CBOR decoding).
    Protocol,
    /// Reject messages provided by the IC. Note that unless the [`OperationStatus`](super::OperationStatus)
    /// is `Received`, a reject cannot necessarily be trusted.
    Reject,
    /// Errors relating to the HTTP transport (e.g. TCP errors).
    Transport,
    /// Errors from a pluggable interface (e.g. [`Identity`](super::Identity)).
    External,
    /// Errors caused by hitting a user-provided limit (e.g. response body size).
    Limit,
    /// Errors caused by invalid input to a function.
    Input,
    /// Uncategorizable errors.
    Unknown,
}

impl AgentError {
    /// Returns what kind of error occurred.
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }
    /// Returns details on whatever operation was ongoing, or `None` if there wasn't one.
    pub fn operation_info(&self) -> Option<&OperationInfo> {
        self.inner.operation_info.as_ref()
    }
    /// Creates a new error for use in the [`RouteProvider`](super::RouteProvider) interface.
    /// `operation_info` will return `None` initially, this will be inserted by the agent.
    pub fn new_route_provider_error_without_context(message: String) -> Self {
        Self {
            inner: Box::new(AgentErrorInner {
                source: Some(Box::new(ErrorCode::RouteProviderError(message))),
                kind: ErrorKind::External,
                operation_info: None,
            }),
        }
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
    pub(crate) fn add_context(&mut self) {
        self.inner.operation_info = CURRENT_OPERATION.try_with(|op| (*op.borrow()).clone()).ok();
    }
    /// If this error is an HTTP error, retrieve the the payload. Equivalent to downcasting [`source()`](Error::source).
    pub fn as_http_error(&self) -> Option<&HttpErrorPayload> {
        self.inner.source.as_ref().and_then(|source| source.downcast_ref())
    }
}

impl Debug for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentError").field("source", &self.inner.source).field("kind", &self.inner.kind).field("operation_info", &self.inner.operation_info).finish()
    }
}

/// An error that occurred when using the agent.
#[derive(Error, Debug)]
pub(crate) enum ErrorCode {
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

    /// The status endpoint returned an invalid status.
    #[error("Status endpoint returned an invalid status.")]
    InvalidReplicaStatus,

    /// The call was marked done, but no reply was provided.
    #[error("Call was marked as done but we never saw the reply. Request ID: {0}")]
    RequestStatusDoneNoReply(String),

    /// The lookup path did not make sense for the certificate.
    #[error("The lookup path ({0:?}) does not make sense for the certificate.")]
    LookupPathError(Vec<Label>),

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

    /// Route provider failed to generate a url for some reason.
    #[error("Route provider failed to generate url: {0}")]
    RouteProviderError(String),

    /// Invalid HTTP response.
    #[error("Invalid HTTP response: {0}")]
    InvalidHttpResponse(String),

    /// Wrong envelope type for function.
    #[error("Wrong request type {found}, expected {expected}")]
    WrongRequestType { found: String, expected: String }
}

impl Error for AgentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source.as_ref().map(|s| &**s as _)
    }
}

impl Display for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.inner.kind {
            ErrorKind::External => {
                if let Some(source) = &self.inner.source {
                    write!(f, "{source}")?;
                } else {
                    write!(f, "unknown internal module error")?;
                }
                return Ok(());
            }
            ErrorKind::Input => write!(f, "input precondition failed")?,
            ErrorKind::Limit => write!(f, "internal limit reached")?,
            ErrorKind::Protocol => write!(f, "IC protocol error")?,
            ErrorKind::Reject => write!(f, "call rejected")?,
            ErrorKind::Transport => write!(f, "HTTP transport error")?,
            ErrorKind::Trust => write!(f, "trust error")?,
            ErrorKind::Unknown => write!(f, "internal error")?,
        }
        if let Some(source) = &self.inner.source {
            write!(f, ": {source}")?;
        }
        Ok(())
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
        // No matter whether content_type is text/* or not, always try to parse it as a string.
        // If this fails, print hex.
        let status = http::StatusCode::from_u16(self.status)
            .map_or_else(|_| format!("{}", self.status), |code| format!("{code}"));
        let content_type = self.content_type.as_deref().unwrap_or("<none>");
        if let Ok(content) = std::str::from_utf8(&self.content) {
            f.write_fmt(format_args!(
                r#"replica HTTP error: {content:?} (HTTP code {status}, content type {content_type:?})"#
            ))?;
        } else {
            f.write_fmt(format_args!(
                r#"replica HTTP error: 0x{} (non-UTF-8) (HTTP code {status}, content type {content_type:?})"#,
                hex::encode(&self.content)
            ))?;
        }
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

impl Error for HttpErrorPayload {}

impl AsRef<AgentError> for AgentError {
    fn as_ref(&self) -> &AgentError {
        self
    }
}

/// Errors produced by the `inspect_*` family of [`Agent`] methods.
#[derive(Debug)]
pub enum InspectionError {
    /// A field did not match.
    CallDataMismatch {
        /// The field that was mismatched.
        field: String,
        /// The value that was expected to be in the CBOR.
        value_arg: String,
        /// The value that was actually in the CBOR.
        value_cbor: String,
    },
    /// Failed for another reason (e.g. decoding).
    Other(AgentError)
}

impl Display for InspectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self { 
            InspectionError::CallDataMismatch { field, value_arg, value_cbor } => write!(f, "mismatch between the CBOR encoded call and the arguments: field {field}, value in argument is {value_arg}, value in CBOR is {value_cbor}"),
            InspectionError::Other(error) => write!(f, "inspection error: {error}"),
        }
    }
}

impl Error for InspectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Other(err) = self { Some(err) } else { None }
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
            r#"replica HTTP error: "hello" (HTTP code 420 <unknown status code>, content type "<none>")"#,
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
            r#"replica HTTP error: 0xc328 (non-UTF-8) (HTTP code 420 <unknown status code>, content type "<none>")"#,
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
            r#"replica HTTP error: "hello" (HTTP code 420 <unknown status code>, content type "text/plain")"#,
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
            r#"replica HTTP error: "hello" (HTTP code 420 <unknown status code>, content type "text/plain; charset=utf-8")"#,
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
            r#"replica HTTP error: "world" (HTTP code 420 <unknown status code>, content type "text/html")"#,
        );
    }
}
