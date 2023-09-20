//! Types related to the [HTTP transport](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-interface)
//! for the [Internet Computer](https://internetcomputer.org). Primarily used through [`ic-agent`](https://docs.rs/ic-agent).

#![warn(missing_docs, missing_debug_implementations)]
#![deny(elided_lifetimes_in_paths)]

use std::borrow::Cow;

use candid::Principal;
use ic_certification::Label;
pub use request_id::{to_request_id, RequestId, RequestIdError};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;

mod request_id;
pub mod signed;

/// The authentication envelope, containing the contents and their signature.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Envelope<'a> {
    /// The data that is signed by the caller.
    pub content: Cow<'a, EnvelopeContent>,
    /// The public key of the self-signing principal this request is from.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub sender_pubkey: Option<Vec<u8>>,
    /// A cryptographic signature authorizing the request. Not necessarily made by `sender_pubkey`; when delegations are involved,
    /// `sender_sig` is the tail of the delegation chain, and `sender_pubkey` is the head.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub sender_sig: Option<Vec<u8>>,
    /// The chain of delegations connecting `sender_pubkey` to `sender_sig`, and in that order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_delegation: Option<Vec<SignedDelegation>>,
}

/// The content of an IC ingress message, not including any signature information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request_type", rename_all = "snake_case")]
pub enum EnvelopeContent {
    /// A replicated call to a canister method, whether update or query.
    Call {
        /// A random series of bytes to uniquely identify this message.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
        nonce: Option<Vec<u8>>,
        /// A nanosecond timestamp after which this request is no longer valid.
        ingress_expiry: u64,
        /// The principal that is sending this request.
        sender: Principal,
        /// The ID of the canister to be called.
        canister_id: Principal,
        /// The name of the canister method to be called.
        method_name: String,
        /// The argument to pass to the canister method.
        #[serde(with = "serde_bytes")]
        arg: Vec<u8>,
    },
    /// A request for information from the [IC state tree](https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree).
    ReadState {
        /// A nanosecond timestamp after which this request is no longer valid.
        ingress_expiry: u64,
        /// The principal that is sending this request.
        sender: Principal,
        /// A list of paths within the state tree to fetch.
        paths: Vec<Vec<Label>>,
    },
    /// An unreplicated call to a canister query method.
    Query {
        /// A nanosecond timestamp after which this request is no longer valid.
        ingress_expiry: u64,
        /// The principal that is sending this request.
        sender: Principal,
        /// The ID of the canister to be called.
        canister_id: Principal,
        /// The name of the canister method to be called.
        method_name: String,
        /// The argument to pass to the canister method.
        #[serde(with = "serde_bytes")]
        arg: Vec<u8>,
    },
}

impl EnvelopeContent {
    /// Returns the `ingress_expiry` field common to all variants.
    pub fn ingress_expiry(&self) -> u64 {
        let (Self::Call { ingress_expiry, .. }
        | Self::Query { ingress_expiry, .. }
        | Self::ReadState { ingress_expiry, .. }) = self;
        *ingress_expiry
    }
    /// Returns the `sender` field common to all variants.
    pub fn sender(&self) -> &Principal {
        let (Self::Call { sender, .. }
        | Self::Query { sender, .. }
        | Self::ReadState { sender, .. }) = self;
        sender
    }
    /// Converts the envelope content to a request ID.
    ///
    /// Equivalent to calling [`to_request_id`], but infallible.
    pub fn to_request_id(&self) -> RequestId {
        to_request_id(self)
            .expect("to_request_id::<EnvelopeContent> should always succeed but did not")
    }
}

/// The response from a request to the `read_state` endpoint.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadStateResponse {
    /// A [certificate](https://internetcomputer.org/docs/current/references/ic-interface-spec#certificate), containing
    /// part of the system state tree as well as a signature to verify its authenticity.
    /// Use the [`ic-certification`](https://docs.rs/ic-certification) crate to process it.
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

/// Possible responses to a query call.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QueryResponse {
    /// The request was successfully replied to.
    Replied {
        /// The reply from the canister.
        reply: ReplyResponse,
    },
    /// The request was rejected.
    Rejected(RejectResponse),
}

/// An IC execution error received from the replica.
#[derive(Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct RejectResponse {
    /// The [reject code](https://internetcomputer.org/docs/current/references/ic-interface-spec#reject-codes) returned by the replica.
    pub reject_code: RejectCode,
    /// The rejection message.
    pub reject_message: String,
    /// The optional [error code](https://internetcomputer.org/docs/current/references/ic-interface-spec#error-codes) returned by the replica.
    #[serde(default)]
    pub error_code: Option<String>,
}

/// See the [interface spec](https://internetcomputer.org/docs/current/references/ic-interface-spec#reject-codes).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr, Ord, PartialOrd,
)]
#[repr(u8)]
pub enum RejectCode {
    /// Fatal system error, retry unlikely to be useful
    SysFatal = 1,
    /// Transient system error, retry might be possible.
    SysTransient = 2,
    /// Invalid destination (e.g. canister/account does not exist)
    DestinationInvalid = 3,
    /// Explicit reject by the canister.
    CanisterReject = 4,
    /// Canister error (e.g., trap, no response)
    CanisterError = 5,
}

impl TryFrom<u64> for RejectCode {
    type Error = InvalidRejectCodeError;

    fn try_from(value: u64) -> Result<Self, InvalidRejectCodeError> {
        match value {
            1 => Ok(RejectCode::SysFatal),
            2 => Ok(RejectCode::SysTransient),
            3 => Ok(RejectCode::DestinationInvalid),
            4 => Ok(RejectCode::CanisterReject),
            5 => Ok(RejectCode::CanisterError),
            _ => Err(InvalidRejectCodeError(value)),
        }
    }
}

/// Error returned from `RejectCode::try_from`.
#[derive(Debug, Error)]
#[error("Invalid reject code {0}")]
pub struct InvalidRejectCodeError(pub u64);

/// The response of `/api/v2/canister/<effective_canister_id>/read_state` with `request_status` request type.
///
/// See [the HTTP interface specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-call-overview) for more details.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum RequestStatusResponse {
    /// The status of the request is unknown.
    Unknown,
    /// The request has been received, and will probably get processed.
    Received,
    /// The request is currently being processed.
    Processing,
    /// The request has been successfully replied to.
    Replied(ReplyResponse),
    /// The request has been rejected.
    Rejected(RejectResponse),
    /// The call has been completed, and it has been long enough that the reply/reject data has been purged, but the call has not expired yet.
    Done,
}

/// A successful reply to a canister call.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ReplyResponse {
    /// The reply message, likely Candid-encoded.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
}

/// A delegation from one key to another.
///
/// If key A signs a delegation containing key B, then key B may be used to
/// authenticate as key A's corresponding principal(s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// The delegated-to key.
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    /// A nanosecond timestamp after which this delegation is no longer valid.
    pub expiration: u64,
    /// If present, this delegation only applies to requests sent to one of these canisters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Principal>>,
    /// If present, this delegation only applies to requests originating from one of these principals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub senders: Option<Vec<Principal>>,
}

const IC_REQUEST_DELEGATION_DOMAIN_SEPARATOR: &[u8] = b"\x1Aic-request-auth-delegation";

impl Delegation {
    /// Returns the signable form of the delegation, by running it through [`to_request_id`]
    /// and prepending `\x1Aic-request-auth-delegation` to the result.
    pub fn signable(&self) -> Vec<u8> {
        let hash = to_request_id(self).unwrap();
        let mut bytes = Vec::with_capacity(59);
        bytes.extend_from_slice(IC_REQUEST_DELEGATION_DOMAIN_SEPARATOR);
        bytes.extend_from_slice(hash.as_slice());
        bytes
    }
}

/// A [`Delegation`] that has been signed by an [`Identity`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDelegation {
    /// The signed delegation.
    pub delegation: Delegation,
    /// The signature for the delegation.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}
