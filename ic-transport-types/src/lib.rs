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

/// The authentication envelope, containing the contents and their signature. This struct can be passed to `Agent`'s
/// `*_signed` methods via [`encode_bytes`](Envelope::encode_bytes).
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

impl Envelope<'_> {
    /// Convert the authentication envelope to the format expected by the IC HTTP interface. The result can be passed to `Agent`'s `*_signed` methods.
    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut serializer = serde_cbor::Serializer::new(Vec::new());
        serializer.self_describe().unwrap();
        self.serialize(&mut serializer)
            .expect("infallible Envelope::serialize");
        serializer.into_inner()
    }
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
        /// A random series of bytes to uniquely identify this message.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
        nonce: Option<Vec<u8>>,
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

/// The parsed response from a request to the v3 `call` endpoint. A request to the `call` endpoint.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TransportCallResponse {
    /// The IC responded with a certified response.
    Replied {
        /// The CBOR serialized certificate for the call response.
        #[serde(with = "serde_bytes")]
        certificate: Vec<u8>,
    },

    /// The replica responded with a non replicated rejection.
    NonReplicatedRejection(RejectResponse),

    /// The replica timed out the sync request, but forwarded the ingress message
    /// to the canister. The request id should be used to poll for the response
    /// The status of the request must be polled.
    Accepted,
}

/// The response from a request to the `call` endpoint.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum CallResponse<Out> {
    /// The call completed, and the response is available.
    Response(Out),
    /// The replica timed out the update call, and the request id should be used to poll for the response
    /// using the `Agent::wait` method.
    Poll(RequestId),
}

impl<Out> CallResponse<Out> {
    /// Maps the inner value, if this is `Response`.
    #[inline]
    pub fn map<Out2>(self, f: impl FnOnce(Out) -> Out2) -> CallResponse<Out2> {
        match self {
            Self::Poll(p) => CallResponse::Poll(p),
            Self::Response(r) => CallResponse::Response(f(r)),
        }
    }
}

impl<T, E> CallResponse<Result<T, E>> {
    /// Extracts an inner `Result`, if this is `Response`.
    #[inline]
    pub fn transpose(self) -> Result<CallResponse<T>, E> {
        match self {
            Self::Poll(p) => Ok(CallResponse::Poll(p)),
            Self::Response(r) => r.map(CallResponse::Response),
        }
    }
}

impl<T> CallResponse<Option<T>> {
    /// Extracts an inner `Option`, if this is `Response`.
    #[inline]
    pub fn transpose(self) -> Option<CallResponse<T>> {
        match self {
            Self::Poll(p) => Some(CallResponse::Poll(p)),
            Self::Response(r) => r.map(CallResponse::Response),
        }
    }
}

impl<T> CallResponse<(T,)> {
    /// Extracts the inner value of a 1-tuple, if this is `Response`.`
    #[inline]
    pub fn detuple(self) -> CallResponse<T> {
        match self {
            Self::Poll(p) => CallResponse::Poll(p),
            Self::Response(r) => CallResponse::Response(r.0),
        }
    }
}

/// Possible responses to a query call.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QueryResponse {
    /// The request was successfully replied to.
    Replied {
        /// The reply from the canister.
        reply: ReplyResponse,

        /// The list of node signatures.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        signatures: Vec<NodeSignature>,
    },
    /// The request was rejected.
    Rejected {
        /// The rejection from the canister.
        #[serde(flatten)]
        reject: RejectResponse,

        /// The list of node signatures.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        signatures: Vec<NodeSignature>,
    },
}

impl QueryResponse {
    /// Returns the signable form of the query response, as described in
    /// [the spec](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-query).
    /// This is what is signed in the `signatures` fields.
    pub fn signable(&self, request_id: RequestId, timestamp: u64) -> Vec<u8> {
        #[derive(Serialize)]
        #[serde(tag = "status", rename_all = "snake_case")]
        enum QueryResponseSignable<'a> {
            Replied {
                reply: &'a ReplyResponse, // polyfill until hash_of_map is figured out
                request_id: RequestId,
                timestamp: u64,
            },
            Rejected {
                reject_code: RejectCode,
                reject_message: &'a String,
                #[serde(default)]
                error_code: Option<&'a String>,
                request_id: RequestId,
                timestamp: u64,
            },
        }
        let response = match self {
            Self::Replied { reply, .. } => QueryResponseSignable::Replied {
                reply,
                request_id,
                timestamp,
            },
            Self::Rejected { reject, .. } => QueryResponseSignable::Rejected {
                error_code: reject.error_code.as_ref(),
                reject_code: reject.reject_code,
                reject_message: &reject.reject_message,
                request_id,
                timestamp,
            },
        };
        let mut signable = Vec::with_capacity(44);
        signable.extend_from_slice(b"\x0Bic-response");
        signable.extend_from_slice(to_request_id(&response).unwrap().as_slice());
        signable
    }

    /// Helper function to get the signatures field present in both variants.
    pub fn signatures(&self) -> &[NodeSignature] {
        match self {
            Self::Rejected { signatures, .. } => signatures,
            Self::Replied { signatures, .. } => signatures,
        }
    }
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

/// A [`Delegation`] that has been signed by an [`Identity`](https://docs.rs/ic-agent/latest/ic_agent/trait.Identity.html).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDelegation {
    /// The signed delegation.
    pub delegation: Delegation,
    /// The signature for the delegation.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// A response signature from an individual node.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeSignature {
    /// The timestamp that the signature was created at.
    pub timestamp: u64,
    /// The signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// The ID of the  node.
    pub identity: Principal,
}

/// A list of subnet metrics.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SubnetMetrics {
    /// The number of canisters on this subnet.
    pub num_canisters: u64,
    /// The total size of the state in bytes taken by canisters on this subnet since this subnet was created.
    pub canister_state_bytes: u64,
    /// The total number of cycles consumed by all current and deleted canisters on this subnet.
    #[serde(with = "map_u128")]
    pub consumed_cycles_total: u128,
    /// The total number of transactions processed on this subnet since this subnet was created.
    pub update_transactions_total: u64,
}

mod map_u128 {
    use serde::{
        de::{Error, IgnoredAny, MapAccess, Visitor},
        ser::SerializeMap,
        Deserializer, Serializer,
    };
    use std::fmt;

    pub fn serialize<S: Serializer>(val: &u128, s: S) -> Result<S::Ok, S::Error> {
        let low = *val & u64::MAX as u128;
        let high = *val >> 64;
        let mut map = s.serialize_map(Some(2))?;
        map.serialize_entry(&0, &low)?;
        map.serialize_entry(&1, &(high != 0).then_some(high))?;
        map.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        d.deserialize_map(MapU128Visitor)
    }

    struct MapU128Visitor;

    impl<'de> Visitor<'de> for MapU128Visitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map of low and high")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let (_, low): (IgnoredAny, u64) = map
                .next_entry()?
                .ok_or_else(|| A::Error::missing_field("0"))?;
            let opt: Option<(IgnoredAny, Option<u64>)> = map.next_entry()?;
            let high = opt.and_then(|x| x.1).unwrap_or(0);
            Ok((high as u128) << 64 | low as u128)
        }
    }
}
