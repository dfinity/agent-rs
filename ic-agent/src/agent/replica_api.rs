use std::borrow::Cow;

use crate::{export::Principal, to_request_id, AgentError, RequestId};
use ic_certification::Label;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Envelope<'a> {
    pub content: Cow<'a, EnvelopeContent>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes")]
    pub sender_pubkey: Option<Vec<u8>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes")]
    pub sender_sig: Option<Vec<u8>>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "request_type")]
pub enum SyncContent {
    #[serde(rename = "read_state")]
    ReadStateRequest {
        ingress_expiry: u64,
        sender: Principal,
        paths: Vec<Vec<Label>>,
    },
    #[serde(rename = "query")]
    QueryRequest {
        ingress_expiry: u64,
        sender: Principal,
        canister_id: Principal,
        method_name: String,
        #[serde(with = "serde_bytes")]
        arg: Vec<u8>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadStateResponse {
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status")]
pub enum Status {
    #[serde(rename = "unknown")]
    Unknown {},
    #[serde(rename = "received")]
    Received {},
    #[serde(rename = "processing")]
    Processing {},
    #[serde(rename = "replied")]
    Replied { reply: RequestStatusResponseReplied },
    #[serde(rename = "rejected")]
    Rejected {
        reject_code: u64,
        reject_message: String,
    },
    #[serde(rename = "done")]
    Done {},
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RequestStatusResponseReplied {
    CallReply(CallReply),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallReply {
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status")]
pub enum QueryResponse {
    #[serde(rename = "replied")]
    Replied { reply: CallReply },
    #[serde(rename = "rejected")]
    Rejected(RejectResponse),
}

/// An IC execution error received from the replica.
#[derive(Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct RejectResponse {
    /// The [reject code](https://smartcontracts.org/docs/interface-spec/index.html#reject-codes) returned by the replica.
    pub reject_code: RejectCode,
    /// The rejection message.
    pub reject_message: String,
    /// The optional [error code](https://smartcontracts.org/docs/interface-spec/index.html#error-codes) returned by the replica.
    #[serde(default)]
    pub error_code: Option<String>,
}

/// See the [interface spec](https://smartcontracts.org/docs/interface-spec/index.html#reject-codes).
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
    type Error = AgentError;

    fn try_from(value: u64) -> Result<Self, AgentError> {
        match value {
            1 => Ok(RejectCode::SysFatal),
            2 => Ok(RejectCode::SysTransient),
            3 => Ok(RejectCode::DestinationInvalid),
            4 => Ok(RejectCode::CanisterReject),
            5 => Ok(RejectCode::CanisterError),
            _ => Err(AgentError::MessageError(format!(
                "Received an invalid reject code {}",
                value
            ))),
        }
    }
}
