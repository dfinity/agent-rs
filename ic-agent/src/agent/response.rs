use crate::agent::replica_api::RejectResponse;

/// The response of /api/v2/canister/<effective_canister_id>/read_state with "request_status" request type.
///
/// See [the HTTP interface specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-call-overview) for more details.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RequestStatusResponse {
    /// The status of the request is unknown.
    Unknown,
    /// The request has been received, and will probably get processed.
    Received,
    /// The request is currently being processed.
    Processing,
    /// The request has been successfully replied to.
    Replied {
        /// The reply from the replica.
        reply: Replied,
    },
    /// The request has been rejected.
    Rejected(RejectResponse),
    /// The call has been completed, and it has been long enough that the reply/reject data has been purged, but the call has not expired yet.
    Done,
}

#[allow(missing_docs)]
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Replied {
    CallReplied(Vec<u8>),
}
