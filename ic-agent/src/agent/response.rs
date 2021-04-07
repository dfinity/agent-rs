/// The response of /api/v2/canister/<effective_canister_id>/read_state with "request_status" request type.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RequestStatusResponse {
    Unknown,
    Received,
    Processing,
    Replied {
        reply: Replied,
    },
    Rejected {
        reject_code: u64,
        reject_message: String,
    },
    Done,
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Replied {
    CallReplied(Vec<u8>),
}
