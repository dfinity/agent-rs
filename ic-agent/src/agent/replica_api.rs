use ic_types::Principal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Envelope<T: Serialize> {
    pub content: T,
    #[serde(with = "serde_bytes")]
    pub sender_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sender_sig: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "request_type")]
pub enum AsyncContent {
    #[serde(rename = "call")]
    CallRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "serde_bytes")]
        nonce: Option<Vec<u8>>,
        ingress_expiry: u64,
        sender: Principal,
        canister_id: Principal,
        method_name: String,
        #[serde(with = "serde_bytes")]
        arg: Vec<u8>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "request_type")]
pub enum SyncContent {
    #[serde(rename = "request_status")]
    RequestStatusRequest {
        ingress_expiry: u64,
        #[serde(with = "serde_bytes")]
        request_id: Vec<u8>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestStatusResponse {
    pub status: Status,
    #[serde(rename = "time")]
    pub time: u64,
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
// Doesn't work
// ---- agent::agent_test::call stdout ----
// Error: InvalidCborData(ErrorImpl { code: Message("missing field `time`"), offset: 0 })
// thread 'agent::agent_test::call' panicked at 'assertion failed: `(left == right)`
//   left: `1`,
//  right: `0`: the test returned a termination value with a non-zero status code (1) which indicates a failure', <::std::macros::panic macros>:5:6
// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

// ---- agent::agent_test::call_rejected stdout ----
// thread 'agent::agent_test::call_rejected' panicked at 'internal error: entered unreachable code: Err(InvalidCborData(ErrorImpl { code: Message("missing field `time`"), offset: 0 }))', ic-agent/src/agent/agent_test.rs:186:19
// #[derive(Debug, Clone, Deserialize, Serialize)]
// #[serde(tag = "status")]
// pub enum RequestStatusResponse {
//     #[serde(rename = "unknown")]
//     Unknown { time: u64 },
//     #[serde(rename = "received")]
//     Received { time: u64 },
//     #[serde(rename = "processing")]
//     Processing { time: u64 },
//     #[serde(rename = "replied")]
//     Replied {
//         reply: RequestStatusResponseReplied,
//         time: u64,
//     },
//     #[serde(rename = "rejected")]
//     Rejected {
//         reject_code: u64,
//         reject_message: String,
//         time: u64,
//     },
//     #[serde(rename = "done")]
//     Done { time: u64 },
// }

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
    Rejected {
        reject_code: u64,
        reject_message: String,
    },
}
