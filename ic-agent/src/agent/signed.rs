use crate::export::Principal;
use crate::RequestId;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedQuery {
    pub ingress_expiry: u64,
    pub sender: Principal,
    pub canister_id: Principal,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,

    pub effective_canister_id: Principal,

    #[serde(with = "serde_bytes")]
    pub signed_query: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes")]
    pub nonce: Option<Vec<u8>>,
    pub ingress_expiry: u64,
    pub sender: Principal,
    pub canister_id: Principal,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,

    pub effective_canister_id: Principal,

    #[serde(with = "serde_bytes")]
    pub signed_update: Vec<u8>,

    pub request_id: RequestId,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedRequestStatus {
    pub ingress_expiry: u64,
    pub sender: Principal,
    pub effective_canister_id: Principal,
    pub request_id: RequestId,
    #[serde(with = "serde_bytes")]
    pub signed_request_status: Vec<u8>,
}
