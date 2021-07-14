use crate::{export::Principal, RequestId};

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
    #[serde(default)]
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

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_query_serde() {
        let query = SignedQuery {
            ingress_expiry: 1,
            sender: Principal::from_slice(&[0; 29]),
            canister_id: Principal::from_slice(&[0; 29]),
            method_name: "greet".to_string(),
            arg: vec![0,1],
            effective_canister_id: Principal::from_slice(&[0; 29]),
            signed_query: vec![0,1,2,3],
        };
        let serialized = serde_json::to_string(&query).unwrap();
        let deserialized = serde_json::from_str::<SignedQuery>(&serialized);
        assert!(deserialized.is_ok());
    }
}