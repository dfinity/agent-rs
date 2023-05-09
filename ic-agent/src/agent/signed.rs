//! Types representing signed messages.

use crate::{export::Principal, RequestId};

use serde::{Deserialize, Serialize};

/// A signed query request message. Produced by [`QueryBuilder::sign`](super::QueryBuilder::sign).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedQuery {
    /// The Unix timestamp that the request will expire at.
    pub ingress_expiry: u64,
    /// The principal ID of the caller.
    pub sender: Principal,
    /// The principal ID of the canister being called.
    pub canister_id: Principal,
    /// The name of the canister method being called.
    pub method_name: String,
    /// The argument blob to be passed to the method.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    /// The [effective canister ID](https://smartcontracts.org/docs/interface-spec/index.html#http-effective-canister-id) of the destination.
    pub effective_canister_id: Principal,
    /// The CBOR-encoded [authentication envelope](https://smartcontracts.org/docs/interface-spec/index.html#authentication) for the request.
    #[serde(with = "serde_bytes")]
    pub signed_query: Vec<u8>,
}

/// A signed update request message. Produced by [`UpdateBuilder::sign`](super::UpdateBuilder::sign).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedUpdate {
    /// A nonce to uniquely identify this update call.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes")]
    pub nonce: Option<Vec<u8>>,
    /// The Unix timestamp that the request will expire at.
    pub ingress_expiry: u64,
    /// The principal ID of the caller.
    pub sender: Principal,
    /// The principal ID of the canister being called.
    pub canister_id: Principal,
    /// The name of the canister method being called.
    pub method_name: String,
    /// The argument blob to be passed to the method.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    /// The [effective canister ID](https://smartcontracts.org/docs/interface-spec/index.html#http-effective-canister-id) of the destination.
    pub effective_canister_id: Principal,
    #[serde(with = "serde_bytes")]
    /// The CBOR-encoded [authentication envelope](https://smartcontracts.org/docs/interface-spec/index.html#authentication) for the request.
    pub signed_update: Vec<u8>,
    /// The request ID.
    pub request_id: RequestId,
}

/// A signed request-status request message. Produced by [`Agent::sign_request_status`](super::Agent::sign_request_status).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedRequestStatus {
    /// The Unix timestamp that the request will expire at.
    pub ingress_expiry: u64,
    /// The principal ID of the caller.
    pub sender: Principal,
    /// The [effective canister ID](https://smartcontracts.org/docs/interface-spec/index.html#http-effective-canister-id) of the destination.
    pub effective_canister_id: Principal,
    /// The request ID.
    pub request_id: RequestId,
    /// The CBOR-encoded [authentication envelope](https://smartcontracts.org/docs/interface-spec/index.html#authentication) for the request.
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
            sender: Principal::management_canister(),
            canister_id: Principal::management_canister(),
            method_name: "greet".to_string(),
            arg: vec![0, 1],
            effective_canister_id: Principal::management_canister(),
            signed_query: vec![0, 1, 2, 3],
        };
        let serialized = serde_json::to_string(&query).unwrap();
        let deserialized = serde_json::from_str::<SignedQuery>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_update_serde() {
        let update = SignedUpdate {
            nonce: None,
            ingress_expiry: 1,
            sender: Principal::management_canister(),
            canister_id: Principal::management_canister(),
            method_name: "greet".to_string(),
            arg: vec![0, 1],
            effective_canister_id: Principal::management_canister(),
            signed_update: vec![0, 1, 2, 3],
            request_id: RequestId::new(&[0; 32]),
        };
        let serialized = serde_json::to_string(&update).unwrap();
        let deserialized = serde_json::from_str::<SignedUpdate>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_request_status_serde() {
        let request_status = SignedRequestStatus {
            ingress_expiry: 1,
            sender: Principal::management_canister(),
            effective_canister_id: Principal::management_canister(),
            request_id: RequestId::new(&[0; 32]),
            signed_request_status: vec![0, 1, 2, 3],
        };
        let serialized = serde_json::to_string(&request_status).unwrap();
        let deserialized = serde_json::from_str::<SignedRequestStatus>(&serialized);
        assert!(deserialized.is_ok());
    }
}
