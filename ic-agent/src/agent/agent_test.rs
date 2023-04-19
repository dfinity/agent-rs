// Disable these tests without the reqwest feature.
#![cfg(feature = "reqwest")]

use self::mock::{assert_mock, mock};
use crate::{
    agent::{
        http_transport::ReqwestTransport,
        replica_api::{CallReply, QueryResponse, RejectCode},
        Status,
    },
    export::Principal,
    Agent, AgentError,
};
use ic_certification::Label;
use std::collections::BTreeMap;
#[cfg(target_family = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test;

use super::replica_api::RejectResponse;

#[cfg(target_family = "wasm")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn query() -> Result<(), AgentError> {
    let blob = Vec::from("Hello World");
    let response = QueryResponse::Replied {
        reply: CallReply { arg: blob.clone() },
    };

    let (query_mock, url) = mock(
        "POST",
        "/api/v2/canister/aaaaa-aa/query",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url)?)
        .build()?;
    let result = agent
        .query_raw(
            &Principal::management_canister(),
            Principal::management_canister(),
            "main",
            &[],
            None,
        )
        .await;

    assert_mock(query_mock).await;

    assert_eq!(result?, blob);

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn query_error() -> Result<(), AgentError> {
    let (query_mock, url) =
        mock("POST", "/api/v2/canister/aaaaa-aa/query", 500, vec![], None).await;
    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(url)?)
        .build()?;

    let result = agent
        .query_raw(
            &Principal::management_canister(),
            Principal::management_canister(),
            "greet",
            &[],
            None,
        )
        .await;

    assert_mock(query_mock).await;

    assert!(result.is_err());

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn query_rejected() -> Result<(), AgentError> {
    let response: QueryResponse = QueryResponse::Rejected(RejectResponse {
        reject_code: RejectCode::DestinationInvalid,
        reject_message: "Rejected Message".to_string(),
        error_code: None,
    });

    let (query_mock, url) = mock(
        "POST",
        "/api/v2/canister/aaaaa-aa/query",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url)?)
        .build()?;

    let result = agent
        .query_raw(
            &Principal::management_canister(),
            Principal::management_canister(),
            "greet",
            &[],
            None,
        )
        .await;

    assert_mock(query_mock).await;

    match result {
        Err(AgentError::ReplicaError(replica_error)) => {
            assert_eq!(replica_error.reject_code, RejectCode::DestinationInvalid);
            assert_eq!(replica_error.reject_message, "Rejected Message");
        }
        result => unreachable!("{:?}", result),
    }

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn call_error() -> Result<(), AgentError> {
    let (call_mock, url) = mock("POST", "/api/v2/canister/aaaaa-aa/call", 500, vec![], None).await;

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url)?)
        .build()?;

    let result = agent
        .update(&Principal::management_canister(), "greet")
        .with_arg([])
        .call()
        .await;

    assert_mock(call_mock).await;

    assert!(result.is_err());

    Ok(())
}

// #[cfg_attr(not(target_family = "wasm"), tokio::test)]
// #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
// async fn call_error_in_body() -> Result<(), AgentError> {
//     let (call_mock, url) = mock("POST", "/api/v2/canister/aaaaa-aa/call", 200, vec![], None).await;

//     let agent = Agent::builder()
//         .with_transport(ReqwestTransport::create(&url)?)
//         .build()?;

//     let result = agent
//         .update(&Principal::management_canister(), "greet")
//         .with_arg([])
//         .call()
//         .await;

//     assert_mock(call_mock).await;

//     let error = result.unwrap_err();
//     // assert_type_eq!(AgentError::ReplicaErrorV2, error.type)
//     // assert!(result.is_err_and(|error| error.to));

//     // Ok(())
// }

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn status() -> Result<(), AgentError> {
    let ic_api_version = "1.2.3".to_string();
    let mut map = BTreeMap::new();
    map.insert(
        serde_cbor::Value::Text("ic_api_version".to_owned()),
        serde_cbor::Value::Text(ic_api_version.clone()),
    );
    let response = serde_cbor::Value::Map(map);
    let (read_mock, url) = mock(
        "GET",
        "/api/v2/status",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url)?)
        .build()?;
    let result = agent.status().await;

    assert_mock(read_mock).await;
    assert!(matches!(result, Ok(Status { ic_api_version: v, .. }) if v == ic_api_version));

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn status_okay() -> Result<(), AgentError> {
    let mut map = BTreeMap::new();
    map.insert(
        serde_cbor::Value::Text("ic_api_version".to_owned()),
        serde_cbor::Value::Text("1.2.3".to_owned()),
    );
    let response = serde_cbor::Value::Map(map);
    let (read_mock, url) = mock(
        "GET",
        "/api/v2/status",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url)?)
        .build()?;
    let result = agent.status().await;

    assert_mock(read_mock).await;

    assert!(result.is_ok());

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
// test that the agent (re)tries to reach the server.
// We spawn an agent that waits 400ms between requests, and times out after 600ms. The agent is
// expected to hit the server at ~ 0ms and ~ 400 ms, and then shut down at 600ms, so we check that
// the server got two requests.
async fn status_error() -> Result<(), AgentError> {
    // This mock is never asserted as we don't know (nor do we need to know) how many times
    // it is called.
    let (_read_mock, url) = mock("GET", "/api/v2/status", 500, vec![], None).await;

    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url)?)
        .build()?;
    let result = agent.status().await;

    assert!(result.is_err());

    Ok(())
}

// these values for canister, paths, and mock_response are captured from a real request to mainnet
// the response amounts to "method not found"
// we don't really care about the response since we're just testing the cert verification
const REQ_WITH_DELEGATED_CERT_PATH: [&str; 2] = [
    "726571756573745F737461747573",
    "92F03ABDDC774EE97882320CF15F2029A868FFCFE3BE48FEF84FC97B5A13E04A",
];
const REQ_WITH_DELEGATED_CERT_CANISTER: &str = "ivg37-qiaaa-aaaab-aaaga-cai";
const REQ_WITH_DELEGATED_CERT_RESPONSE: [u8; 1074] = [
    217, 217, 247, 161, 107, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 89, 4, 31, 217,
    217, 247, 163, 100, 116, 114, 101, 101, 131, 1, 131, 1, 130, 4, 88, 32, 37, 15, 94, 38, 134,
    141, 156, 30, 167, 171, 41, 203, 233, 193, 91, 241, 196, 124, 13, 118, 5, 232, 3, 227, 158, 55,
    90, 127, 224, 156, 110, 187, 131, 1, 131, 2, 78, 114, 101, 113, 117, 101, 115, 116, 95, 115,
    116, 97, 116, 117, 115, 131, 1, 130, 4, 88, 32, 75, 38, 130, 39, 119, 78, 199, 127, 242, 179,
    126, 203, 18, 21, 115, 41, 213, 76, 243, 118, 105, 75, 221, 89, 222, 215, 128, 62, 253, 130,
    56, 111, 131, 2, 88, 32, 237, 173, 81, 14, 170, 160, 142, 210, 172, 212, 120, 19, 36, 230, 68,
    98, 105, 218, 103, 83, 236, 23, 118, 15, 32, 107, 190, 129, 196, 101, 255, 82, 131, 1, 131, 1,
    131, 2, 75, 114, 101, 106, 101, 99, 116, 95, 99, 111, 100, 101, 130, 3, 65, 3, 131, 2, 78, 114,
    101, 106, 101, 99, 116, 95, 109, 101, 115, 115, 97, 103, 101, 130, 3, 88, 68, 67, 97, 110, 105,
    115, 116, 101, 114, 32, 105, 118, 103, 51, 55, 45, 113, 105, 97, 97, 97, 45, 97, 97, 97, 97,
    98, 45, 97, 97, 97, 103, 97, 45, 99, 97, 105, 32, 104, 97, 115, 32, 110, 111, 32, 117, 112,
    100, 97, 116, 101, 32, 109, 101, 116, 104, 111, 100, 32, 39, 114, 101, 103, 105, 115, 116, 101,
    114, 39, 131, 2, 70, 115, 116, 97, 116, 117, 115, 130, 3, 72, 114, 101, 106, 101, 99, 116, 101,
    100, 130, 4, 88, 32, 151, 35, 47, 49, 246, 171, 124, 164, 254, 83, 235, 101, 104, 252, 62, 2,
    188, 34, 254, 148, 171, 49, 208, 16, 229, 251, 60, 100, 35, 1, 241, 96, 131, 1, 130, 4, 88, 32,
    58, 72, 209, 252, 33, 61, 73, 48, 113, 3, 16, 79, 125, 114, 194, 181, 147, 14, 219, 168, 120,
    123, 144, 99, 31, 52, 59, 58, 166, 138, 95, 10, 131, 2, 68, 116, 105, 109, 101, 130, 3, 73,
    226, 220, 147, 144, 145, 198, 150, 235, 22, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101,
    88, 48, 137, 162, 190, 33, 181, 250, 138, 201, 250, 177, 82, 126, 4, 19, 39, 206, 137, 157,
    125, 169, 113, 67, 106, 31, 33, 101, 57, 57, 71, 180, 217, 66, 54, 91, 254, 84, 136, 113, 14,
    97, 166, 25, 186, 72, 56, 138, 33, 177, 106, 100, 101, 108, 101, 103, 97, 116, 105, 111, 110,
    162, 105, 115, 117, 98, 110, 101, 116, 95, 105, 100, 88, 29, 215, 123, 42, 47, 113, 153, 185,
    168, 174, 201, 63, 230, 251, 88, 134, 97, 53, 140, 241, 34, 35, 233, 163, 175, 123, 78, 186,
    196, 2, 107, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 89, 2, 49, 217, 217, 247, 162,
    100, 116, 114, 101, 101, 131, 1, 130, 4, 88, 32, 174, 2, 63, 40, 195, 185, 217, 102, 200, 251,
    9, 249, 237, 117, 92, 130, 138, 173, 181, 21, 46, 0, 170, 247, 0, 177, 140, 156, 6, 114, 148,
    180, 131, 1, 131, 2, 70, 115, 117, 98, 110, 101, 116, 131, 1, 130, 4, 88, 32, 232, 59, 176, 37,
    246, 87, 76, 143, 49, 35, 61, 192, 254, 40, 159, 245, 70, 223, 161, 228, 155, 214, 17, 109,
    214, 232, 137, 109, 144, 164, 148, 110, 131, 1, 130, 4, 88, 32, 231, 130, 97, 144, 146, 214,
    157, 91, 235, 240, 146, 65, 56, 189, 65, 22, 176, 21, 107, 90, 149, 226, 92, 53, 142, 168, 207,
    126, 113, 97, 166, 97, 131, 1, 131, 1, 130, 4, 88, 32, 98, 81, 63, 169, 38, 201, 169, 239, 128,
    58, 194, 132, 214, 32, 243, 3, 24, 149, 136, 225, 211, 144, 67, 73, 171, 99, 182, 71, 8, 86,
    252, 72, 131, 1, 130, 4, 88, 32, 96, 233, 163, 68, 206, 210, 201, 196, 169, 106, 1, 151, 253,
    88, 95, 45, 37, 157, 189, 25, 62, 78, 173, 165, 98, 57, 202, 194, 96, 135, 249, 197, 131, 2,
    88, 29, 215, 123, 42, 47, 113, 153, 185, 168, 174, 201, 63, 230, 251, 88, 134, 97, 53, 140,
    241, 34, 35, 233, 163, 175, 123, 78, 186, 196, 2, 131, 1, 131, 2, 79, 99, 97, 110, 105, 115,
    116, 101, 114, 95, 114, 97, 110, 103, 101, 115, 130, 3, 88, 27, 217, 217, 247, 129, 130, 74, 0,
    0, 0, 0, 0, 32, 0, 0, 1, 1, 74, 0, 0, 0, 0, 0, 47, 255, 255, 1, 1, 131, 2, 74, 112, 117, 98,
    108, 105, 99, 95, 107, 101, 121, 130, 3, 88, 133, 48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1,
    130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 153,
    51, 225, 248, 158, 138, 60, 77, 127, 220, 204, 219, 213, 24, 8, 158, 43, 212, 216, 24, 10, 38,
    31, 24, 217, 194, 71, 165, 39, 104, 235, 206, 152, 220, 115, 40, 163, 152, 20, 168, 249, 17, 8,
    106, 29, 213, 12, 190, 1, 94, 42, 83, 183, 191, 120, 181, 82, 136, 137, 61, 170, 21, 195, 70,
    100, 14, 136, 49, 215, 42, 18, 189, 237, 217, 121, 210, 132, 112, 195, 72, 35, 184, 209, 195,
    244, 121, 93, 156, 57, 132, 162, 71, 19, 46, 148, 254, 130, 4, 88, 32, 153, 111, 23, 187, 146,
    107, 227, 49, 87, 69, 222, 167, 40, 32, 5, 167, 147, 181, 142, 118, 175, 235, 93, 67, 209, 162,
    140, 226, 157, 45, 21, 133, 131, 2, 68, 116, 105, 109, 101, 130, 3, 73, 149, 184, 170, 192,
    228, 237, 162, 234, 22, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101, 88, 48, 172, 233, 252,
    221, 155, 201, 119, 224, 93, 99, 40, 248, 137, 220, 78, 124, 153, 17, 76, 115, 122, 73, 70, 83,
    203, 39, 161, 245, 92, 6, 244, 85, 94, 15, 22, 9, 128, 175, 94, 173, 9, 138, 204, 25, 80, 16,
    178, 247,
];

// this is the same response as REQ_WITH_DELEGATED_CERT_RESPONSE, but with a manually pruned
// /subnet/<subnetid>/canister_ranges field
const PRUNED_SUBNET: [u8; 1064] = [
    161, 107, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 89, 4, 24, 163, 100, 116, 114,
    101, 101, 131, 1, 131, 1, 130, 4, 88, 32, 37, 15, 94, 38, 134, 141, 156, 30, 167, 171, 41, 203,
    233, 193, 91, 241, 196, 124, 13, 118, 5, 232, 3, 227, 158, 55, 90, 127, 224, 156, 110, 187,
    131, 1, 131, 2, 78, 114, 101, 113, 117, 101, 115, 116, 95, 115, 116, 97, 116, 117, 115, 131, 1,
    130, 4, 88, 32, 75, 38, 130, 39, 119, 78, 199, 127, 242, 179, 126, 203, 18, 21, 115, 41, 213,
    76, 243, 118, 105, 75, 221, 89, 222, 215, 128, 62, 253, 130, 56, 111, 131, 2, 88, 32, 237, 173,
    81, 14, 170, 160, 142, 210, 172, 212, 120, 19, 36, 230, 68, 98, 105, 218, 103, 83, 236, 23,
    118, 15, 32, 107, 190, 129, 196, 101, 255, 82, 131, 1, 131, 1, 131, 2, 75, 114, 101, 106, 101,
    99, 116, 95, 99, 111, 100, 101, 130, 3, 65, 3, 131, 2, 78, 114, 101, 106, 101, 99, 116, 95,
    109, 101, 115, 115, 97, 103, 101, 130, 3, 88, 68, 67, 97, 110, 105, 115, 116, 101, 114, 32,
    105, 118, 103, 51, 55, 45, 113, 105, 97, 97, 97, 45, 97, 97, 97, 97, 98, 45, 97, 97, 97, 103,
    97, 45, 99, 97, 105, 32, 104, 97, 115, 32, 110, 111, 32, 117, 112, 100, 97, 116, 101, 32, 109,
    101, 116, 104, 111, 100, 32, 39, 114, 101, 103, 105, 115, 116, 101, 114, 39, 131, 2, 70, 115,
    116, 97, 116, 117, 115, 130, 3, 72, 114, 101, 106, 101, 99, 116, 101, 100, 130, 4, 88, 32, 151,
    35, 47, 49, 246, 171, 124, 164, 254, 83, 235, 101, 104, 252, 62, 2, 188, 34, 254, 148, 171, 49,
    208, 16, 229, 251, 60, 100, 35, 1, 241, 96, 131, 1, 130, 4, 88, 32, 58, 72, 209, 252, 33, 61,
    73, 48, 113, 3, 16, 79, 125, 114, 194, 181, 147, 14, 219, 168, 120, 123, 144, 99, 31, 52, 59,
    58, 166, 138, 95, 10, 131, 2, 68, 116, 105, 109, 101, 130, 3, 73, 226, 220, 147, 144, 145, 198,
    150, 235, 22, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101, 88, 48, 137, 162, 190, 33, 181,
    250, 138, 201, 250, 177, 82, 126, 4, 19, 39, 206, 137, 157, 125, 169, 113, 67, 106, 31, 33,
    101, 57, 57, 71, 180, 217, 66, 54, 91, 254, 84, 136, 113, 14, 97, 166, 25, 186, 72, 56, 138,
    33, 177, 106, 100, 101, 108, 101, 103, 97, 116, 105, 111, 110, 162, 105, 115, 117, 98, 110,
    101, 116, 95, 105, 100, 88, 29, 215, 123, 42, 47, 113, 153, 185, 168, 174, 201, 63, 230, 251,
    88, 134, 97, 53, 140, 241, 34, 35, 233, 163, 175, 123, 78, 186, 196, 2, 107, 99, 101, 114, 116,
    105, 102, 105, 99, 97, 116, 101, 89, 2, 45, 163, 100, 116, 114, 101, 101, 131, 1, 130, 4, 88,
    32, 174, 2, 63, 40, 195, 185, 217, 102, 200, 251, 9, 249, 237, 117, 92, 130, 138, 173, 181, 21,
    46, 0, 170, 247, 0, 177, 140, 156, 6, 114, 148, 180, 131, 1, 131, 2, 70, 115, 117, 98, 110,
    101, 116, 131, 1, 130, 4, 88, 32, 232, 59, 176, 37, 246, 87, 76, 143, 49, 35, 61, 192, 254, 40,
    159, 245, 70, 223, 161, 228, 155, 214, 17, 109, 214, 232, 137, 109, 144, 164, 148, 110, 131, 1,
    130, 4, 88, 32, 231, 130, 97, 144, 146, 214, 157, 91, 235, 240, 146, 65, 56, 189, 65, 22, 176,
    21, 107, 90, 149, 226, 92, 53, 142, 168, 207, 126, 113, 97, 166, 97, 131, 1, 131, 1, 130, 4,
    88, 32, 98, 81, 63, 169, 38, 201, 169, 239, 128, 58, 194, 132, 214, 32, 243, 3, 24, 149, 136,
    225, 211, 144, 67, 73, 171, 99, 182, 71, 8, 86, 252, 72, 131, 1, 130, 4, 88, 32, 96, 233, 163,
    68, 206, 210, 201, 196, 169, 106, 1, 151, 253, 88, 95, 45, 37, 157, 189, 25, 62, 78, 173, 165,
    98, 57, 202, 194, 96, 135, 249, 197, 131, 2, 88, 29, 215, 123, 42, 47, 113, 153, 185, 168, 174,
    201, 63, 230, 251, 88, 134, 97, 53, 140, 241, 34, 35, 233, 163, 175, 123, 78, 186, 196, 2, 131,
    1, 130, 4, 88, 32, 32, 38, 201, 161, 171, 93, 204, 127, 80, 161, 230, 124, 235, 148, 89, 31, 6,
    180, 77, 141, 245, 169, 134, 51, 104, 168, 66, 91, 121, 228, 125, 38, 131, 2, 74, 112, 117, 98,
    108, 105, 99, 95, 107, 101, 121, 130, 3, 88, 133, 48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1,
    130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 153,
    51, 225, 248, 158, 138, 60, 77, 127, 220, 204, 219, 213, 24, 8, 158, 43, 212, 216, 24, 10, 38,
    31, 24, 217, 194, 71, 165, 39, 104, 235, 206, 152, 220, 115, 40, 163, 152, 20, 168, 249, 17, 8,
    106, 29, 213, 12, 190, 1, 94, 42, 83, 183, 191, 120, 181, 82, 136, 137, 61, 170, 21, 195, 70,
    100, 14, 136, 49, 215, 42, 18, 189, 237, 217, 121, 210, 132, 112, 195, 72, 35, 184, 209, 195,
    244, 121, 93, 156, 57, 132, 162, 71, 19, 46, 148, 254, 130, 4, 88, 32, 153, 111, 23, 187, 146,
    107, 227, 49, 87, 69, 222, 167, 40, 32, 5, 167, 147, 181, 142, 118, 175, 235, 93, 67, 209, 162,
    140, 226, 157, 45, 21, 133, 131, 2, 68, 116, 105, 109, 101, 130, 3, 73, 149, 184, 170, 192,
    228, 237, 162, 234, 22, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101, 88, 48, 172, 233, 252,
    221, 155, 201, 119, 224, 93, 99, 40, 248, 137, 220, 78, 124, 153, 17, 76, 115, 122, 73, 70, 83,
    203, 39, 161, 245, 92, 6, 244, 85, 94, 15, 22, 9, 128, 175, 94, 173, 9, 138, 204, 25, 80, 16,
    178, 247, 106, 100, 101, 108, 101, 103, 97, 116, 105, 111, 110, 246,
];

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
// asserts that a delegated certificate with correct /subnet/<subnetid>/canister_ranges
// passes the certificate verification
async fn check_subnet_range_with_valid_range() {
    let (_read_mock, url) = mock(
        "POST",
        "/api/v2/canister/ivg37-qiaaa-aaaab-aaaga-cai/read_state",
        200,
        REQ_WITH_DELEGATED_CERT_RESPONSE.into(),
        Some("application/cbor"),
    )
    .await;
    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url).unwrap())
        .build()
        .unwrap();
    let _result = agent
        .read_state_raw(
            vec![REQ_WITH_DELEGATED_CERT_PATH
                .iter()
                .map(Label::from)
                .collect()],
            Principal::from_text(REQ_WITH_DELEGATED_CERT_CANISTER).unwrap(),
        )
        .await
        .expect("read state failed");
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
// asserts that a delegated certificate with /subnet/<subnetid>/canister_ranges that don't include
// the canister gets rejected by the cert verification because the subnet is not authorized to
// respond to requests for this canister. We do this by using a correct response but serving it
// for the wrong canister, which a malicious node might do.
async fn check_subnet_range_with_unauthorized_range() {
    let wrong_canister = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
    let (_read_mock, url) = mock(
        "POST",
        "/api/v2/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/read_state",
        200,
        REQ_WITH_DELEGATED_CERT_RESPONSE.into(),
        Some("application/cbor"),
    )
    .await;
    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url).unwrap())
        .build()
        .unwrap();
    let result = agent
        .read_state_raw(
            vec![REQ_WITH_DELEGATED_CERT_PATH
                .iter()
                .map(Label::from)
                .collect()],
            wrong_canister,
        )
        .await;
    assert_eq!(result, Err(AgentError::CertificateNotAuthorized()));
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
// asserts that a delegated certificate with pruned/removed /subnet/<subnetid>/canister_ranges
// gets rejected by the cert verification. We do this by using a correct response that has
// the leaf manually pruned
async fn check_subnet_range_with_pruned_range() {
    let canister = Principal::from_text("ivg37-qiaaa-aaaab-aaaga-cai").unwrap();
    let (_read_mock, url) = mock(
        "POST",
        "/api/v2/canister/ivg37-qiaaa-aaaab-aaaga-cai/read_state",
        200,
        PRUNED_SUBNET.into(),
        Some("application/cbor"),
    )
    .await;
    let agent = Agent::builder()
        .with_transport(ReqwestTransport::create(&url).unwrap())
        .build()
        .unwrap();
    let result = agent
        .read_state_raw(
            vec![REQ_WITH_DELEGATED_CERT_PATH
                .iter()
                .map(Label::from)
                .collect()],
            canister,
        )
        .await;
    assert!(result.is_err());
}

#[cfg(not(target_family = "wasm"))]
mod mock {

    use mockito::{Mock, Server, ServerGuard};

    pub async fn mock(
        method: &str,
        path: &str,
        status_code: u16,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> ((ServerGuard, Mock), String) {
        let mut server = Server::new_async().await;
        let mut mock = server
            .mock(method, path)
            .with_status(status_code as _)
            .with_body(body);
        if let Some(content_type) = content_type {
            mock = mock.with_header("Content-Type", content_type);
        }
        let mock = mock.create_async().await;
        let url = server.url();
        ((server, mock), url)
    }

    pub async fn assert_mock((_, mock): (ServerGuard, Mock)) {
        mock.assert_async().await;
    }
}

#[cfg(target_family = "wasm")]
mod mock {
    use js_sys::*;
    use reqwest::Client;
    use serde::Serialize;
    use std::collections::HashMap;
    use wasm_bindgen::{prelude::*, JsCast};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::*;

    #[wasm_bindgen(module = "/http_mock_service_worker.js")]
    extern "C" {}

    #[derive(Debug, Serialize)]
    struct MockConfig {
        pub kind: String,
        pub method: String,
        pub path: String,
        pub nonce: String,
        pub status_code: u16,
        pub headers: Option<HashMap<String, String>>,
        pub body: Vec<u8>,
    }

    pub async fn mock(
        method: &str,
        path: &str,
        status_code: u16,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> (String, String) {
        let swc = window().unwrap().navigator().service_worker();
        let registration: ServiceWorkerRegistration =
            JsFuture::from(swc.register("/http_mock_service_worker.js"))
                .await
                .unwrap()
                .unchecked_into();
        JsFuture::from(swc.ready().unwrap()).await.unwrap();
        let sw = registration.active().unwrap();
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let nonce = hex::encode(nonce);
        let config = MockConfig {
            kind: "config".into(),
            nonce: nonce.clone(),
            method: method.into(),
            path: path.into(),
            status_code,
            body,
            headers: content_type.map(|c| HashMap::from([("Content-Type".into(), c.into())])),
        };
        if sw.state() == ServiceWorkerState::Activating {
            JsFuture::from(Promise::new(&mut |rs, _| sw.set_onstatechange(Some(&rs))))
                .await
                .unwrap();
        }
        Client::new()
            .post("http://mock_configure")
            .json(&config)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        (nonce.clone(), format!("http://mock_{}/", nonce))
    }

    pub async fn assert_mock(nonce: String) {
        let hits = Client::new()
            .get(&format!("http://mock_assert/{}", nonce))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(hits.parse::<i32>().unwrap() >= 1);
    }
}
