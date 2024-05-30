// Disable these tests without the reqwest feature.
#![cfg(feature = "reqwest")]

use self::mock::{
    assert_mock, assert_single_mock, assert_single_mock_count, mock, mock_additional,
};
use crate::{
    agent::{http_transport::ReqwestTransport, Status},
    export::Principal,
    Agent, AgentError, Certificate,
};
use candid::{Encode, Nat};
use futures_util::FutureExt;
use ic_certification::{Delegation, Label};
use ic_transport_types::{NodeSignature, QueryResponse, RejectCode, RejectResponse, ReplyResponse};
use reqwest::Client;
use std::{collections::BTreeMap, time::Duration};
use std::{collections::VecDeque, sync::Arc};
#[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::agent::http_transport::route_provider::{RoundRobinRouteProvider, RouteProvider};
#[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn make_agent(url: &str) -> Agent {
    Agent::builder()
        .with_transport(ReqwestTransport::create(url).unwrap())
        .with_verify_query_signatures(false)
        .build()
        .unwrap()
}

fn make_agent_with_route_provider(
    route_provider: Arc<dyn RouteProvider>,
    tcp_retries: usize,
) -> Agent {
    let client = Client::builder()
        .use_rustls_tls()
        .build()
        .expect("Could not create HTTP client.");
    Agent::builder()
        .with_transport(
            ReqwestTransport::create_with_client_route(route_provider, client)
                .unwrap()
                .with_max_tcp_errors_retries(tcp_retries),
        )
        .with_verify_query_signatures(false)
        .build()
        .unwrap()
}

fn make_agent_with_hyper_transport_route_provider(
    route_provider: Arc<dyn RouteProvider>,
    tcp_retries: usize,
) -> Agent {
    use super::http_transport::HyperTransport;
    use http_body_util::Full;
    use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
    use hyper_util::{
        client::legacy::{connect::HttpConnector, Client as LegacyClient},
        rt::TokioExecutor,
    };

    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: LegacyClient<HttpsConnector<HttpConnector>, Full<VecDeque<u8>>> =
        LegacyClient::builder(TokioExecutor::new()).build(connector);
    let transport = HyperTransport::create_with_service_route(route_provider, client)
        .unwrap()
        .with_max_tcp_errors_retries(tcp_retries);
    Agent::builder()
        .with_transport(transport)
        .with_verify_query_signatures(false)
        .build()
        .unwrap()
}

fn make_untimed_agent(url: &str) -> Agent {
    Agent::builder()
        .with_transport(ReqwestTransport::create(url).unwrap())
        .with_verify_query_signatures(false)
        .with_ingress_expiry(Some(Duration::from_secs(u32::MAX as _)))
        .build()
        .unwrap()
}

fn make_certifying_agent(url: &str) -> Agent {
    Agent::builder()
        .with_transport(ReqwestTransport::create(url).unwrap())
        .with_ingress_expiry(Some(Duration::from_secs(u32::MAX as _)))
        .build()
        .unwrap()
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn query() -> Result<(), AgentError> {
    let blob = Vec::from("Hello World");
    let response = QueryResponse::Replied {
        reply: ReplyResponse { arg: blob.clone() },
        signatures: vec![],
    };

    let (query_mock, url) = mock(
        "POST",
        "/api/v2/canister/aaaaa-aa/query",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = make_agent(&url);
    let result = agent
        .query_raw(
            Principal::management_canister(),
            Principal::management_canister(),
            "main".to_string(),
            vec![],
            None,
            false,
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
    let agent = make_agent(&url);

    let result = agent
        .query_raw(
            Principal::management_canister(),
            Principal::management_canister(),
            "greet".to_string(),
            vec![],
            None,
            false,
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
    let response: QueryResponse = QueryResponse::Rejected {
        reject: RejectResponse {
            reject_code: RejectCode::DestinationInvalid,
            reject_message: "Rejected Message".to_string(),
            error_code: Some("Error code".to_string()),
        },
        signatures: vec![],
    };

    let (query_mock, url) = mock(
        "POST",
        "/api/v2/canister/aaaaa-aa/query",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = make_agent(&url);

    let result = agent
        .query_raw(
            Principal::management_canister(),
            Principal::management_canister(),
            "greet".to_string(),
            vec![],
            None,
            false,
            None,
        )
        .await;

    assert_mock(query_mock).await;

    match result {
        Err(AgentError::UncertifiedReject(replica_error)) => {
            assert_eq!(replica_error.reject_code, RejectCode::DestinationInvalid);
            assert_eq!(replica_error.reject_message, "Rejected Message");
            assert_eq!(replica_error.error_code, Some("Error code".to_string()));
        }
        result => unreachable!("{:?}", result),
    }

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn call_error() -> Result<(), AgentError> {
    let (call_mock, url) = mock("POST", "/api/v2/canister/aaaaa-aa/call", 500, vec![], None).await;

    let agent = make_agent(&url);

    let result = agent
        .update(&Principal::management_canister(), "greet")
        .with_arg([])
        .call()
        .await;

    assert_mock(call_mock).await;

    assert!(result.is_err());

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn call_rejected() -> Result<(), AgentError> {
    let reject_body = RejectResponse {
        reject_code: RejectCode::SysTransient,
        reject_message: "Test reject message".to_string(),
        error_code: Some("Test error code".to_string()),
    };

    let body = serde_cbor::to_vec(&reject_body).unwrap();

    let (call_mock, url) = mock(
        "POST",
        "/api/v2/canister/aaaaa-aa/call",
        200,
        body,
        Some("application/cbor"),
    )
    .await;

    let agent = make_agent(&url);

    let result = agent
        .update(&Principal::management_canister(), "greet")
        .with_arg([])
        .call()
        .await;

    assert_mock(call_mock).await;

    let expected_response = Err(AgentError::UncertifiedReject(reject_body));
    assert_eq!(expected_response, result);

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn call_rejected_without_error_code() -> Result<(), AgentError> {
    let reject_body = RejectResponse {
        reject_code: RejectCode::SysTransient,
        reject_message: "Test reject message".to_string(),
        error_code: None,
    };

    let body = serde_cbor::to_vec(&reject_body).unwrap();

    let (call_mock, url) = mock(
        "POST",
        "/api/v2/canister/aaaaa-aa/call",
        200,
        body,
        Some("application/cbor"),
    )
    .await;

    let agent = make_agent(&url);

    let result = agent
        .update(&Principal::management_canister(), "greet")
        .with_arg([])
        .call()
        .await;

    assert_mock(call_mock).await;

    let expected_response = Err(AgentError::UncertifiedReject(reject_body));
    assert_eq!(expected_response, result);

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn status() -> Result<(), AgentError> {
    let map = BTreeMap::new();
    let response = serde_cbor::Value::Map(map);
    let (read_mock, url) = mock(
        "GET",
        "/api/v2/status",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = make_agent(&url);
    let result = agent.status().await;

    assert_mock(read_mock).await;
    assert!(matches!(result, Ok(Status { .. })));

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn status_okay() -> Result<(), AgentError> {
    let map = BTreeMap::new();
    let response = serde_cbor::Value::Map(map);
    let (read_mock, url) = mock(
        "GET",
        "/api/v2/status",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;

    let agent = make_agent(&url);
    let result = agent.status().await;

    assert_mock(read_mock).await;

    assert!(result.is_ok());

    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
async fn reqwest_client_status_okay_when_request_retried() -> Result<(), AgentError> {
    let map = BTreeMap::new();
    let response = serde_cbor::Value::Map(map);
    let (read_mock, url) = mock(
        "GET",
        "/api/v2/status",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;
    // Without retry request should fail.
    let non_working_url = "http://127.0.0.1:4444";
    let tcp_retries = 0;
    let route_provider = RoundRobinRouteProvider::new(vec![non_working_url, &url]).unwrap();
    let agent = make_agent_with_route_provider(Arc::new(route_provider), tcp_retries);
    let result = agent.status().await;
    assert!(result.is_err());

    // With retry request should succeed.
    let tcp_retries = 1;
    let route_provider = RoundRobinRouteProvider::new(vec![non_working_url, &url]).unwrap();
    let agent = make_agent_with_route_provider(Arc::new(route_provider), tcp_retries);
    let result = agent.status().await;

    assert_mock(read_mock).await;

    assert!(result.is_ok());
    Ok(())
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
async fn hyper_client_status_okay_when_request_retried() -> Result<(), AgentError> {
    let map = BTreeMap::new();
    let response = serde_cbor::Value::Map(map);
    let (read_mock, url) = mock(
        "GET",
        "/api/v2/status",
        200,
        serde_cbor::to_vec(&response)?,
        Some("application/cbor"),
    )
    .await;
    // Without retry request should fail.
    let non_working_url = "http://127.0.0.1:4444";
    let tcp_retries = 0;
    let route_provider = RoundRobinRouteProvider::new(vec![non_working_url, &url]).unwrap();
    let agent =
        make_agent_with_hyper_transport_route_provider(Arc::new(route_provider), tcp_retries);
    let result = agent.status().await;
    assert!(result.is_err());

    // With retry request should succeed.
    let tcp_retries = 1;
    let route_provider = RoundRobinRouteProvider::new(vec![non_working_url, &url]).unwrap();
    let agent =
        make_agent_with_hyper_transport_route_provider(Arc::new(route_provider), tcp_retries);
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

    let agent = make_agent(&url);
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
const REQ_WITH_DELEGATED_CERT_RESPONSE: &[u8] =
    include_bytes!("agent_test/req_with_delegated_cert_response.bin");

// this is the same response as REQ_WITH_DELEGATED_CERT_RESPONSE, but with a manually pruned
// /subnet/<subnetid>/canister_ranges field
const PRUNED_SUBNET: &[u8] = include_bytes!("agent_test/pruned_subnet.bin");

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
    let agent = make_untimed_agent(&url);
    let _result = agent
        .read_state_raw(
            vec![REQ_WITH_DELEGATED_CERT_PATH
                .into_iter()
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
    let agent = make_untimed_agent(&url);
    let result = agent
        .read_state_raw(
            vec![REQ_WITH_DELEGATED_CERT_PATH
                .into_iter()
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
    let agent = make_untimed_agent(&url);
    let result = agent
        .read_state_raw(
            vec![REQ_WITH_DELEGATED_CERT_PATH
                .into_iter()
                .map(Label::from)
                .collect()],
            canister,
        )
        .await;
    assert!(result.is_err());
}

const WRONG_SUBNET_CERT: &[u8] = include_bytes!("agent_test/wrong_subnet.bin");

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn wrong_subnet_query_certificate() {
    let canister = Principal::from_text("224od-giaaa-aaaao-ae5vq-cai").unwrap();
    let (mut read_mock, url) = mock(
        "POST",
        "/api/v2/canister/224od-giaaa-aaaao-ae5vq-cai/read_state",
        200,
        WRONG_SUBNET_CERT.into(),
        Some("application/cbor"),
    )
    .await;
    let blob = Encode!(&Nat::from(12u8)).unwrap();
    let response = QueryResponse::Replied {
        reply: ReplyResponse { arg: blob.clone() },
        signatures: vec![NodeSignature {
            timestamp: 1697831349698624964,
            signature: hex::decode("4bb6ba316623395d56d8e2834ece39d2c81d47e76a9fd122e1457963be6a83a5589e2c98c7b4d8b3c6c7b11c74b8ce9dcb345b5d1bd91706a643f33c7b509b0b").unwrap(),
            identity: "oo4np-rrvnz-5vram-kglex-enhkp-uew6q-vdf6z-whj4x-v44jd-tebaw-nqe".parse().unwrap()
        }],
    };
    mock_additional(
        &mut read_mock,
        "POST",
        "/api/v2/canister/224od-giaaa-aaaao-ae5vq-cai/query",
        200,
        serde_cbor::to_vec(&response).unwrap(),
        Some("application/cbor"),
    )
    .await;
    let agent = make_certifying_agent(&url);
    let result = agent.query(&canister, "getVersion").call().await;
    assert!(matches!(
        result.unwrap_err(),
        AgentError::CertificateNotAuthorized()
    ));
    assert_single_mock(
        "POST",
        "/api/v2/canister/224od-giaaa-aaaao-ae5vq-cai/read_state",
        &read_mock,
    )
    .await;
}

const GOOD_SUBNET_KEYS: &[u8] = include_bytes!("agent_test/subnet_keys.bin");

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn no_cert() {
    let canister = Principal::from_text("224od-giaaa-aaaao-ae5vq-cai").unwrap();
    let (mut read_mock, url) = mock(
        "POST",
        "/api/v2/canister/224od-giaaa-aaaao-ae5vq-cai/read_state",
        200,
        GOOD_SUBNET_KEYS.into(),
        Some("application/cbor"),
    )
    .await;
    let blob = Encode!(&Nat::from(12u8)).unwrap();
    let response = QueryResponse::Replied {
        reply: ReplyResponse { arg: blob.clone() },
        signatures: vec![],
    };
    mock_additional(
        &mut read_mock,
        "POST",
        "/api/v2/canister/224od-giaaa-aaaao-ae5vq-cai/query",
        200,
        serde_cbor::to_vec(&response).unwrap(),
        Some("application/cbor"),
    )
    .await;
    let agent = make_certifying_agent(&url);
    let result = agent.query(&canister, "getVersion").call().await;
    assert!(matches!(result.unwrap_err(), AgentError::MissingSignature));
    assert_mock(read_mock).await;
}

const RESP_WITH_SUBNET_KEY: &[u8] = include_bytes!("agent_test/with_subnet_key.bin");

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn too_many_delegations() {
    // Use the certificate as its own delegation, and repeat the process the specified number of times
    fn self_delegate_cert(subnet_id: Vec<u8>, cert: &Certificate, depth: u32) -> Certificate {
        let mut current = cert.clone();
        for _ in 0..depth {
            current = Certificate {
                tree: current.tree.clone(),
                signature: current.signature.clone(),
                delegation: Some(Delegation {
                    subnet_id: subnet_id.clone(),
                    certificate: serde_cbor::to_vec(&current).unwrap(),
                }),
            }
        }
        current
    }

    let canister_id_str = "rdmx6-jaaaa-aaaaa-aaadq-cai";
    let canister_id = Principal::from_text(canister_id_str).unwrap();
    let subnet_id = Vec::from(
        Principal::from_text("uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe")
            .unwrap()
            .as_slice(),
    );

    let (_read_mock, url) = mock(
        "POST",
        format!("/api/v2/canister/{}/read_state", canister_id_str).as_str(),
        200,
        RESP_WITH_SUBNET_KEY.into(),
        Some("application/cbor"),
    )
    .await;
    let path_label = Label::from_bytes("subnet".as_bytes());
    let agent = make_untimed_agent(&url);
    let cert = agent
        .read_state_raw(vec![vec![path_label]], canister_id)
        .await
        .expect("read state failed");
    let new_cert = self_delegate_cert(subnet_id, &cert, 1);
    assert!(matches!(
        agent.verify(&new_cert, canister_id).unwrap_err(),
        AgentError::CertificateHasTooManyDelegations
    ));
}

#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn retry_ratelimit() {
    let (mut mock, url) = mock(
        "POST",
        "/api/v2/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/query",
        429,
        vec![],
        Some("text/plain"),
    )
    .await;
    let agent = make_agent(&url);
    futures_util::select! {
        _ = agent.query(&"ryjl3-tyaaa-aaaaa-aaaba-cai".parse().unwrap(), "greet").call().fuse() => panic!("did not retry 429"),
        _ = crate::util::sleep(Duration::from_millis(500)).fuse() => {},
    };
    assert_single_mock_count(
        "POST",
        "/api/v2/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/query",
        2,
        &mut mock,
    )
    .await;
}

#[cfg(not(target_family = "wasm"))]
mod mock {

    use std::collections::HashMap;

    use mockito::{Mock, Server, ServerGuard};

    pub async fn mock(
        method: &str,
        path: &str,
        status_code: u16,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> ((ServerGuard, HashMap<String, Mock>), String) {
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
        (
            (server, HashMap::from([(format!("{method} {path}"), mock)])),
            url,
        )
    }

    pub async fn mock_additional(
        orig: &mut (ServerGuard, HashMap<String, Mock>),
        method: &str,
        path: &str,
        status_code: u16,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) {
        let mut mock = orig
            .0
            .mock(method, path)
            .with_status(status_code as _)
            .with_body(body);
        if let Some(content_type) = content_type {
            mock = mock.with_header("Content-Type", content_type);
        }
        orig.1
            .insert(format!("{method} {path}"), mock.create_async().await);
    }

    pub async fn assert_mock((_, mocks): (ServerGuard, HashMap<String, Mock>)) {
        for mock in mocks.values() {
            mock.assert_async().await;
        }
    }

    pub async fn assert_single_mock(
        method: &str,
        path: &str,
        (_, mocks): &(ServerGuard, HashMap<String, Mock>),
    ) {
        mocks[&format!("{method} {path}")].assert_async().await;
    }

    pub async fn assert_single_mock_count(
        method: &str,
        path: &str,
        n: usize,
        (_, mocks): &mut (ServerGuard, HashMap<String, Mock>),
    ) {
        let k = format!("{method} {path}");
        let mut mock = mocks.remove(&k).unwrap();
        mock = mock.expect_at_least(n);
        mock.assert_async().await;
        mocks.insert(k, mock);
    }
}

#[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
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
            .post(&format!("http://mock_configure/{nonce}"))
            .json(&config)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        (nonce.clone(), format!("http://mock_{}/", nonce))
    }

    pub async fn mock_additional(
        orig: &mut String,
        method: &str,
        path: &str,
        status_code: u16,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) {
        let config = MockConfig {
            kind: "config".into(),
            method: method.into(),
            path: path.into(),
            status_code,
            body,
            headers: content_type.map(|c| HashMap::from([("Content-Type".into(), c.into())])),
        };
        Client::new()
            .post(&format!("http://mock_configure/{orig}"))
            .json(&config)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }

    async fn get_hits(nonce: &str) -> HashMap<String, i64> {
        Client::new()
            .get(&format!("http://mock_assert/{}", nonce))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    pub async fn assert_mock(nonce: String) {
        let hits = get_hits(&nonce).await;
        assert!(hits.values().all(|x| *x > 0));
    }

    pub async fn assert_single_mock(method: &str, path: &str, nonce: &String) {
        let hits = get_hits(nonce).await;
        assert!(hits[&format!("{method} {path}")] > 0);
    }

    pub async fn assert_single_mock_count(method: &str, path: &str, n: usize, nonce: &mut String) {
        let hits = get_hits(&*nonce).await;
        assert!(hits[&format!("{method} {path}")] >= n as i64);
    }
}
