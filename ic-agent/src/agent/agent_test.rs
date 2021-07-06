// Disable these tests without the reqwest feature.
#![cfg(feature = "reqwest")]

use crate::{
    agent::{
        replica_api::{CallReply, QueryResponse},
        Status,
    },
    export::Principal,
    Agent, AgentError,
};
use mockito::mock;
use std::collections::BTreeMap;

#[test]
fn query() -> Result<(), AgentError> {
    let blob = Vec::from("Hello World");
    let response = QueryResponse::Replied {
        reply: CallReply { arg: blob.clone() },
    };

    let query_mock = mock("POST", "/api/v2/canister/aaaaa-aa/query")
        .with_status(200)
        .with_header("content-type", "application/cbor")
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;
    let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async {
        agent
            .query_raw(
                &Principal::management_canister(),
                Principal::management_canister(),
                "main",
                &[],
                None,
            )
            .await
    });

    query_mock.assert();

    assert_eq!(result?, blob);

    Ok(())
}

#[test]
fn query_error() -> Result<(), AgentError> {
    let query_mock = mock("POST", "/api/v2/canister/aaaaa-aa/query")
        .with_status(500)
        .create();
    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;
    let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

    let result = runtime.block_on(async {
        agent
            .query_raw(
                &Principal::management_canister(),
                Principal::management_canister(),
                "greet",
                &[],
                None,
            )
            .await
    });

    query_mock.assert();

    assert!(result.is_err());

    Ok(())
}

#[test]
fn query_rejected() -> Result<(), AgentError> {
    let response: QueryResponse = QueryResponse::Rejected {
        reject_code: 1234,
        reject_message: "Rejected Message".to_string(),
    };

    let query_mock = mock("POST", "/api/v2/canister/aaaaa-aa/query")
        .with_status(200)
        .with_header("content-type", "application/cbor")
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;
    let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

    let result = runtime.block_on(async {
        agent
            .query_raw(
                &Principal::management_canister(),
                Principal::management_canister(),
                "greet",
                &[],
                None,
            )
            .await
    });

    query_mock.assert();

    match result {
        Err(AgentError::ReplicaError {
            reject_code: code,
            reject_message: msg,
        }) => {
            assert_eq!(code, 1234);
            assert_eq!(msg, "Rejected Message");
        }
        result => unreachable!("{:?}", result),
    }

    Ok(())
}

#[test]
fn call_error() -> Result<(), AgentError> {
    let call_mock = mock("POST", "/api/v2/canister/aaaaa-aa/call")
        .with_status(500)
        .create();

    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;

    let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async {
        agent
            .update(&Principal::management_canister(), "greet")
            .with_arg(&[])
            .call()
            .await
    });

    call_mock.assert();

    assert!(result.is_err());

    Ok(())
}

#[test]
fn status() -> Result<(), AgentError> {
    let ic_api_version = "1.2.3".to_string();
    let mut map = BTreeMap::new();
    map.insert(
        serde_cbor::Value::Text("ic_api_version".to_owned()),
        serde_cbor::Value::Text(ic_api_version.clone()),
    );
    let response = serde_cbor::Value::Map(map);
    let read_mock = mock("GET", "/api/v2/status")
        .with_status(200)
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::builder().with_url(mockito::server_url()).build()?;
    let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async { agent.status().await });

    read_mock.assert();
    assert!(matches!(result, Ok(Status { ic_api_version: v, .. }) if v == ic_api_version));

    Ok(())
}

#[test]
fn status_okay() -> Result<(), AgentError> {
    let mut map = BTreeMap::new();
    map.insert(
        serde_cbor::Value::Text("ic_api_version".to_owned()),
        serde_cbor::Value::Text("1.2.3".to_owned()),
    );
    let response = serde_cbor::Value::Map(map);
    let read_mock = mock("GET", "/api/v2/status")
        .with_status(200)
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::builder().with_url(mockito::server_url()).build()?;
    let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(agent.status());

    read_mock.assert();

    assert!(result.is_ok());

    Ok(())
}

#[test]
// test that the agent (re)tries to reach the server.
// We spawn an agent that waits 400ms between requests, and times out after 600ms. The agent is
// expected to hit the server at ~ 0ms and ~ 400 ms, and then shut down at 600ms, so we check that
// the server got two requests.
fn status_error() -> Result<(), AgentError> {
    // This mock is never asserted as we don't know (nor do we need to know) how many times
    // it is called.
    let _read_mock = mock("GET", "/api/v2/status").with_status(500).create();

    let agent = Agent::builder().with_url(mockito::server_url()).build()?;
    let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async { agent.status().await });

    assert!(result.is_err());

    Ok(())
}
