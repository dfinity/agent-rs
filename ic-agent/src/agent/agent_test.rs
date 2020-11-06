use crate::agent::replica_api::{CallReply, QueryResponse, ReadStateResponse, StateTreePath};
use crate::agent::response::{Replied, RequestStatusResponse};
use crate::agent::{AgentConfig, Status};
use crate::export::Principal;
use crate::{Agent, AgentError};
use delay::Delay;
use mockito::mock;
use std::collections::BTreeMap;
use std::time::Duration;

#[test]
fn query() -> Result<(), AgentError> {
    let blob = Vec::from("Hello World");
    let response = QueryResponse::Replied {
        reply: CallReply { arg: blob.clone() },
    };

    let read_mock = mock("POST", "/api/v1/read")
        .with_status(200)
        .with_header("content-type", "application/cbor")
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async {
        agent
            .query_raw(&Principal::management_canister(), "main", &[], None)
            .await
    });

    read_mock.assert();

    assert_eq!(result?, blob);

    Ok(())
}

#[test]
fn query_error() -> Result<(), AgentError> {
    let read_mock = mock("POST", "/api/v1/read").with_status(500).create();
    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

    let result = runtime.block_on(async {
        agent
            .query_raw(&Principal::management_canister(), "greet", &[], None)
            .await
    });

    read_mock.assert();

    assert!(result.is_err());

    Ok(())
}

#[test]
fn query_rejected() -> Result<(), AgentError> {
    let response: QueryResponse = QueryResponse::Rejected {
        reject_code: 1234,
        reject_message: "Rejected Message".to_string(),
    };

    let read_mock = mock("POST", "/api/v1/read")
        .with_status(200)
        .with_header("content-type", "application/cbor")
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

    let result = runtime.block_on(async {
        agent
            .query_raw(&Principal::management_canister(), "greet", &[], None)
            .await
    });

    read_mock.assert();

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
#[ignore]
fn call() -> Result<(), AgentError> {
    let read_state_response = ReadStateResponse {
        certificate: vec![1, 2, 3],
    };
    let blob = serde_cbor::to_vec(&read_state_response)?;
    let response = QueryResponse::Replied {
        reply: CallReply { arg: blob.clone() },
    };

    let submit_mock = mock("POST", "/api/v1/submit").with_status(200).create();
    let status_mock = mock("POST", "/api/v1/read")
        .with_status(200)
        .with_header("content-type", "application/cbor")
        .with_body(serde_cbor::to_vec(&read_state_response)?)
        .create();

    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;

    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async {
        let request_id = agent
            .update(&Principal::management_canister(), "greet")
            .with_arg(&[])
            .call()
            .await?;
        let paths: Vec<StateTreePath> = vec![vec![
            serde_bytes::ByteBuf::from("request_status".as_bytes()),
            serde_bytes::ByteBuf::from(request_id.to_vec()),
        ]];

        agent.read_state_raw(paths, None).await
    });

    submit_mock.assert();
    status_mock.assert();

    assert_eq!(result?, read_state_response);

    Ok(())
}

#[test]
fn call_error() -> Result<(), AgentError> {
    let submit_mock = mock("POST", "/api/v1/submit").with_status(500).create();

    let agent = Agent::builder().with_url(&mockito::server_url()).build()?;

    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async {
        agent
            .update(&Principal::management_canister(), "greet")
            .with_arg(&[])
            .call()
            .await
    });

    submit_mock.assert();

    assert!(result.is_err());

    Ok(())
}

#[test]
#[ignore]
fn call_rejected() -> Result<(), AgentError> {
    let response: QueryResponse = QueryResponse::Rejected {
        reject_code: 1234,
        reject_message: "Rejected Message".to_string(),
    };

    let submit_mock = mock("POST", "/api/v1/submit").with_status(200).create();
    let status_mock = mock("POST", "/api/v1/read")
        .with_status(200)
        .with_header("content-type", "application/cbor")
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::new(AgentConfig {
        url: mockito::server_url(),
        ..Default::default()
    })?;

    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async {
        agent
            .update(&Principal::management_canister(), "greet")
            .call_and_wait(Delay::timeout(Duration::from_millis(100)))
            .await
    });

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

    submit_mock.assert();
    status_mock.assert();

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
    let read_mock = mock("GET", "/api/v1/status")
        .with_status(200)
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::new(AgentConfig {
        url: mockito::server_url(),
        ..Default::default()
    })?;
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
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
    let read_mock = mock("GET", "/api/v1/status")
        .with_status(200)
        .with_body(serde_cbor::to_vec(&response)?)
        .create();

    let agent = Agent::new(AgentConfig {
        url: mockito::server_url(),
        ..Default::default()
    })?;
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
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
    let _read_mock = mock("GET", "/api/v1/status").with_status(500).create();

    let agent = Agent::new(AgentConfig {
        url: mockito::server_url(),
        ..Default::default()
    })?;
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(async { agent.status().await });

    assert!(result.is_err());

    Ok(())
}
