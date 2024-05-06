//! A [`Transport`] that connects using a [`reqwest`] client.
#![cfg(feature = "reqwest")]

use ic_transport_types::TransportCallResponse;
pub use reqwest;
use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use reqwest::{
    header::{HeaderMap, CONTENT_TYPE},
    Body, Client, Method, Request, StatusCode,
};

use crate::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::route_provider::{RoundRobinRouteProvider, RouteProvider},
        AgentFuture, Transport,
    },
    export::Principal,
    AgentError,
};

/// A [`Transport`] using [`reqwest`] to make HTTP calls to the Internet Computer.
#[derive(Debug)]
pub struct ReqwestTransport {
    route_provider: Arc<dyn RouteProvider>,
    client: Client,
    max_response_body_size: Option<usize>,
}

#[doc(hidden)]
#[deprecated(since = "0.30.0", note = "use ReqwestTransport")]
pub use ReqwestTransport as ReqwestHttpReplicaV2Transport;

use super::route_provider::Endpoint; // delete after 0.31

impl ReqwestTransport {
    /// Creates a replica transport from a HTTP URL.
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        #[cfg(not(target_family = "wasm"))]
        {
            Self::create_with_client(
                url,
                Client::builder()
                    .use_rustls_tls()
                    .build()
                    .expect("Could not create HTTP client."),
            )
        }
        #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
        {
            Self::create_with_client(url, Client::new())
        }
    }

    /// Creates a replica transport from a HTTP URL and a [`reqwest::Client`].
    pub fn create_with_client<U: Into<String>>(url: U, client: Client) -> Result<Self, AgentError> {
        let route_provider = Arc::new(RoundRobinRouteProvider::new(vec![url.into()])?);
        Self::create_with_client_route(route_provider, client)
    }

    /// Creates a replica transport from a [`RouteProvider`] and a [`reqwest::Client`].
    pub fn create_with_client_route(
        route_provider: Arc<dyn RouteProvider>,
        client: Client,
    ) -> Result<Self, AgentError> {
        Ok(Self {
            route_provider,
            client,
            max_response_body_size: None,
        })
    }

    /// Sets a max response body size limit
    pub fn with_max_response_body_size(self, max_response_body_size: usize) -> Self {
        ReqwestTransport {
            max_response_body_size: Some(max_response_body_size),
            ..self
        }
    }

    async fn request(
        &self,
        http_request: Request,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), AgentError> {
        let response = self
            .client
            .execute(http_request)
            .await
            .map_err(|x| AgentError::TransportError(Box::new(x)))?;

        let http_status = response.status();
        let response_headers = response.headers().clone();

        // Size Check (Content-Length)
        if matches!(self
            .max_response_body_size
            .zip(response.content_length()), Some((size_limit, content_length)) if content_length as usize > size_limit)
        {
            return Err(AgentError::ResponseSizeExceededLimit());
        }

        let mut body: Vec<u8> = response
            .content_length()
            .map_or_else(Vec::new, |n| Vec::with_capacity(n as usize));

        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|x| AgentError::TransportError(Box::new(x)))?;

            // Size Check (Body Size)
            if matches!(self
                .max_response_body_size, Some(size_limit) if body.len() + chunk.len() > size_limit)
            {
                return Err(AgentError::ResponseSizeExceededLimit());
            }

            body.extend_from_slice(chunk.as_ref());
        }

        Ok((http_status, response_headers, body))
    }

    async fn execute(
        &self,
        endpoint: Endpoint,
        method: Method,
        body: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, StatusCode), AgentError> {
        let url = self.route_provider.route(endpoint)?.join("")?;
        let mut http_request = Request::new(method, url);
        http_request
            .headers_mut()
            .insert(CONTENT_TYPE, "application/cbor".parse().unwrap());

        *http_request.body_mut() = body.map(Body::from);

        let request_result = loop {
            let result = self.request(http_request.try_clone().unwrap()).await?;
            if result.0 != StatusCode::TOO_MANY_REQUESTS {
                break result;
            }
            crate::util::sleep(Duration::from_millis(250)).await;
        };
        let status = request_result.0;
        let headers = request_result.1;
        let body = request_result.2;

        if status.is_client_error() || status.is_server_error() {
            Err(AgentError::HttpError(HttpErrorPayload {
                status: status.into(),
                content_type: headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|x| x.to_string()),
                content: body,
            }))
        } else {
            Ok((body, status))
        }
    }
}

impl Transport for ReqwestTransport {
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<TransportCallResponse> {
        Box::pin(async move {
            self.execute(
                Endpoint::Call(effective_canister_id),
                Method::POST,
                Some(envelope),
            )
            .await
            .and_then(|(body, status)| {
                if status == StatusCode::OK {
                    serde_cbor::from_slice(&body).map_err(AgentError::InvalidCborData)
                } else {
                    Err(AgentError::InvalidHttpResponse(
                        "Expected `200`, `4xx`, or `5xx` HTTP status code.".to_string(),
                    ))
                }
            })
        })
    }

    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            self.execute(
                Endpoint::ReadStateCanister(effective_canister_id),
                Method::POST,
                Some(envelope),
            )
            .await
            .map(|(body, _)| body)
        })
    }

    fn read_subnet_state(&self, subnet_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            self.execute(
                Endpoint::ReadStateSubnet(subnet_id),
                Method::POST,
                Some(envelope),
            )
            .await
            .map(|(body, _)| body)
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            self.execute(
                Endpoint::Query(effective_canister_id),
                Method::POST,
                Some(envelope),
            )
            .await
            .map(|(body, _)| body)
        })
    }

    fn status(&self) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            self.execute(Endpoint::Status, Method::GET, None)
                .await
                .map(|(body, _)| body)
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
    use wasm_bindgen_test::wasm_bindgen_test;
    #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use crate::agent::http_transport::route_provider::Endpoint;

    use super::ReqwestTransport;

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn redirect() {
        fn test(base: &str, result: &str) {
            let t: ReqwestTransport = ReqwestTransport::create(base).unwrap();
            let expected_endpoint = format!("{}status", result);

            assert_eq!(
                t.route_provider.route(Endpoint::Status).unwrap().as_str(),
                expected_endpoint,
                "{}",
                base
            );
        }

        test("https://ic0.app", "https://ic0.app/api/v2/");
        test("https://IC0.app", "https://ic0.app/api/v2/");
        test("https://foo.ic0.app", "https://ic0.app/api/v2/");
        test("https://foo.IC0.app", "https://ic0.app/api/v2/");
        test("https://foo.Ic0.app", "https://ic0.app/api/v2/");
        test("https://foo.iC0.app", "https://ic0.app/api/v2/");
        test("https://foo.bar.ic0.app", "https://ic0.app/api/v2/");
        test("https://ic0.app/foo/", "https://ic0.app/foo/api/v2/");
        test("https://foo.ic0.app/foo/", "https://ic0.app/foo/api/v2/");
        test(
            "https://ryjl3-tyaaa-aaaaa-aaaba-cai.ic0.app",
            "https://ic0.app/api/v2/",
        );

        test("https://ic1.app", "https://ic1.app/api/v2/");
        test("https://foo.ic1.app", "https://foo.ic1.app/api/v2/");
        test("https://ic0.app.ic1.app", "https://ic0.app.ic1.app/api/v2/");

        test("https://fooic0.app", "https://fooic0.app/api/v2/");
        test("https://fooic0.app.ic0.app", "https://ic0.app/api/v2/");

        test("https://icp0.io", "https://icp0.io/api/v2/");
        test(
            "https://ryjl3-tyaaa-aaaaa-aaaba-cai.icp0.io",
            "https://icp0.io/api/v2/",
        );
        test("https://ic0.app.icp0.io", "https://icp0.io/api/v2/");

        test("https://icp-api.io", "https://icp-api.io/api/v2/");
        test(
            "https://ryjl3-tyaaa-aaaaa-aaaba-cai.icp-api.io",
            "https://icp-api.io/api/v2/",
        );
        test("https://icp0.io.icp-api.io", "https://icp-api.io/api/v2/");

        test("http://localhost:4943", "http://localhost:4943/api/v2/");
        test(
            "http://ryjl3-tyaaa-aaaaa-aaaba-cai.localhost:4943",
            "http://localhost:4943/api/v2/",
        );
    }
}
