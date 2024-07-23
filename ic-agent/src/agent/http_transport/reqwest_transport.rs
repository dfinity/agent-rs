//! A [`Transport`] that connects using a [`reqwest`] client.
#![cfg(feature = "reqwest")]

use ic_transport_types::{RejectResponse, TransportCallResponse};
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
    #[allow(dead_code)]
    max_tcp_error_retries: usize,
    use_call_v3_endpoint: bool,
}

impl ReqwestTransport {
    /// Creates a replica transport from a HTTP URL. By default a request timeout of 6 minutes is used.
    /// Use `create_with_client` to configure this and other client options.
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        #[cfg(not(target_family = "wasm"))]
        {
            Self::create_with_client(
                url,
                Client::builder()
                    .use_rustls_tls()
                    .timeout(Duration::from_secs(360))
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
            max_tcp_error_retries: 0,
            use_call_v3_endpoint: false,
        })
    }

    /// Sets a max response body size limit
    pub fn with_max_response_body_size(self, max_response_body_size: usize) -> Self {
        ReqwestTransport {
            max_response_body_size: Some(max_response_body_size),
            ..self
        }
    }

    /// Sets a max number of retries for tcp connection errors.
    pub fn with_max_tcp_errors_retries(self, retries: usize) -> Self {
        ReqwestTransport {
            max_tcp_error_retries: retries,
            ..self
        }
    }

    /// Use call v3 endpoint for synchronous update calls.
    /// __This is an experimental feature, and should not be used in production,
    /// as the endpoint is not available yet on the mainnet IC.__
    ///
    /// By enabling this feature, the agent will use the `v3` endpoint for update calls,
    /// which is synchronous. This means the replica will wait for a certificate for the call,
    /// meaning the agent will not need to poll for the certificate.
    #[cfg(feature = "experimental_sync_call")]
    pub fn with_use_call_v3_endpoint(self) -> Self {
        ReqwestTransport {
            use_call_v3_endpoint: true,
            ..self
        }
    }

    async fn request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), AgentError> {
        let create_request_with_generated_url = || -> Result<Request, AgentError> {
            let url = self.route_provider.route()?.join(endpoint)?;
            let mut http_request = Request::new(method.clone(), url);
            http_request
                .headers_mut()
                .insert(CONTENT_TYPE, "application/cbor".parse().unwrap());
            *http_request.body_mut() = body.as_ref().cloned().map(Body::from);
            Ok(http_request)
        };

        // Dispatch request with a retry logic only for non-wasm builds.
        let response = {
            #[cfg(target_family = "wasm")]
            {
                let http_request = create_request_with_generated_url()?;
                match self.client.execute(http_request).await {
                    Ok(response) => response,
                    Err(err) => return Err(AgentError::TransportError(Box::new(err))),
                }
            }
            #[cfg(not(target_family = "wasm"))]
            {
                // RouteProvider generates urls dynamically. Some of these urls can be potentially unhealthy.
                // TCP related errors (host unreachable, connection refused, connection timed out, connection reset) can be safely retried with a newly generated url.

                let mut retry_count = 0;

                loop {
                    let http_request = create_request_with_generated_url()?;

                    match self.client.execute(http_request).await {
                        Ok(response) => break response,
                        Err(err) => {
                            // Network-related errors can be retried.
                            if err.is_connect() {
                                if retry_count >= self.max_tcp_error_retries {
                                    return Err(AgentError::TransportError(Box::new(err)));
                                }
                                retry_count += 1;
                                continue;
                            }
                            return Err(AgentError::TransportError(Box::new(err)));
                        }
                    }
                }
            }
        };

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
        method: Method,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>), AgentError> {
        let request_result = loop {
            let result = self
                .request(method.clone(), endpoint, body.as_ref().cloned())
                .await?;
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
        } else if !(status == StatusCode::OK || status == StatusCode::ACCEPTED) {
            Err(AgentError::InvalidHttpResponse(format!(
                "Expected `200`, `202`, 4xx`, or `5xx` HTTP status code. Got: {}",
                status
            )))
        } else {
            Ok((status, body))
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
            let api_version = if self.use_call_v3_endpoint {
                "v3"
            } else {
                "v2"
            };

            let endpoint = format!(
                "api/{}/canister/{}/call",
                api_version,
                effective_canister_id.to_text()
            );
            let (status_code, response_body) = self
                .execute(Method::POST, &endpoint, Some(envelope))
                .await?;

            if status_code == StatusCode::ACCEPTED {
                return Ok(TransportCallResponse::Accepted);
            }

            // status_code == OK (200)
            if self.use_call_v3_endpoint {
                serde_cbor::from_slice(&response_body).map_err(AgentError::InvalidCborData)
            } else {
                let reject_response = serde_cbor::from_slice::<RejectResponse>(&response_body)
                    .map_err(AgentError::InvalidCborData)?;

                Err(AgentError::UncertifiedReject(reject_response))
            }
        })
    }

    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>> {
        let endpoint = format!(
            "api/v2/canister/{}/read_state",
            effective_canister_id.to_text()
        );

        Box::pin(async move {
            self.execute(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|r| r.1)
        })
    }

    fn read_subnet_state(&self, subnet_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("api/v2/subnet/{}/read_state", subnet_id.to_text());
            self.execute(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|r| r.1)
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("api/v2/canister/{}/query", effective_canister_id.to_text());
            self.execute(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|r| r.1)
        })
    }

    fn status(&self) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = "api/v2/status";
            self.execute(Method::GET, endpoint, None).await.map(|r| r.1)
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
    use wasm_bindgen_test::wasm_bindgen_test;
    #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use super::ReqwestTransport;

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn redirect() {
        fn test(base: &str, result: &str) {
            let t = ReqwestTransport::create(base).unwrap();
            assert_eq!(
                t.route_provider.route().unwrap().as_str(),
                result,
                "{}",
                base
            );
        }

        test("https://ic0.app", "https://ic0.app/");
        test("https://IC0.app", "https://ic0.app/");
        test("https://foo.ic0.app", "https://ic0.app/");
        test("https://foo.IC0.app", "https://ic0.app/");
        test("https://foo.Ic0.app", "https://ic0.app/");
        test("https://foo.iC0.app", "https://ic0.app/");
        test("https://foo.bar.ic0.app", "https://ic0.app/");
        test("https://ic0.app/foo/", "https://ic0.app/foo/");
        test("https://foo.ic0.app/foo/", "https://ic0.app/foo/");
        test(
            "https://ryjl3-tyaaa-aaaaa-aaaba-cai.ic0.app",
            "https://ic0.app/",
        );

        test("https://ic1.app", "https://ic1.app/");
        test("https://foo.ic1.app", "https://foo.ic1.app/");
        test("https://ic0.app.ic1.app", "https://ic0.app.ic1.app/");

        test("https://fooic0.app", "https://fooic0.app/");
        test("https://fooic0.app.ic0.app", "https://ic0.app/");

        test("https://icp0.io", "https://icp0.io/");
        test(
            "https://ryjl3-tyaaa-aaaaa-aaaba-cai.icp0.io",
            "https://icp0.io/",
        );
        test("https://ic0.app.icp0.io", "https://icp0.io/");

        test("https://icp-api.io", "https://icp-api.io/");
        test(
            "https://ryjl3-tyaaa-aaaaa-aaaba-cai.icp-api.io",
            "https://icp-api.io/",
        );
        test("https://icp0.io.icp-api.io", "https://icp-api.io/");

        test("http://localhost:4943", "http://localhost:4943/");
        test(
            "http://ryjl3-tyaaa-aaaaa-aaaba-cai.localhost:4943",
            "http://localhost:4943/",
        );
    }
}
