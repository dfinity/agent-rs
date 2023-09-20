//! A [`Transport`] that connects using a [`reqwest`] client.
#![cfg(feature = "reqwest")]

use ic_transport_types::RejectResponse;
pub use reqwest;

use futures_util::StreamExt;
use reqwest::{
    header::{HeaderMap, CONTENT_TYPE},
    Body, Client, Method, Request, StatusCode, Url,
};

use crate::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::{IC0_DOMAIN, IC0_SUB_DOMAIN},
        AgentFuture, Transport,
    },
    export::Principal,
    AgentError, RequestId,
};

/// A [`Transport`] using [`reqwest`] to make HTTP calls to the Internet Computer.
#[derive(Debug)]
pub struct ReqwestTransport {
    url: Url,
    client: Client,
    max_response_body_size: Option<usize>,
}

#[doc(hidden)]
pub use ReqwestTransport as ReqwestHttpReplicaV2Transport; // deprecate after 0.24

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
        let url = url.into();
        Ok(Self {
            url: Url::parse(&url)
                .and_then(|mut url| {
                    // rewrite *.ic0.app to ic0.app
                    if let Some(domain) = url.domain() {
                        if domain.ends_with(IC0_SUB_DOMAIN) {
                            url.set_host(Some(IC0_DOMAIN))?;
                        }
                    }
                    url.join("api/v2/")
                })
                .map_err(|_| AgentError::InvalidReplicaUrl(url.clone()))?,
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
        method: Method,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, AgentError> {
        let url = self.url.join(endpoint)?;
        let mut http_request = Request::new(method, url);
        http_request
            .headers_mut()
            .insert(CONTENT_TYPE, "application/cbor".parse().unwrap());

        *http_request.body_mut() = body.map(Body::from);

        let request_result = self.request(http_request.try_clone().unwrap()).await?;
        let status = request_result.0;
        let headers = request_result.1;
        let body = request_result.2;

        // status == OK means we have an error message for call requests
        // see https://internetcomputer.org/docs/current/references/ic-interface-spec#http-call
        if status == StatusCode::OK && endpoint.ends_with("call") {
            let cbor_decoded_body: Result<RejectResponse, serde_cbor::Error> =
                serde_cbor::from_slice(&body);

            let agent_error = match cbor_decoded_body {
                Ok(replica_error) => AgentError::ReplicaError(replica_error),
                Err(cbor_error) => AgentError::InvalidCborData(cbor_error),
            };

            Err(agent_error)
        } else if status.is_client_error() || status.is_server_error() {
            Err(AgentError::HttpError(HttpErrorPayload {
                status: status.into(),
                content_type: headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|x| x.to_string()),
                content: body,
            }))
        } else {
            Ok(body)
        }
    }
}

impl Transport for ReqwestTransport {
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        _request_id: RequestId,
    ) -> AgentFuture<()> {
        Box::pin(async move {
            let endpoint = format!("canister/{}/call", effective_canister_id.to_text());
            self.execute(Method::POST, &endpoint, Some(envelope))
                .await?;
            Ok(())
        })
    }

    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("canister/{effective_canister_id}/read_state");
            self.execute(Method::POST, &endpoint, Some(envelope)).await
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("canister/{effective_canister_id}/query");
            self.execute(Method::POST, &endpoint, Some(envelope)).await
        })
    }

    fn status(&self) -> AgentFuture<Vec<u8>> {
        Box::pin(async move { self.execute(Method::GET, "status", None).await })
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
            assert_eq!(t.url.as_str(), result, "{}", base);
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

        test("https://ic1.app", "https://ic1.app/api/v2/");
        test("https://foo.ic1.app", "https://foo.ic1.app/api/v2/");
        test("https://ic0.app.ic1.app", "https://ic0.app.ic1.app/api/v2/");

        test("https://fooic0.app", "https://fooic0.app/api/v2/");
        test("https://fooic0.app.ic0.app", "https://ic0.app/api/v2/");
    }
}
