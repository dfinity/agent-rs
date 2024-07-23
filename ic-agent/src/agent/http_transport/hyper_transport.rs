//! A [`Transport`] that connects using a [`hyper`] client.
use http::StatusCode;
pub use hyper;

use std::sync::Arc;
use std::time::Duration;
use std::{any, error::Error, future::Future, marker::PhantomData, sync::atomic::AtomicPtr};

use http_body::Body;
use http_body_to_bytes::{http_body_to_bytes, http_body_to_bytes_with_max_length};
use http_body_util::LengthLimitError;
use hyper::{header::CONTENT_TYPE, Method, Request, Response};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use ic_transport_types::{RejectResponse, TransportCallResponse};
use tower::Service;

use crate::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::route_provider::{RoundRobinRouteProvider, RouteProvider},
        AgentFuture, Transport,
    },
    export::Principal,
    AgentError,
};

/// A [`Transport`] using [`hyper`] to make HTTP calls to the Internet Computer.
#[derive(Debug)]
pub struct HyperTransport<B1, S = Client<HttpsConnector<HttpConnector>, B1>> {
    _marker: PhantomData<AtomicPtr<B1>>,
    route_provider: Arc<dyn RouteProvider>,
    max_response_body_size: Option<usize>,
    #[allow(dead_code)]
    max_tcp_error_retries: usize,
    service: S,
    use_call_v3_endpoint: bool,
}

/// Trait representing the contraints on [`HttpBody`] that [`HyperTransport`] requires
pub trait HyperBody:
    Body<Data = Self::BodyData, Error = Self::BodyError> + Send + Unpin + 'static
{
    /// Values yielded by the `Body`.
    type BodyData: Send;
    /// The error type this `Body` might generate.
    type BodyError: Into<Box<dyn std::error::Error + Send + Sync>>;
}

impl<B> HyperBody for B
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Error + Send + Sync + 'static,
{
    type BodyData = B::Data;
    type BodyError = B::Error;
}

/// Trait representing the constraints on [`Service`] that [`HyperTransport`] requires.
pub trait HyperService<B1: HyperBody>:
    Send
    + Sync
    + Clone
    + Service<
        Request<B1>,
        Response = Response<hyper::body::Incoming>,
        Error = Self::RError,
        Future = Self::ServiceFuture,
    >
{
    /// The error type for conversion to `Bytes`.
    type RError: std::error::Error + Send + Sync + 'static;
    /// The future response value.
    type ServiceFuture: Send + Future<Output = Result<Self::Response, Self::Error>>;
}

impl<B1, S, E> HyperService<B1> for S
where
    B1: HyperBody,
    E: std::error::Error + Send + Sync + 'static,
    S: Send
        + Sync
        + Clone
        + Service<Request<B1>, Response = Response<hyper::body::Incoming>, Error = E>,
    S::Future: Send,
{
    type ServiceFuture = S::Future;
    type RError = E;
}

impl<B1: HyperBody + From<Vec<u8>>> HyperTransport<B1> {
    /// Creates a replica transport from a HTTP URL.
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self::create_with_service(url, client)
    }
}

impl<B1, S> HyperTransport<B1, S>
where
    B1: HyperBody + From<Vec<u8>>,
    S: HyperService<B1>,
{
    /// Creates a replica transport from a HTTP URL and a [`HyperService`].
    pub fn create_with_service<U: Into<String>>(url: U, service: S) -> Result<Self, AgentError> {
        let route_provider = Arc::new(RoundRobinRouteProvider::new(vec![url.into()])?);
        Self::create_with_service_route(route_provider, service)
    }

    /// Creates a replica transport from a [`RouteProvider`] and a [`HyperService`].
    pub fn create_with_service_route(
        route_provider: Arc<dyn RouteProvider>,
        service: S,
    ) -> Result<Self, AgentError> {
        Ok(Self {
            _marker: PhantomData,
            route_provider,
            service,
            max_response_body_size: None,
            max_tcp_error_retries: 0,
            use_call_v3_endpoint: false,
        })
    }

    /// Sets a max response body size limit
    pub fn with_max_response_body_size(self, max_response_body_size: usize) -> Self {
        Self {
            max_response_body_size: Some(max_response_body_size),
            ..self
        }
    }

    /// Sets a max number of retries for tcp connection errors.
    pub fn with_max_tcp_errors_retries(self, retries: usize) -> Self {
        HyperTransport {
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
        Self {
            use_call_v3_endpoint: true,
            ..self
        }
    }

    async fn request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>), AgentError> {
        let body = body.unwrap_or_default();
        fn map_error<E: Error + Send + Sync + 'static>(err: E) -> AgentError {
            if any::TypeId::of::<E>() == any::TypeId::of::<AgentError>() {
                // Store the value in an `Option` so we can `take`
                // it after casting to `&mut dyn Any`.
                let mut slot = Some(err);

                // Re-write the `$val` ident with the downcasted value.
                let val = (&mut slot as &mut dyn any::Any)
                    .downcast_mut::<Option<AgentError>>()
                    .unwrap()
                    .take()
                    .unwrap();

                // Run the $body in scope of the replaced val.
                return val;
            }
            AgentError::TransportError(Box::new(err))
        }

        let create_request_with_generated_url = || -> Result<Request<_>, AgentError> {
            let url = self.route_provider.route()?.join(endpoint)?;
            println!("{url}");
            let http_request = Request::builder()
                .method(&method)
                .uri(url.as_str())
                .header(CONTENT_TYPE, "application/cbor")
                .body(body.clone().into())
                .map_err(|err| AgentError::TransportError(Box::new(err)))?;
            Ok(http_request)
        };

        let response = loop {
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

                        match self.service.clone().call(http_request).await {
                            Ok(response) => break response,
                            Err(err) => {
                                if (&err as &dyn Error)
                                    .downcast_ref::<hyper_util::client::legacy::Error>()
                                    .is_some_and(|e| e.is_connect())
                                {
                                    if retry_count >= self.max_tcp_error_retries {
                                        return Err(map_error(err));
                                    }
                                    retry_count += 1;
                                    continue;
                                }
                                return Err(map_error(err));
                            }
                        }
                    }
                }
            };

            if response.status() != StatusCode::TOO_MANY_REQUESTS {
                break response;
            }
            crate::util::sleep(Duration::from_millis(250)).await;
        };
        let (parts, body) = response.into_parts();
        let body = if let Some(limit) = self.max_response_body_size {
            http_body_to_bytes_with_max_length(body, limit)
                .await
                .map_err(|err| {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        AgentError::ResponseSizeExceededLimit()
                    } else {
                        AgentError::TransportError(err)
                    }
                })?
        } else {
            http_body_to_bytes(body)
                .await
                .map_err(|err| AgentError::TransportError(err.into()))?
        };

        let (status, headers, body) = (parts.status, parts.headers, body.to_vec());
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
            Ok((status, body))
        }
    }
}

impl<B1, S> Transport for HyperTransport<B1, S>
where
    B1: HyperBody + From<Vec<u8>>,
    S: HyperService<B1>,
{
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
                &api_version,
                effective_canister_id.to_text()
            );
            let (status_code, response_body) = self
                .request(Method::POST, &endpoint, Some(envelope))
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
        Box::pin(async move {
            let endpoint = format!("canister/{effective_canister_id}/read_state",);
            self.request(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|(_, body)| body)
        })
    }

    fn read_subnet_state(&self, subnet_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("api/v2/subnet/{subnet_id}/read_state",);
            self.request(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|(_, body)| body)
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("api/v2/canister/{effective_canister_id}/query",);
            self.request(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|(_, body)| body)
        })
    }

    fn status(&self) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = "api/v2/status";
            self.request(Method::GET, endpoint, None)
                .await
                .map(|(_, body)| body)
        })
    }
}

#[cfg(test)]
mod test {
    use super::HyperTransport;
    use http_body_util::Full;
    use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::collections::VecDeque;
    use url::Url;

    #[test]
    fn redirect() {
        fn test(base: &str, result: &str) {
            let connector = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build();
            let client: Client<HttpsConnector<HttpConnector>, Full<VecDeque<u8>>> =
                Client::builder(TokioExecutor::new()).build(connector);
            let url: Url = base.parse().unwrap();
            let t = HyperTransport::create_with_service(url, client).unwrap();
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

        test("https://ic1.app", "https://ic1.app/");
        test("https://foo.ic1.app", "https://foo.ic1.app/");
        test("https://ic0.app.ic1.app", "https://ic0.app.ic1.app/");

        test("https://fooic0.app", "https://fooic0.app/");
        test("https://fooic0.app.ic0.app", "https://ic0.app/");
    }
}
