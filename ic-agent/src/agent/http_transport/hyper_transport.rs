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
use tower::Service;

use crate::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::route_provider::{RoundRobinRouteProvider, RouteProvider},
        AgentFuture, Transport,
    },
    export::Principal,
    AgentError, RequestId,
};

/// A [`Transport`] using [`hyper`] to make HTTP calls to the Internet Computer.
#[derive(Debug)]
pub struct HyperTransport<B1, S = Client<HttpsConnector<HttpConnector>, B1>> {
    _marker: PhantomData<AtomicPtr<B1>>,
    route_provider: Arc<dyn RouteProvider>,
    max_response_body_size: Option<usize>,
    service: S,
}

#[doc(hidden)]
#[deprecated(since = "0.30.0", note = "use HyperTransport")]
pub use HyperTransport as HyperReplicaV2Transport; // delete after 0.31

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

/// Trait representing the contraints on [`Service`] that [`HyperTransport`] requires.
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
        })
    }

    /// Sets a max response body size limit
    pub fn with_max_response_body_size(self, max_response_body_size: usize) -> Self {
        Self {
            max_response_body_size: Some(max_response_body_size),
            ..self
        }
    }

    async fn request(
        &self,
        method: Method,
        url: String,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, AgentError> {
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
        let response = loop {
            let http_request = Request::builder()
                .method(&method)
                .uri(&url)
                .header(CONTENT_TYPE, "application/cbor")
                .body(body.clone().into())
                .map_err(|err| AgentError::TransportError(Box::new(err)))?;
            let response = self
                .service
                .clone()
                .call(http_request)
                .await
                .map_err(map_error)?;
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
            Ok(body)
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
        _request_id: RequestId,
    ) -> AgentFuture<()> {
        Box::pin(async move {
            let url = format!(
                "{}canister/{effective_canister_id}/call",
                self.route_provider.route()?
            );
            self.request(Method::POST, url, Some(envelope)).await?;
            Ok(())
        })
    }

    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let url = format!(
                "{}canister/{effective_canister_id}/read_state",
                self.route_provider.route()?
            );
            self.request(Method::POST, url, Some(envelope)).await
        })
    }

    fn read_subnet_state(&self, subnet_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let url = format!(
                "{}subnet/{subnet_id}/read_state",
                self.route_provider.route()?
            );
            self.request(Method::POST, url, Some(envelope)).await
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let url = format!(
                "{}canister/{effective_canister_id}/query",
                self.route_provider.route()?
            );
            self.request(Method::POST, url, Some(envelope)).await
        })
    }

    fn status(&self) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let url = format!("{}status", self.route_provider.route()?);
            self.request(Method::GET, url, None).await
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
