//! A [`Transport`] that connects using a [`hyper`] client.
pub use hyper;

use std::{any, error::Error, future::Future, marker::PhantomData, sync::atomic::AtomicPtr};

use http_body::{LengthLimitError, Limited};
use hyper::{
    body::HttpBody, client::HttpConnector, header::CONTENT_TYPE, service::Service, Client, Method,
    Request, Response,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};

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
    route_provider: Box<dyn RouteProvider>,
    max_response_body_size: Option<usize>,
    service: S,
}

#[doc(hidden)]
#[deprecated(since = "0.30.0", note = "use HyperTransport")]
pub use HyperTransport as HyperReplicaV2Transport; // delete after 0.31

/// Trait representing the contraints on [`HttpBody`] that [`HyperTransport`] requires
pub trait HyperBody:
    HttpBody<Data = Self::BodyData, Error = Self::BodyError> + Send + From<Vec<u8>> + 'static
{
    /// Values yielded by the `Body`.
    type BodyData: Send;
    /// The error type this `Body` might generate.
    type BodyError: Error + Send + Sync + 'static;
}

impl<B> HyperBody for B
where
    B: HttpBody + Send + From<Vec<u8>> + 'static,
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
        Response = Response<Self::ResponseBody>,
        Error = hyper::Error,
        Future = Self::ServiceFuture,
    >
{
    /// Values yielded in the `Body` of the `Response`.
    type ResponseBody: HyperBody;
    /// The future response value.
    type ServiceFuture: Send + Future<Output = Result<Self::Response, Self::Error>>;
}

impl<B1, B2, S> HyperService<B1> for S
where
    B1: HyperBody,
    B2: HyperBody,
    S: Send + Sync + Clone + Service<Request<B1>, Response = Response<B2>, Error = hyper::Error>,
    S::Future: Send,
{
    type ResponseBody = B2;
    type ServiceFuture = S::Future;
}

impl<B1: HyperBody> HyperTransport<B1> {
    /// Creates a replica transport from a HTTP URL.
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        Self::create_with_service(url, Client::builder().build(connector))
    }
}

impl<B1, S> HyperTransport<B1, S>
where
    B1: HyperBody,
    S: HyperService<B1>,
{
    /// Creates a replica transport from a HTTP URL and a [`HyperService`].
    pub fn create_with_service<U: Into<String>>(url: U, service: S) -> Result<Self, AgentError> {
        let route_provider = Box::new(RoundRobinRouteProvider::new(vec![url.into()])?);
        Self::create_with_service_route(route_provider, service)
    }

    /// Creates a replica transport from a [`RouteProvider`] and a [`HyperService`].
    pub fn create_with_service_route(
        route_provider: Box<dyn RouteProvider>,
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
        let http_request = Request::builder()
            .method(method)
            .uri(url)
            .header(CONTENT_TYPE, "application/cbor")
            .body(body.unwrap_or_default().into())
            .map_err(|err| AgentError::TransportError(Box::new(err)))?;

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
        let response = self
            .service
            .clone()
            .call(http_request)
            .await
            .map_err(map_error)?;

        let (parts, body) = response.into_parts();
        let body = if let Some(limit) = self.max_response_body_size {
            hyper::body::to_bytes(Limited::new(body, limit))
                .await
                .map_err(|err| {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        AgentError::ResponseSizeExceededLimit()
                    } else {
                        AgentError::TransportError(err)
                    }
                })?
        } else {
            hyper::body::to_bytes(body)
                .await
                .map_err(|err| AgentError::TransportError(Box::new(err)))?
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
    B1: HyperBody,
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
    use hyper::Client;
    use url::Url;

    #[test]
    fn redirect() {
        fn test(base: &str, result: &str) {
            let client: Client<_> = Client::builder().build_http();
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
