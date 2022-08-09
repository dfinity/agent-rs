//! A [ReplicaV2Transport] that connects using a hyper client.
#![cfg(any(feature = "hyper"))]

pub use hyper;

use std::{any, error::Error, future::Future, marker::PhantomData, sync::atomic::AtomicPtr};

use bytes::Bytes;
use http::uri::{Authority, PathAndQuery};
use http_body::{LengthLimitError, Limited};
use hyper::{
    body::HttpBody, client::HttpConnector, header::CONTENT_TYPE, service::Service, Body, Client,
    Method, Request, Response, Uri,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};

use crate::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::{IC0_DOMAIN, IC0_SUB_DOMAIN},
        AgentFuture, ReplicaV2Transport,
    },
    ic_types::Principal,
    AgentError, RequestId,
};

/// A [ReplicaV2Transport] using [hyper] to make HTTP calls to the internet computer.
#[derive(Debug)]
pub struct HyperReplicaV2Transport<B1, B2 = Body, S = Client<HttpsConnector<HttpConnector>, B1>> {
    _marker: PhantomData<(AtomicPtr<B1>, AtomicPtr<B2>)>,
    url: Uri,
    max_response_body_size: Option<usize>,
    service: S,
}

/// Trait representing the contraints on [`HttpBody`] that [`HyperReplicaV2Transport`] requires
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

/// Trait representing the contraints on [`Service`] that [`HyperReplicaV2Transport`] requires.
pub trait HyperService<B1: HyperBody, B2: HyperBody>:
    Send
    + Sync
    + Clone
    + Service<
        Request<B1>,
        Response = Response<B2>,
        Error = hyper::Error,
        Future = Self::ServiceFuture,
    >
{
    /// The future response value.
    type ServiceFuture: Send + Future<Output = Result<Self::Response, Self::Error>>;
}

impl<B1, B2, S> HyperService<B1, B2> for S
where
    B1: HyperBody,
    B2: HyperBody,
    S: Send + Sync + Clone + Service<Request<B1>, Response = Response<B2>, Error = hyper::Error>,
    S::Future: Send,
{
    type ServiceFuture = S::Future;
}

impl<B1: HyperBody> HyperReplicaV2Transport<B1> {
    /// Creates a replica transport from a HTTP URL.
    pub fn create<U: Into<Uri>>(url: U) -> Result<Self, AgentError> {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        Self::create_with_service(url, Client::builder().build(connector))
    }
}

impl<B1, B2, S> HyperReplicaV2Transport<B1, B2, S>
where
    B1: HyperBody,
    B2: HyperBody,
    S: HyperService<B1, B2>,
{
    /// Creates a replica transport from a HTTP URL and a [`reqwest::Client`].
    pub fn create_with_service<U: Into<Uri>>(url: U, service: S) -> Result<Self, AgentError> {
        // Parse the url
        let url = url.into();
        let mut parts = url.clone().into_parts();
        parts.authority = parts
            .authority
            .map(|v| {
                let host = v.host();
                let host = match host.len().checked_sub(IC0_SUB_DOMAIN.len()) {
                    None => host,
                    Some(start) if host[start..].eq_ignore_ascii_case(IC0_SUB_DOMAIN) => IC0_DOMAIN,
                    Some(_) => host,
                };
                let port = v.port();
                let (colon, port) = match port.as_ref() {
                    Some(v) => (":", v.as_str()),
                    None => ("", ""),
                };
                Authority::from_maybe_shared(Bytes::from(format!("{host}{colon}{port}")))
            })
            .transpose()
            .map_err(|_| AgentError::InvalidReplicaUrl(format!("{url}")))?;
        parts.path_and_query = Some(
            parts
                .path_and_query
                .map_or(Ok(PathAndQuery::from_static("/api/v2")), |v| {
                    let mut found = false;
                    fn replace<T>(a: T, b: &mut T) -> T {
                        std::mem::replace(b, a)
                    }
                    let v = v
                        .path()
                        .trim_end_matches(|c| !replace(found || c == '/', &mut found));
                    PathAndQuery::from_maybe_shared(Bytes::from(format!("{v}/api/v2")))
                })
                .map_err(|_| AgentError::InvalidReplicaUrl(format!("{url}")))?,
        );
        let url =
            Uri::from_parts(parts).map_err(|_| AgentError::InvalidReplicaUrl(format!("{url}")))?;

        Ok(Self {
            _marker: PhantomData,
            url: url,
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
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|x| x.to_string()),
                content: body,
            }))
        } else {
            Ok(body)
        }
    }
}

impl<B1, B2, S> ReplicaV2Transport for HyperReplicaV2Transport<B1, B2, S>
where
    B1: HyperBody,
    B2: HyperBody,
    S: HyperService<B1, B2>,
{
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        _request_id: RequestId,
    ) -> AgentFuture<()> {
        Box::pin(async move {
            let url = format!("{}/canister/{effective_canister_id}/call", self.url);
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
            let url = format!("{}/canister/{effective_canister_id}/read_state", self.url);
            self.request(Method::POST, url, Some(envelope)).await
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let url = format!("{}/canister/{effective_canister_id}/query", self.url);
            self.request(Method::POST, url, Some(envelope)).await
        })
    }

    fn status(&self) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let url = format!("{}/status", self.url);
            self.request(Method::GET, url, None).await
        })
    }
}

#[cfg(test)]
mod test {
    use super::HyperReplicaV2Transport;
    use hyper::{Client, Uri};

    #[test]
    fn redirect() {
        fn test(base: &str, result: &str) {
            let client: Client<_> = Client::builder().build_http();
            let uri: Uri = base.parse().unwrap();
            let t = HyperReplicaV2Transport::create_with_service(uri, client).unwrap();
            assert_eq!(t.url, result, "{}", base);
        }

        test("https://ic0.app", "https://ic0.app/api/v2");
        test("https://IC0.app", "https://ic0.app/api/v2");
        test("https://foo.ic0.app", "https://ic0.app/api/v2");
        test("https://foo.IC0.app", "https://ic0.app/api/v2");
        test("https://foo.Ic0.app", "https://ic0.app/api/v2");
        test("https://foo.iC0.app", "https://ic0.app/api/v2");
        test("https://foo.bar.ic0.app", "https://ic0.app/api/v2");
        test("https://ic0.app/foo/", "https://ic0.app/foo/api/v2");
        test("https://foo.ic0.app/foo/", "https://ic0.app/foo/api/v2");

        test("https://ic1.app", "https://ic1.app/api/v2");
        test("https://foo.ic1.app", "https://foo.ic1.app/api/v2");
        test("https://ic0.app.ic1.app", "https://ic0.app.ic1.app/api/v2");

        test("https://fooic0.app", "https://fooic0.app/api/v2");
        test("https://fooic0.app.ic0.app", "https://ic0.app/api/v2");
    }
}
