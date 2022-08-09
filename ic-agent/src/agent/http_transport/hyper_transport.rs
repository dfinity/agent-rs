//! A [ReplicaV2Transport] that connects using a hyper client.
#![cfg(any(feature = "hyper", feature = "hyper_no_tls"))]

use bytes::Bytes;
use http::uri::{Authority, PathAndQuery};
use http_body::{LengthLimitError, Limited};
use hyper::{
    body::HttpBody,
    client::{connect::Connect, HttpConnector},
    header::CONTENT_TYPE,
    Body, Client, Method, Request, Uri,
};
#[cfg(feature = "hyper")]
use hyper_tls::HttpsConnector;
use std::{any, error::Error};

use crate::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::{IC0_DOMAIN, IC0_SUB_DOMAIN},
        AgentFuture, ReplicaV2Transport,
    },
    ic_types::Principal,
    AgentError, RequestId,
};

/// A [ReplicaV2Transport] using Reqwest to make HTTP calls to the internet computer.
#[cfg(feature = "hyper")]
#[derive(Debug)]
pub struct HyperReplicaV2Transport<C = HttpsConnector<HttpConnector>, B = Body> {
    url: Uri,
    client: Client<C, B>,
    max_response_body_size: Option<usize>,
}

/// A [ReplicaV2Transport] using Reqwest to make HTTP calls to the internet computer.
#[cfg(not(feature = "hyper"))]
#[derive(Debug)]
pub struct HyperReplicaV2Transport<C, B = Body> {
    url: Uri,
    client: Client<C, B>,
    max_response_body_size: Option<usize>,
}

impl<C, B> HyperReplicaV2Transport<C, B>
where
    C: Clone + Connect + Default + Send + Sync + 'static,
    B: HttpBody + Send + From<Vec<u8>> + 'static,
    B::Data: Send,
    B::Error: Error + Send + Sync + 'static,
{
    /// Creates a replica transport from a HTTP URL.
    pub fn create<U: Into<Uri>>(url: U) -> Result<Self, AgentError> {
        Self::create_with_client(url, Client::builder().build(C::default()))
    }
}

impl<C, B> HyperReplicaV2Transport<C, B>
where
    C: Clone + Connect + Send + Sync + 'static,
    B: HttpBody + Send + From<Vec<u8>> + 'static,
    B::Data: Send,
    B::Error: Error + Send + Sync + 'static,
{
    /// Creates a replica transport from a HTTP URL and a [`reqwest::Client`].
    pub fn create_with_client<U: Into<Uri>>(
        url: U,
        client: Client<C, B>,
    ) -> Result<Self, AgentError> {
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
            url: url,
            client,
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
        let response = self.client.request(http_request).await.map_err(map_error)?;

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

impl<C, B> ReplicaV2Transport for HyperReplicaV2Transport<C, B>
where
    C: Clone + Connect + Send + Sync + 'static,
    B: HttpBody + Send + From<Vec<u8>> + 'static,
    B::Data: Send,
    B::Error: Error + Send + Sync + 'static,
{
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        _request_id: RequestId,
    ) -> AgentFuture<()> {
        Box::pin(async move {
            let url = format!(
                "{}/canister/{}/call",
                self.url,
                effective_canister_id.to_text()
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
                "{}/canister/{}/read_state",
                self.url,
                effective_canister_id.to_text()
            );
            self.request(Method::POST, url, Some(envelope)).await
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let url = format!(
                "{}/canister/{}/query",
                self.url,
                effective_canister_id.to_text()
            );
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
            let t = HyperReplicaV2Transport::create_with_client(uri, client).unwrap();
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
