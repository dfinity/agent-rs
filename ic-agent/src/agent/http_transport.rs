//! A [ReplicaV2Transport] that connects using a reqwest client.
#![cfg(feature = "reqwest")]

pub use reqwest;

use crate::{agent::agent_error::HttpErrorPayload, ic_types::Principal, AgentError, RequestId};
use futures_util::StreamExt;
use hyper_rustls::ConfigBuilderExt;
use reqwest::Method;
use std::{future::Future, pin::Pin, sync::Arc};

/// Implemented by the Agent environment to cache and update an HTTP Auth password.
/// It returns a tuple of `(username, password)`.
pub trait PasswordManager: Send + Sync {
    /// Retrieve the cached value for a user. If no cache value exists for this URL,
    /// the manager can return [`None`].
    fn cached(&self, url: &str) -> Result<Option<(String, String)>, String>;

    /// A call to the replica failed, so in order to succeed a username and password
    /// is required. If one cannot be provided (for example, there's no terminal),
    /// this should return an error.
    /// If the username and password provided by this method does not work (the next
    /// request still returns UNAUTHORIZED), this will be called and the request will
    /// be retried in a loop.
    fn required(&self, url: &str) -> Result<(String, String), String>;
}

impl_debug_empty!(dyn PasswordManager);

/// A [ReplicaV2Transport] using Reqwest to make HTTP calls to the internet computer.
#[derive(Debug)]
pub struct ReqwestHttpReplicaV2Transport {
    url: reqwest::Url,
    client: reqwest::Client,
    password_manager: Option<Arc<dyn PasswordManager>>,
    max_response_body_size: Option<usize>,
}

const IC0_DOMAIN: &str = "ic0.app";
const IC0_SUB_DOMAIN: &str = ".ic0.app";

impl ReqwestHttpReplicaV2Transport {
    /// Creates a replica transport from a HTTP URL.
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_webpki_roots()
            .with_no_client_auth();

        // Advertise support for HTTP/2
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Self::create_with_client(
            url,
            reqwest::Client::builder()
                .use_preconfigured_tls(tls_config)
                .build()
                .expect("Could not create HTTP client."),
        )
    }

    /// Creates a replica transport from a HTTP URL and a [`reqwest::Client`].
    pub fn create_with_client<U: Into<String>>(
        url: U,
        client: reqwest::Client,
    ) -> Result<Self, AgentError> {
        let url = url.into();
        Ok(Self {
            url: reqwest::Url::parse(&url)
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
            password_manager: None,
            max_response_body_size: None,
        })
    }

    /// Sets a password manager to use with HTTP authentication.
    pub fn with_password_manager<P: 'static + PasswordManager>(self, password_manager: P) -> Self {
        ReqwestHttpReplicaV2Transport {
            password_manager: Some(Arc::new(password_manager)),
            ..self
        }
    }

    /// Same as [`with_password_manager`], but providing the Arc so one does not have to be created.
    pub fn with_arc_password_manager(self, password_manager: Arc<dyn PasswordManager>) -> Self {
        ReqwestHttpReplicaV2Transport {
            password_manager: Some(password_manager),
            ..self
        }
    }

    /// Sets a max response body size limit
    pub fn with_max_response_body_size(self, max_response_body_size: usize) -> Self {
        ReqwestHttpReplicaV2Transport {
            max_response_body_size: Some(max_response_body_size),
            ..self
        }
    }

    /// Gets the set password manager, if one exists. Otherwise returns None.
    pub fn password_manager(&self) -> Option<&dyn PasswordManager> {
        self.password_manager.as_deref()
    }

    fn maybe_add_authorization(
        &self,
        http_request: &mut reqwest::Request,
        cached: bool,
    ) -> Result<(), AgentError> {
        if let Some(pm) = &self.password_manager {
            let maybe_user_pass = if cached {
                pm.cached(http_request.url().as_str())
            } else {
                pm.required(http_request.url().as_str()).map(Some)
            };

            if let Some((u, p)) = maybe_user_pass.map_err(AgentError::AuthenticationError)? {
                let auth = base64::encode(&format!("{}:{}", u, p));
                http_request.headers_mut().insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Basic {}", auth).parse().unwrap(),
                );
            }
        }
        Ok(())
    }

    async fn request(
        &self,
        http_request: reqwest::Request,
    ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, Vec<u8>), AgentError> {
        let response = self
            .client
            .execute(
                http_request
                    .try_clone()
                    .expect("Could not clone a request."),
            )
            .await
            .map_err(|x| AgentError::TransportError(Box::new(x)))?;

        let http_status = response.status();
        let response_headers = response.headers().clone();

        // Size Check (Content-Length)
        if let Some(true) = self
            .max_response_body_size
            .zip(response.content_length())
            .map(|(size_limit, content_length)| content_length as usize > size_limit)
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
            if let Some(true) = self
                .max_response_body_size
                .map(|size_limit| body.len() + chunk.len() > size_limit)
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
        let mut http_request = reqwest::Request::new(method, url);
        http_request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            "application/cbor".parse().unwrap(),
        );

        self.maybe_add_authorization(&mut http_request, true)?;

        *http_request.body_mut() = body.map(reqwest::Body::from);

        let mut status;
        let mut headers;
        let mut body;
        loop {
            let request_result = self.request(http_request.try_clone().unwrap()).await?;
            status = request_result.0;
            headers = request_result.1;
            body = request_result.2;

            // If the server returned UNAUTHORIZED, and it is the first time we replay the call,
            // check if we can get the username/password for the HTTP Auth.
            if status == reqwest::StatusCode::UNAUTHORIZED {
                if self.url.scheme() == "https" || self.url.host_str() == Some("localhost") {
                    // If there is a password manager, get the username and password from it.
                    self.maybe_add_authorization(&mut http_request, false)?;
                } else {
                    return Err(AgentError::CannotUseAuthenticationOnNonSecureUrl());
                }
            } else {
                break;
            }
        }

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

impl super::ReplicaV2Transport for ReqwestHttpReplicaV2Transport {
    fn call<'a>(
        &'a self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        _request_id: RequestId,
    ) -> Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send + 'a>> {
        async fn run(
            s: &ReqwestHttpReplicaV2Transport,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
        ) -> Result<(), AgentError> {
            let endpoint = format!("canister/{}/call", effective_canister_id.to_text());
            s.execute(Method::POST, &endpoint, Some(envelope)).await?;
            Ok(())
        }

        Box::pin(run(self, effective_canister_id, envelope))
    }

    fn read_state<'a>(
        &'a self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
        async fn run(
            s: &ReqwestHttpReplicaV2Transport,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
        ) -> Result<Vec<u8>, AgentError> {
            let endpoint = format!("canister/{}/read_state", effective_canister_id.to_text());
            s.execute(Method::POST, &endpoint, Some(envelope)).await
        }

        Box::pin(run(self, effective_canister_id, envelope))
    }

    fn query<'a>(
        &'a self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
        async fn run(
            s: &ReqwestHttpReplicaV2Transport,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
        ) -> Result<Vec<u8>, AgentError> {
            let endpoint = format!("canister/{}/query", effective_canister_id.to_text());
            s.execute(Method::POST, &endpoint, Some(envelope)).await
        }

        Box::pin(run(self, effective_canister_id, envelope))
    }

    fn status<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
        async fn run(s: &ReqwestHttpReplicaV2Transport) -> Result<Vec<u8>, AgentError> {
            s.execute(Method::GET, "status", None).await
        }

        Box::pin(run(self))
    }
}

#[cfg(test)]
mod test {
    use super::ReqwestHttpReplicaV2Transport;

    #[test]
    fn redirect() {
        fn test(base: &str, result: &str) {
            let t = ReqwestHttpReplicaV2Transport::create(base).unwrap();
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
