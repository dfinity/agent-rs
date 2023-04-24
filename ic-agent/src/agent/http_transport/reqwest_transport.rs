//! A [`Transport`] that connects using a [`reqwest`] client.
#![cfg(feature = "reqwest")]

pub use reqwest;

use std::sync::Arc;

use futures_util::StreamExt;
#[cfg(not(target_family = "wasm"))]
use hyper_rustls::ConfigBuilderExt;
use reqwest::{
    header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE},
    Body, Client, Method, Request, StatusCode, Url,
};

use crate::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::{IC0_DOMAIN, IC0_SUB_DOMAIN},
        replica_api::RejectResponse,
        AgentFuture, Transport,
    },
    export::Principal,
    AgentError, RequestId,
};

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

impl dyn PasswordManager {
    fn get(&self, cached: bool, url: &str) -> Result<Option<(String, String)>, AgentError> {
        if cached {
            self.cached(url)
        } else {
            self.required(url).map(Some)
        }
        .map_err(AgentError::AuthenticationError)
    }
}

impl_debug_empty!(dyn PasswordManager);

/// A [`Transport`] using [`reqwest`] to make HTTP calls to the Internet Computer.
#[derive(Debug)]
pub struct ReqwestTransport {
    url: Url,
    client: Client,
    password_manager: Option<Arc<dyn PasswordManager>>,
    max_response_body_size: Option<usize>,
}

#[doc(hidden)]
pub use ReqwestTransport as ReqwestHttpReplicaV2Transport; // deprecate after 0.24

impl ReqwestTransport {
    /// Creates a replica transport from a HTTP URL.
    #[cfg(not(target_family = "wasm"))]
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_webpki_roots()
            .with_no_client_auth();

        // Advertise support for HTTP/2
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Self::create_with_client(
            url,
            Client::builder()
                .use_preconfigured_tls(tls_config)
                .build()
                .expect("Could not create HTTP client."),
        )
    }

    /// Creates a replica transport from a HTTP URL.
    #[cfg(target_family = "wasm")]
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        Self::create_with_client(url, Client::new())
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
            password_manager: None,
            max_response_body_size: None,
        })
    }

    /// Sets a password manager to use with HTTP authentication.
    pub fn with_password_manager<P: 'static + PasswordManager>(self, password_manager: P) -> Self {
        self.with_arc_password_manager(Arc::new(password_manager))
    }

    /// Same as [`Self::with_password_manager`], but providing the Arc so one does not have to be created.
    pub fn with_arc_password_manager(self, password_manager: Arc<dyn PasswordManager>) -> Self {
        ReqwestTransport {
            password_manager: Some(password_manager),
            ..self
        }
    }

    /// Sets a max response body size limit
    pub fn with_max_response_body_size(self, max_response_body_size: usize) -> Self {
        ReqwestTransport {
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
        http_request: &mut Request,
        cached: bool,
    ) -> Result<(), AgentError> {
        if let Some(pm) = &self.password_manager {
            if let Some((u, p)) = pm.get(cached, http_request.url().as_str())? {
                let auth = base64::encode(&format!("{}:{}", u, p));
                http_request
                    .headers_mut()
                    .insert(AUTHORIZATION, format!("Basic {}", auth).parse().unwrap());
            }
        }
        Ok(())
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

        self.maybe_add_authorization(&mut http_request, true)?;

        *http_request.body_mut() = body.map(Body::from);

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
            if status == StatusCode::UNAUTHORIZED {
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
    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;
    #[cfg(target_family = "wasm")]
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
