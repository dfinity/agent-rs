//! A [ReplicaV2Transport] that connects using a reqwest client.
#![cfg(feature = "reqwest")]

use crate::agent::agent_error::HttpErrorPayload;
use crate::AgentError;
use ic_types::Principal;
use reqwest::Method;
use std::future::Future;
use std::pin::Pin;

/// Implemented by the Agent environment to cache and update an HTTP Auth password.
/// It returns a tuple of `(username, password)`.
pub trait PasswordManager {
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

/// A [ReplicaV2Transport] using Reqwest to make HTTP calls to the internet computer.
pub struct ReqwestHttpReplicaV2Transport {
    url: reqwest::Url,
    client: reqwest::Client,
    password_manager: Option<Box<dyn PasswordManager + Send + Sync>>,
}

impl ReqwestHttpReplicaV2Transport {
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        let mut tls_config = rustls::ClientConfig::new();

        // Advertise support for HTTP/2
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Mozilla CA root store
        tls_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        let url = url.into();

        Ok(Self {
            url: reqwest::Url::parse(&url)
                .and_then(|url| url.join("api/v2/"))
                .map_err(|_| AgentError::InvalidReplicaUrl(url.clone()))?,
            client: reqwest::Client::builder()
                .use_preconfigured_tls(tls_config)
                .build()
                .expect("Could not create HTTP client."),
            password_manager: None,
        })
    }

    pub fn with_password_manager<P: 'static + PasswordManager + Send + Sync>(
        self,
        password_manager: P,
    ) -> Self {
        Self {
            password_manager: Some(Box::new(password_manager)),
            ..self
        }
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
        let bytes = response
            .bytes()
            .await
            .map_err(|x| AgentError::TransportError(Box::new(x)))?
            .to_vec();

        Ok((http_status, response_headers, bytes))
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
