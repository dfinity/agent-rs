pub(crate) mod agent_config;
pub(crate) mod agent_error;
pub(crate) mod builder;
pub(crate) mod nonce;
pub(crate) mod replica_api;
pub(crate) mod response;

pub(crate) mod public {
    pub use super::agent_config::{AgentConfig, PasswordManager};
    pub use super::agent_error::AgentError;
    pub use super::nonce::NonceFactory;
    pub use super::response::{Replied, RequestStatusResponse};
    pub use super::Agent;
}

#[cfg(test)]
mod agent_test;

use crate::agent::replica_api::{AsyncContent, Envelope, SyncContent};
use crate::identity::Identity;
use crate::{to_request_id, Principal, RequestId, Status};
use reqwest::Method;
use serde::Serialize;

use public::*;
use std::convert::TryFrom;

const DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";

/// A low level Agent to make calls to a Replica endpoint.
///
/// ```
/// use ic_agent::{Agent, Principal};
/// use candid::{Encode, Decode, CandidType};
/// use serde::Deserialize;
///
/// #[derive(CandidType, Deserialize)]
/// struct CreateCanisterResult {
///   canister_id: candid::Principal,  // Temporarily, while waiting for Candid to use ic-types
/// }
///
/// async fn create_a_canister() -> Result<Principal, Box<dyn std::error::Error>> {
///   let agent = Agent::builder()
///     .with_url("http://gw.dfinity.org")
///     .build()?;
///   let management_canister_id = Principal::from_text("aaaaa-aa")?;
///
///   let response = agent.update(&management_canister_id, "create_canister", &Encode!()?).await?;
///   let result = Decode!(response.as_slice(), CreateCanisterResult)?;
///   let canister_id: Principal = Principal::from_text(&result.canister_id.to_text())?;
///   Ok(canister_id)
/// }
/// ```
///
/// This agent does not understand Candid, and only acts on byte buffers.
pub struct Agent {
    url: reqwest::Url,
    nonce_factory: NonceFactory,
    default_waiter: delay::Delay,
    client: reqwest::Client,
    identity: Box<dyn Identity>,
    password_manager: Option<Box<dyn PasswordManager>>,
}

impl Agent {
    /// Create an instance of an [`AgentBuilder`] for building an [`Agent`]. This is simpler than
    /// using the [`AgentConfig`] and [`Agent::new()`].
    pub fn builder() -> builder::AgentBuilder {
        Default::default()
    }

    /// Create an instance of an [`Agent`].
    pub fn new(config: AgentConfig) -> Result<Agent, AgentError> {
        let url = config.url;
        let mut tls_config = rustls::ClientConfig::new();

        // Advertise support for HTTP/2
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Mozilla CA root store
        tls_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        Ok(Agent {
            url: reqwest::Url::parse(&url)
                .and_then(|url| url.join("api/v1/"))
                .map_err(|_| AgentError::InvalidReplicaUrl(url.clone()))?,
            client: reqwest::Client::builder()
                .use_preconfigured_tls(tls_config)
                .build()
                .expect("Could not create HTTP client."),
            nonce_factory: config.nonce_factory,
            identity: config.identity,
            default_waiter: config.default_waiter,
            password_manager: config.password_manager,
        })
    }

    fn construct_message(&self, request_id: &RequestId) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(DOMAIN_SEPARATOR);
        buf.extend_from_slice(request_id.as_slice());
        buf
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
            .map_err(AgentError::from)?;

        let http_status = response.status();
        let response_headers = response.headers().clone();
        let bytes = response.bytes().await?.to_vec();

        Ok((http_status, response_headers, bytes))
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

    async fn execute<T: std::fmt::Debug + serde::Serialize>(
        &self,
        method: Method,
        endpoint: &str,
        envelope: Option<Envelope<T>>,
    ) -> Result<Vec<u8>, AgentError> {
        let mut body = None;
        if let Some(e) = envelope {
            let mut serialized_bytes = Vec::new();

            let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
            serializer.self_describe()?;
            e.serialize(&mut serializer)?;

            body = Some(serialized_bytes);
        }

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
            Err(AgentError::HttpError {
                status: status.into(),
                content_type: headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|x| x.to_string()),
                content: body,
            })
        } else {
            Ok(body)
        }
    }

    async fn read<A>(&self, request: SyncContent) -> Result<A, AgentError>
    where
        A: serde::de::DeserializeOwned,
    {
        let anonymous = Principal::anonymous();
        let request_id = to_request_id(&request)?;
        let sender = match &request {
            SyncContent::QueryRequest { sender, .. } => sender,
            SyncContent::RequestStatusRequest { .. } => &anonymous,
        };
        let msg = self.construct_message(&request_id);
        let signature = self
            .identity
            .sign(&msg, &sender)
            .map_err(AgentError::SigningError)?;
        let bytes = self
            .execute(
                Method::POST,
                "read",
                Some(Envelope {
                    content: request,
                    sender_pubkey: signature.public_key,
                    sender_sig: signature.signature,
                }),
            )
            .await?;

        serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)
    }

    async fn submit(&self, request: AsyncContent) -> Result<RequestId, AgentError> {
        let request_id = to_request_id(&request)?;
        let sender = match request.clone() {
            AsyncContent::CallRequest { sender, .. } => sender,
        };
        let msg = self.construct_message(&request_id);
        let signature = self
            .identity
            .sign(&msg, &sender)
            .map_err(AgentError::SigningError)?;
        let _ = self
            .execute(
                Method::POST,
                "submit",
                Some(Envelope {
                    content: request,
                    sender_pubkey: signature.public_key,
                    sender_sig: signature.signature,
                }),
            )
            .await?;

        Ok(request_id)
    }

    /// The simplest form of query; sends a blob and will return a blob. The encoding is
    /// left as an exercise to the user.
    pub async fn query(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        self.read::<replica_api::QueryResponse>(SyncContent::QueryRequest {
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            canister_id: canister_id.clone(),
            method_name: method_name.to_string(),
            arg: arg.to_vec(),
        })
        .await
        .and_then(|response| match response {
            replica_api::QueryResponse::Replied { reply } => Ok(reply.arg),
            replica_api::QueryResponse::Rejected {
                reject_code,
                reject_message,
            } => Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }),
        })
    }

    pub async fn request_status(&self, request_id: &RequestId) -> Result<Replied, AgentError> {
        self.request_status_and_wait(request_id, self.default_waiter.clone())
            .await
    }

    pub async fn request_status_raw(
        &self,
        request_id: &RequestId,
    ) -> Result<RequestStatusResponse, AgentError> {
        self.read(SyncContent::RequestStatusRequest {
            request_id: request_id.as_slice().into(),
        })
        .await
        .map(|response| match response {
            replica_api::RequestStatusResponse::Replied { reply } => {
                let reply = match reply {
                    replica_api::RequestStatusResponseReplied::CallReply(reply) => {
                        Replied::CallReplied(reply.arg)
                    }
                };

                RequestStatusResponse::Replied { reply }
            }
            replica_api::RequestStatusResponse::Unknown {} => RequestStatusResponse::Unknown,
            replica_api::RequestStatusResponse::Received {} => RequestStatusResponse::Received,
            replica_api::RequestStatusResponse::Processing {} => RequestStatusResponse::Processing,
            replica_api::RequestStatusResponse::Rejected {
                reject_code,
                reject_message,
            } => RequestStatusResponse::Rejected {
                reject_code,
                reject_message,
            },
        })
    }

    pub async fn request_status_and_wait<W: delay::Waiter>(
        &self,
        request_id: &RequestId,
        mut waiter: W,
    ) -> Result<Replied, AgentError> {
        waiter.start();

        loop {
            match self.request_status_raw(request_id).await? {
                RequestStatusResponse::Replied { reply } => return Ok(reply),
                RequestStatusResponse::Rejected {
                    reject_code,
                    reject_message,
                } => {
                    return Err(AgentError::ReplicaError {
                        reject_code,
                        reject_message,
                    })
                }
                RequestStatusResponse::Unknown => (),
                RequestStatusResponse::Received => (),
                RequestStatusResponse::Processing => (),
            };

            waiter
                .wait()
                .map_err(|_| AgentError::TimeoutWaitingForResponse())?;
        }
    }

    pub async fn update_and_wait<W: delay::Waiter>(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: &[u8],
        waiter: W,
    ) -> Result<Vec<u8>, AgentError> {
        let request_id = self.update_raw(canister_id, method_name, arg).await?;
        match self.request_status_and_wait(&request_id, waiter).await? {
            Replied::CallReplied(arg) => Ok(arg),
        }
    }

    pub async fn update(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        self.update_and_wait(canister_id, method_name, arg, self.default_waiter.clone())
            .await
    }

    pub async fn update_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: &[u8],
    ) -> Result<RequestId, AgentError> {
        self.submit(AsyncContent::CallRequest {
            canister_id: canister_id.clone(),
            method_name: method_name.into(),
            arg: arg.to_vec(),
            nonce: self.nonce_factory.generate().map(|b| b.as_slice().into()),
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
        })
        .await
    }

    pub async fn status(&self) -> Result<Status, AgentError> {
        let bytes = self.execute::<()>(Method::GET, "status", None).await?;

        let cbor: serde_cbor::Value =
            serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)?;

        Status::try_from(&cbor).map_err(|_| AgentError::InvalidReplicaStatus)
    }
}
