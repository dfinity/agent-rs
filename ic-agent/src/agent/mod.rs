pub(crate) mod agent_config;
pub(crate) mod agent_error;
pub(crate) mod builder;
pub(crate) mod nonce;
pub(crate) mod replica_api;
pub(crate) mod response;

pub(crate) mod public {
    pub use super::agent_config::{AgentConfig, PasswordManager};
    pub use super::agent_error::AgentError;
    pub use super::builder::AgentBuilder;
    pub use super::nonce::NonceFactory;
    pub use super::response::{Replied, RequestStatusResponse};
    pub use super::{Agent, UpdateBuilder};
}

#[cfg(test)]
mod agent_test;

use crate::agent::replica_api::{AsyncContent, Envelope, SyncContent};
use crate::identity::Identity;
use crate::{to_request_id, Principal, RequestId, Status};
use delay::Waiter;
use reqwest::Method;
use serde::Serialize;

use public::*;
use std::convert::TryFrom;
use std::time::Duration;

const DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";

/// A low level Agent to make calls to a Replica endpoint.
///
/// ```ignore
/// # // This test is ignored because it requires an ic to be running. We run these
/// # // in the ic-ref workflow.
/// use ic_agent::{Agent, Principal};
/// use candid::{Encode, Decode, CandidType};
/// use serde::Deserialize;
///
/// #[derive(CandidType, Deserialize)]
/// struct CreateCanisterResult {
///   canister_id: candid::Principal,
/// }
///
/// # fn create_identity() -> impl ic_agent::Identity {
/// #     let rng = ring::rand::SystemRandom::new();
/// #     let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
/// #         .expect("Could not generate a key pair.");
/// #
/// #     ic_agent::BasicIdentity::from_key_pair(
/// #         ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
/// #           .expect("Could not read the key pair."),
/// #     )
/// # }
/// #
/// # const URL: &'static str = concat!("http://localhost:", env!("IC_REF_PORT"));
/// #
/// async fn create_a_canister() -> Result<Principal, Box<dyn std::error::Error>> {
///   let agent = Agent::builder()
///     .with_url(URL)
///     .with_identity(create_identity())
///     .build()?;
///   let management_canister_id = Principal::from_text("aaaaa-aa")?;
///
///   let waiter = delay::Delay::builder()
///     .throttle(std::time::Duration::from_millis(500))
///     .timeout(std::time::Duration::from_secs(60 * 5))
///     .build();
///
///   // Create a call to the management canister to create a new canister ID,
///   // and wait for a result.
///   let response = agent.update(&management_canister_id, "create_canister")
///     .with_arg(&Encode!()?)  // Empty Candid.
///     .call_and_wait(waiter)
///     .await?;
///
///   let result = Decode!(response.as_slice(), CreateCanisterResult)?;
///   let canister_id: Principal = Principal::from_text(&result.canister_id.to_text())?;
///   Ok(canister_id)
/// }
///
/// # let mut runtime = tokio::runtime::Runtime::new().unwrap();
/// # runtime.block_on(async {
/// let canister_id = create_a_canister().await.unwrap();
/// eprintln!("{}", canister_id);
/// # });
/// ```
///
/// This agent does not understand Candid, and only acts on byte buffers.
pub struct Agent {
    url: reqwest::Url,
    nonce_factory: NonceFactory,
    client: reqwest::Client,
    identity: Box<dyn Identity + Send + Sync>,
    password_manager: Option<Box<dyn PasswordManager + Send + Sync>>,
    ingress_expiry_duration: Duration,
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
            password_manager: config.password_manager,
            ingress_expiry_duration: config
                .ingress_expiry_duration
                .unwrap_or_else(|| Duration::from_secs(300)),
        })
    }

    fn get_expiry_date(&self) -> u64 {
        let permitted_drift = Duration::from_secs(60);
        (self.ingress_expiry_duration
            + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time wrapped around.")
            - permitted_drift)
            .as_nanos() as u64
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

    async fn read_endpoint<A>(&self, request: SyncContent) -> Result<A, AgentError>
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

    async fn submit_endpoint(&self, request: AsyncContent) -> Result<RequestId, AgentError> {
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

    /// The simplest way to do a query call; sends a byte array and will return a byte vector.
    /// The encoding is left as an exercise to the user.
    async fn query_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: &[u8],
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<Vec<u8>, AgentError> {
        self.read_endpoint::<replica_api::QueryResponse>(SyncContent::QueryRequest {
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            canister_id: canister_id.clone(),
            method_name: method_name.to_string(),
            arg: arg.to_vec(),
            ingress_expiry: ingress_expiry_datetime.unwrap_or_else(|| self.get_expiry_date()),
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

    /// The simplest way to do an update call; sends a byte array and will return a RequestId.
    /// The RequestId should then be used for request_status (most likely in a loop).
    async fn update_raw(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: &[u8],
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<RequestId, AgentError> {
        self.submit_endpoint(AsyncContent::CallRequest {
            canister_id: canister_id.clone(),
            method_name: method_name.into(),
            arg: arg.to_vec(),
            nonce: self.nonce_factory.generate().map(|b| b.as_slice().into()),
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            ingress_expiry: ingress_expiry_datetime.unwrap_or_else(|| self.get_expiry_date()),
        })
        .await
    }

    pub async fn request_status_raw(
        &self,
        request_id: &RequestId,
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<RequestStatusResponse, AgentError> {
        self.read_endpoint(SyncContent::RequestStatusRequest {
            request_id: request_id.as_slice().into(),
            ingress_expiry: ingress_expiry_datetime.unwrap_or_else(|| self.get_expiry_date()),
        })
        .await
        .map(|response| match response {
            replica_api::Status::Replied { reply } => {
                let reply = match reply {
                    replica_api::RequestStatusResponseReplied::CallReply(reply) => {
                        Replied::CallReplied(reply.arg)
                    }
                };
                RequestStatusResponse::Replied { reply }
            }
            replica_api::Status::Rejected {
                reject_code,
                reject_message,
            } => RequestStatusResponse::Rejected {
                reject_code,
                reject_message,
            },
            replica_api::Status::Unknown {} => RequestStatusResponse::Unknown,
            replica_api::Status::Received {} => RequestStatusResponse::Received,
            replica_api::Status::Processing {} => RequestStatusResponse::Processing,
            replica_api::Status::Done {} => RequestStatusResponse::Done,
        })
    }

    /// Returns an UpdateBuilder enabling the construction of an update call without
    /// passing all arguments.
    pub fn update<S: ToString>(&self, canister_id: &Principal, method_name: S) -> UpdateBuilder {
        UpdateBuilder::new(self, canister_id.clone(), method_name.to_string())
    }

    /// Calls and returns the information returned by the status endpoint of a replica.
    pub async fn status(&self) -> Result<Status, AgentError> {
        let bytes = self.execute::<()>(Method::GET, "status", None).await?;

        let cbor: serde_cbor::Value =
            serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)?;

        Status::try_from(&cbor).map_err(|_| AgentError::InvalidReplicaStatus)
    }

    /// Returns a QueryBuilder enabling the construction of a query call without
    /// passing all arguments.
    pub fn query<S: ToString>(&self, canister_id: &Principal, method_name: S) -> QueryBuilder {
        QueryBuilder::new(self, canister_id.clone(), method_name.to_string())
    }
}

/// A Query Request Builder.
///
/// This makes it easier to do query calls without actually passing all arguments.
pub struct QueryBuilder<'agent> {
    agent: &'agent Agent,
    canister_id: Principal,
    method_name: String,
    arg: Vec<u8>,
    ingress_expiry_datetime: Option<u64>,
}

impl<'agent> QueryBuilder<'agent> {
    pub fn new(agent: &'agent Agent, canister_id: Principal, method_name: String) -> Self {
        Self {
            agent,
            canister_id,
            method_name,
            arg: vec![],
            ingress_expiry_datetime: None,
        }
    }

    pub fn with_arg<A: AsRef<[u8]>>(&mut self, arg: A) -> &mut Self {
        self.arg = arg.as_ref().to_vec();
        self
    }

    /// Takes a SystemTime converts it to a Duration by calling
    /// duration_since(UNIX_EPOCH) to learn about where in time this SystemTime lies.
    /// The Duration is converted to nanoseconds and stored in ingress_expiry_datetime
    pub fn expire_at(&mut self, time: std::time::SystemTime) -> &mut Self {
        self.ingress_expiry_datetime = Some(
            time.duration_since(std::time::UNIX_EPOCH)
                .expect("Time wrapped around")
                .as_nanos() as u64,
        );
        self
    }

    /// Takes a Duration (i.e. 30 sec/5 min 30 sec/1 h 30 min, etc.) and adds it to the
    /// Duration of the current SystemTime since the UNIX_EPOCH
    /// Subtracts a permitted drift from the sum to account for using system time and not block time.
    /// Converts the difference to nanoseconds and stores in ingress_expiry_datetime
    pub fn expire_after(&mut self, duration: std::time::Duration) -> &mut Self {
        let permitted_drift = Duration::from_secs(60);
        self.ingress_expiry_datetime = Some(
            (duration
                + std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time wrapped around")
                - permitted_drift)
                .as_nanos() as u64,
        );
        self
    }

    /// Make a query call. This will return a byte vector.
    pub async fn call(&self) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query_raw(
                &self.canister_id,
                self.method_name.as_str(),
                self.arg.as_slice(),
                self.ingress_expiry_datetime,
            )
            .await
    }
}

/// An Update Request Builder.
///
/// This makes it easier to do update calls without actually passing all arguments or specifying
/// if you want to wait or not.
pub struct UpdateBuilder<'agent> {
    agent: &'agent Agent,
    canister_id: Principal,
    method_name: String,
    arg: Vec<u8>,
    ingress_expiry_datetime: Option<u64>,
}

impl<'agent> UpdateBuilder<'agent> {
    pub fn new(agent: &'agent Agent, canister_id: Principal, method_name: String) -> Self {
        Self {
            agent,
            canister_id,
            method_name,
            arg: vec![],
            ingress_expiry_datetime: None,
        }
    }

    pub fn with_arg<A: AsRef<[u8]>>(&mut self, arg: A) -> &mut Self {
        self.arg = arg.as_ref().to_vec();
        self
    }

    /// Takes a SystemTime converts it to a Duration by calling
    /// duration_since(UNIX_EPOCH) to learn about where in time this SystemTime lies.
    /// The Duration is converted to nanoseconds and stored in ingress_expiry_datetime
    pub fn expire_at(&mut self, time: std::time::SystemTime) -> &mut Self {
        self.ingress_expiry_datetime = Some(
            time.duration_since(std::time::UNIX_EPOCH)
                .expect("Time wrapped around")
                .as_nanos() as u64,
        );
        self
    }

    /// Takes a Duration (i.e. 30 sec/5 min 30 sec/1 h 30 min, etc.) and adds it to the
    /// Duration of the current SystemTime since the UNIX_EPOCH
    /// Subtracts a permitted drift from the sum to account for using system time and not block time.
    /// Converts the difference to nanoseconds and stores in ingress_expiry_datetime
    pub fn expire_after(&mut self, duration: std::time::Duration) -> &mut Self {
        let permitted_drift = Duration::from_secs(60);
        self.ingress_expiry_datetime = Some(
            (duration
                + std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time wrapped around")
                - permitted_drift)
                .as_nanos() as u64,
        );
        self
    }

    /// Make an update call. This will call request_status on the RequestId in a loop and return
    /// the response as a byte vector.
    pub async fn call_and_wait<W: Waiter>(&self, mut waiter: W) -> Result<Vec<u8>, AgentError> {
        let request_id = self
            .agent
            .update_raw(
                &self.canister_id,
                self.method_name.as_str(),
                self.arg.as_slice(),
                self.ingress_expiry_datetime,
            )
            .await?;
        waiter.start();

        loop {
            match self
                .agent
                .request_status_raw(&request_id, self.ingress_expiry_datetime)
                .await?
            {
                RequestStatusResponse::Replied {
                    reply: Replied::CallReplied(arg),
                } => return Ok(arg),
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
                RequestStatusResponse::Done => {
                    return Err(AgentError::RequestStatusDoneNoReply(String::from(
                        request_id,
                    )))
                }
            };

            waiter
                .wait()
                .map_err(|_| AgentError::TimeoutWaitingForResponse())?;
        }
    }

    /// Make an update call. This will return a RequestId.
    /// The RequestId should then be used for request_status (most likely in a loop).
    pub async fn call(&self) -> Result<RequestId, AgentError> {
        self.agent
            .update_raw(
                &self.canister_id,
                self.method_name.as_str(),
                self.arg.as_slice(),
                self.ingress_expiry_datetime,
            )
            .await
    }
}
