//! The main Agent module. Contains the [Agent] type and all associated structures.
pub(crate) mod agent_config;
pub mod agent_error;
pub(crate) mod builder;
// delete this module after 0.40
#[doc(hidden)]
#[deprecated(since = "0.38.0", note = "use the AgentBuilder methods")]
pub mod http_transport;
pub(crate) mod nonce;
pub(crate) mod response_authentication;
pub mod route_provider;
pub mod status;

pub use agent_config::AgentConfig;
pub use agent_error::AgentError;
use agent_error::{HttpErrorPayload, Operation};
use async_lock::Semaphore;
use async_trait::async_trait;
pub use builder::AgentBuilder;
use bytes::Bytes;
use cached::{Cached, TimedCache};
use http::{header::CONTENT_TYPE, HeaderMap, Method, StatusCode, Uri};
use ic_ed25519::{PublicKey, SignatureError};
#[doc(inline)]
pub use ic_transport_types::{
    signed, CallResponse, Envelope, EnvelopeContent, RejectCode, RejectResponse, ReplyResponse,
    RequestStatusResponse,
};
pub use nonce::{NonceFactory, NonceGenerator};
use rangemap::{RangeInclusiveMap, RangeInclusiveSet, StepFns};
use reqwest::{Client, Request, Response};
use route_provider::{
    dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderBuilder, node::Node,
        snapshot::latency_based_routing::LatencyRoutingSnapshot,
    },
    RouteProvider, UrlUntilReady,
};
use time::OffsetDateTime;
use tower_service::Service;

#[cfg(test)]
mod agent_test;

use crate::{
    agent::response_authentication::{
        extract_der, lookup_canister_info, lookup_canister_metadata, lookup_request_status,
        lookup_subnet, lookup_subnet_metrics, lookup_time, lookup_value,
    },
    export::Principal,
    identity::Identity,
    to_request_id, RequestId,
};
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use backoff::{exponential::ExponentialBackoff, SystemClock};
use ic_certification::{Certificate, Delegation, Label};
use ic_transport_types::{
    signed::{SignedQuery, SignedRequestStatus, SignedUpdate},
    QueryResponse, ReadStateResponse, SubnetMetrics, TransportCallResponse,
};
use serde::Serialize;
use status::Status;
use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryFrom,
    fmt::{self, Debug},
    future::{Future, IntoFuture},
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use crate::agent::response_authentication::lookup_api_boundary_nodes;

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

#[cfg(not(target_family = "wasm"))]
type AgentFuture<'a, V> = Pin<Box<dyn Future<Output = Result<V, AgentError>> + Send + 'a>>;

#[cfg(target_family = "wasm")]
type AgentFuture<'a, V> = Pin<Box<dyn Future<Output = Result<V, AgentError>> + 'a>>;

/// A low level Agent to make calls to a Replica endpoint.
///
/// ```ignore
/// # // This test is ignored because it requires an ic to be running. We run these
/// # // in the ic-ref workflow.
/// use ic_agent::{Agent, export::Principal};
/// use candid::{Encode, Decode, CandidType, Nat};
/// use serde::Deserialize;
///
/// #[derive(CandidType)]
/// struct Argument {
///   amount: Option<Nat>,
/// }
///
/// #[derive(CandidType, Deserialize)]
/// struct CreateCanisterResult {
///   canister_id: Principal,
/// }
///
/// # fn create_identity() -> impl ic_agent::Identity {
/// #     // In real code, the raw key should be either read from a pem file or generated with randomness.
/// #     ic_agent::identity::BasicIdentity::from_raw_key(&[0u8;32])
/// # }
/// #
/// async fn create_a_canister() -> Result<Principal, Box<dyn std::error::Error>> {
/// # let url = format!("http://localhost:{}", option_env!("IC_REF_PORT").unwrap_or("4943"));
///   let agent = Agent::builder()
///     .with_url(url)
///     .with_identity(create_identity())
///     .build()?;
///
///   // Only do the following call when not contacting the IC main net (e.g. a local emulator).
///   // This is important as the main net public key is static and a rogue network could return
///   // a different key.
///   // If you know the root key ahead of time, you can use `agent.set_root_key(root_key);`.
///   agent.fetch_root_key().await?;
///   let management_canister_id = Principal::from_text("aaaaa-aa")?;
///
///   // Create a call to the management canister to create a new canister ID,
///   // and wait for a result.
///   // The effective canister id must belong to the canister ranges of the subnet at which the canister is created.
///   let effective_canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
///   let response = agent.update(&management_canister_id, "provisional_create_canister_with_cycles")
///     .with_effective_canister_id(effective_canister_id)
///     .with_arg(Encode!(&Argument { amount: None })?)
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
///
/// Some methods return certificates. While there is a `verify_certificate` method, any certificate
/// you receive from a method has already been verified and you do not need to manually verify it.
#[derive(Clone)]
pub struct Agent {
    nonce_factory: Arc<dyn NonceGenerator>,
    identity: Arc<dyn Identity>,
    ingress_expiry: Duration,
    root_key: Arc<RwLock<Vec<u8>>>,
    client: Arc<dyn HttpService>,
    route_provider: Arc<dyn RouteProvider>,
    subnet_key_cache: Arc<Mutex<SubnetCache>>,
    concurrent_requests_semaphore: Arc<Semaphore>,
    verify_query_signatures: bool,
    max_response_body_size: Option<usize>,
    max_polling_time: Duration,
    #[allow(dead_code)]
    max_tcp_error_retries: usize,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("Agent")
            .field("ingress_expiry", &self.ingress_expiry)
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Create an instance of an [`AgentBuilder`] for building an [`Agent`]. This is simpler than
    /// using the [`AgentConfig`] and [`Agent::new()`].
    pub fn builder() -> builder::AgentBuilder {
        Default::default()
    }

    /// Create an instance of an [`Agent`].
    pub fn new(config: agent_config::AgentConfig) -> Result<Agent, AgentError> {
        let client = config.http_service.unwrap_or_else(|| {
            Arc::new(Retry429Logic {
                client: config.client.unwrap_or_else(|| {
                    #[cfg(not(target_family = "wasm"))]
                    {
                        Client::builder()
                            .use_rustls_tls()
                            .timeout(Duration::from_secs(360))
                            .build()
                            .expect("Could not create HTTP client.")
                    }
                    #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
                    {
                        Client::new()
                    }
                }),
            })
        });
        Ok(Agent {
            nonce_factory: config.nonce_factory,
            identity: config.identity,
            ingress_expiry: config.ingress_expiry,
            root_key: Arc::new(RwLock::new(IC_ROOT_KEY.to_vec())),
            client: client.clone(),
            route_provider: if let Some(route_provider) = config.route_provider {
                route_provider
            } else if let Some(url) = config.url {
                if config.background_dynamic_routing {
                    assert!(
                        url.scheme() == "https" && url.path() == "/" && url.port().is_none() && url.domain().is_some(),
                        "in dynamic routing mode, URL must be in the exact form https://domain with no path, port, IP, or non-HTTPS scheme"
                    );
                    let seeds = vec![Node::new(url.domain().unwrap()).unwrap()];
                    UrlUntilReady::new(url, async move {
                        DynamicRouteProviderBuilder::new(
                            LatencyRoutingSnapshot::new(),
                            seeds,
                            client,
                        )
                        .build()
                        .await
                    }) as Arc<dyn RouteProvider>
                } else {
                    Arc::new(url)
                }
            } else {
                panic!("either route_provider or url must be specified");
            },
            subnet_key_cache: Arc::new(Mutex::new(SubnetCache::new())),
            verify_query_signatures: config.verify_query_signatures,
            concurrent_requests_semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            max_response_body_size: config.max_response_body_size,
            max_tcp_error_retries: config.max_tcp_error_retries,
            max_polling_time: config.max_polling_time,
        })
    }

    /// Set the identity provider for signing messages.
    ///
    /// NOTE: if you change the identity while having update calls in
    /// flight, you will not be able to [`Agent::request_status_raw`] the status of these
    /// messages.
    pub fn set_identity<I>(&mut self, identity: I)
    where
        I: 'static + Identity,
    {
        self.identity = Arc::new(identity);
    }
    /// Set the arc identity provider for signing messages.
    ///
    /// NOTE: if you change the identity while having update calls in
    /// flight, you will not be able to [`Agent::request_status_raw`] the status of these
    /// messages.
    pub fn set_arc_identity(&mut self, identity: Arc<dyn Identity>) {
        self.identity = identity;
    }

    /// By default, the agent is configured to talk to the main Internet Computer, and verifies
    /// responses using a hard-coded public key.
    ///
    /// This function will instruct the agent to ask the endpoint for its public key, and use
    /// that instead. This is required when talking to a local test instance, for example.
    ///
    /// *Only use this when you are  _not_ talking to the main Internet Computer, otherwise
    /// you are prone to man-in-the-middle attacks! Do not call this function by default.*
    pub async fn fetch_root_key(&self) -> Result<(), AgentError> {
        if self.read_root_key()[..] != IC_ROOT_KEY[..] {
            // already fetched the root key
            return Ok(());
        }
        let status = self.status().await?;
        let Some(root_key) = status.root_key else {
            return Err(AgentError::NoRootKeyInStatus(status));
        };
        self.set_root_key(root_key);
        Ok(())
    }

    /// By default, the agent is configured to talk to the main Internet Computer, and verifies
    /// responses using a hard-coded public key.
    ///
    /// Using this function you can set the root key to a known one if you know if beforehand.
    pub fn set_root_key(&self, root_key: Vec<u8>) {
        *self.root_key.write().unwrap() = root_key;
    }

    /// Return the root key currently in use.
    pub fn read_root_key(&self) -> Vec<u8> {
        self.root_key.read().unwrap().clone()
    }

    fn get_expiry_date(&self) -> u64 {
        let expiry_raw = OffsetDateTime::now_utc() + self.ingress_expiry;
        let mut rounded = expiry_raw.replace_nanosecond(0).unwrap();
        if self.ingress_expiry.as_secs() > 90 {
            rounded = rounded.replace_second(0).unwrap();
        }
        rounded.unix_timestamp_nanos().try_into().unwrap()
    }

    /// Return the principal of the identity.
    pub fn get_principal(&self) -> Result<Principal, String> {
        self.identity.sender()
    }

    async fn query_endpoint<A>(
        &self,
        effective_canister_id: Principal,
        serialized_bytes: Vec<u8>,
    ) -> Result<A, AgentError>
    where
        A: serde::de::DeserializeOwned,
    {
        let _permit = self.concurrent_requests_semaphore.acquire().await;
        let bytes = self
            .execute(
                Method::POST,
                &format!("api/v2/canister/{}/query", effective_canister_id.to_text()),
                Some(serialized_bytes),
            )
            .await?
            .1;
        serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)
    }

    async fn read_state_endpoint<A>(
        &self,
        effective_canister_id: Principal,
        serialized_bytes: Vec<u8>,
    ) -> Result<A, AgentError>
    where
        A: serde::de::DeserializeOwned,
    {
        let _permit = self.concurrent_requests_semaphore.acquire().await;
        let endpoint = format!(
            "api/v2/canister/{}/read_state",
            effective_canister_id.to_text()
        );
        let bytes = self
            .execute(Method::POST, &endpoint, Some(serialized_bytes))
            .await?
            .1;
        serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)
    }

    async fn read_subnet_state_endpoint<A>(
        &self,
        subnet_id: Principal,
        serialized_bytes: Vec<u8>,
    ) -> Result<A, AgentError>
    where
        A: serde::de::DeserializeOwned,
    {
        let _permit = self.concurrent_requests_semaphore.acquire().await;
        let endpoint = format!("api/v2/subnet/{}/read_state", subnet_id.to_text());
        let bytes = self
            .execute(Method::POST, &endpoint, Some(serialized_bytes))
            .await?
            .1;
        serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)
    }

    async fn call_endpoint(
        &self,
        effective_canister_id: Principal,
        serialized_bytes: Vec<u8>,
    ) -> Result<TransportCallResponse, AgentError> {
        let _permit = self.concurrent_requests_semaphore.acquire().await;
        let endpoint = format!("api/v3/canister/{}/call", effective_canister_id.to_text());
        let (status_code, response_body) = self
            .execute(Method::POST, &endpoint, Some(serialized_bytes))
            .await?;

        if status_code == StatusCode::ACCEPTED {
            return Ok(TransportCallResponse::Accepted);
        }

        serde_cbor::from_slice(&response_body).map_err(AgentError::InvalidCborData)
    }

    /// The simplest way to do a query call; sends a byte array and will return a byte vector.
    /// The encoding is left as an exercise to the user.
    #[allow(clippy::too_many_arguments)]
    async fn query_raw(
        &self,
        canister_id: Principal,
        effective_canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry_datetime: Option<u64>,
        use_nonce: bool,
        explicit_verify_query_signatures: Option<bool>,
    ) -> Result<Vec<u8>, AgentError> {
        let operation = Operation::Call {
            canister: canister_id,
            method: method_name.clone(),
        };
        let content = self.query_content(
            canister_id,
            method_name,
            arg,
            ingress_expiry_datetime,
            use_nonce,
        )?;
        let serialized_bytes = sign_envelope(&content, self.identity.clone())?;
        self.query_inner(
            effective_canister_id,
            serialized_bytes,
            content.to_request_id(),
            explicit_verify_query_signatures,
            operation,
        )
        .await
    }

    /// Send the signed query to the network. Will return a byte vector.
    /// The bytes will be checked if it is a valid query.
    /// If you want to inspect the fields of the query call, use [`signed_query_inspect`] before calling this method.
    pub async fn query_signed(
        &self,
        effective_canister_id: Principal,
        signed_query: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        let envelope: Envelope =
            serde_cbor::from_slice(&signed_query).map_err(AgentError::InvalidCborData)?;
        let EnvelopeContent::Query {
            canister_id,
            method_name,
            ..
        } = &*envelope.content
        else {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "query".to_string(),
                value_cbor: if matches!(*envelope.content, EnvelopeContent::Call { .. }) {
                    "update"
                } else {
                    "read_state"
                }
                .to_string(),
            });
        };
        let operation = Operation::Call {
            canister: *canister_id,
            method: method_name.clone(),
        };
        self.query_inner(
            effective_canister_id,
            signed_query,
            envelope.content.to_request_id(),
            None,
            operation,
        )
        .await
    }

    /// Helper function for performing both the query call and possibly a `read_state` to check the subnet node keys.
    ///
    /// This should be used instead of `query_endpoint`. No validation is performed on `signed_query`.
    async fn query_inner(
        &self,
        effective_canister_id: Principal,
        signed_query: Vec<u8>,
        request_id: RequestId,
        explicit_verify_query_signatures: Option<bool>,
        operation: Operation,
    ) -> Result<Vec<u8>, AgentError> {
        let response = if explicit_verify_query_signatures.unwrap_or(self.verify_query_signatures) {
            let (response, mut subnet) = futures_util::try_join!(
                self.query_endpoint::<QueryResponse>(effective_canister_id, signed_query),
                self.get_subnet_by_canister(&effective_canister_id)
            )?;
            if response.signatures().is_empty() {
                return Err(AgentError::MissingSignature);
            } else if response.signatures().len() > subnet.node_keys.len() {
                return Err(AgentError::TooManySignatures {
                    had: response.signatures().len(),
                    needed: subnet.node_keys.len(),
                });
            }
            for signature in response.signatures() {
                if OffsetDateTime::now_utc()
                    - OffsetDateTime::from_unix_timestamp_nanos(signature.timestamp.into()).unwrap()
                    > self.ingress_expiry
                {
                    return Err(AgentError::CertificateOutdated(self.ingress_expiry));
                }
                let signable = response.signable(request_id, signature.timestamp);
                let node_key = if let Some(node_key) = subnet.node_keys.get(&signature.identity) {
                    node_key
                } else {
                    subnet = self
                        .fetch_subnet_by_canister(&effective_canister_id)
                        .await?;
                    subnet
                        .node_keys
                        .get(&signature.identity)
                        .ok_or(AgentError::CertificateNotAuthorized())?
                };
                if node_key.len() != 44 {
                    return Err(AgentError::DerKeyLengthMismatch {
                        expected: 44,
                        actual: node_key.len(),
                    });
                }
                const DER_PREFIX: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];
                if node_key[..12] != DER_PREFIX {
                    return Err(AgentError::DerPrefixMismatch {
                        expected: DER_PREFIX.to_vec(),
                        actual: node_key[..12].to_vec(),
                    });
                }
                let pubkey = PublicKey::deserialize_raw(&node_key[12..])
                    .map_err(|_| AgentError::MalformedPublicKey)?;

                match pubkey.verify_signature(&signable, &signature.signature[..]) {
                    Ok(()) => (),
                    Err(SignatureError::InvalidSignature) => {
                        return Err(AgentError::QuerySignatureVerificationFailed)
                    }
                    Err(SignatureError::InvalidLength) => {
                        return Err(AgentError::MalformedSignature)
                    }
                    _ => unreachable!(),
                }
            }
            response
        } else {
            self.query_endpoint::<QueryResponse>(effective_canister_id, signed_query)
                .await?
        };

        match response {
            QueryResponse::Replied { reply, .. } => Ok(reply.arg),
            QueryResponse::Rejected { reject, .. } => Err(AgentError::UncertifiedReject {
                reject,
                operation: Some(operation),
            }),
        }
    }

    fn query_content(
        &self,
        canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry_datetime: Option<u64>,
        use_nonce: bool,
    ) -> Result<EnvelopeContent, AgentError> {
        Ok(EnvelopeContent::Query {
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            canister_id,
            method_name,
            arg,
            ingress_expiry: ingress_expiry_datetime.unwrap_or_else(|| self.get_expiry_date()),
            nonce: use_nonce.then(|| self.nonce_factory.generate()).flatten(),
        })
    }

    /// The simplest way to do an update call; sends a byte array and will return a response, [`CallResponse`], from the replica.
    async fn update_raw(
        &self,
        canister_id: Principal,
        effective_canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<CallResponse<(Vec<u8>, Certificate)>, AgentError> {
        let nonce = self.nonce_factory.generate();
        let content = self.update_content(
            canister_id,
            method_name.clone(),
            arg,
            ingress_expiry_datetime,
            nonce,
        )?;
        let operation = Some(Operation::Call {
            canister: canister_id,
            method: method_name,
        });
        let request_id = to_request_id(&content)?;
        let serialized_bytes = sign_envelope(&content, self.identity.clone())?;

        let response_body = self
            .call_endpoint(effective_canister_id, serialized_bytes)
            .await?;

        match response_body {
            TransportCallResponse::Replied { certificate } => {
                let certificate =
                    serde_cbor::from_slice(&certificate).map_err(AgentError::InvalidCborData)?;

                self.verify(&certificate, effective_canister_id)?;
                let status = lookup_request_status(&certificate, &request_id)?;

                match status {
                    RequestStatusResponse::Replied(reply) => {
                        Ok(CallResponse::Response((reply.arg, certificate)))
                    }
                    RequestStatusResponse::Rejected(reject_response) => {
                        Err(AgentError::CertifiedReject {
                            reject: reject_response,
                            operation,
                        })?
                    }
                    _ => Ok(CallResponse::Poll(request_id)),
                }
            }
            TransportCallResponse::Accepted => Ok(CallResponse::Poll(request_id)),
            TransportCallResponse::NonReplicatedRejection(reject_response) => {
                Err(AgentError::UncertifiedReject {
                    reject: reject_response,
                    operation,
                })
            }
        }
    }

    /// Send the signed update to the network. Will return a [`CallResponse<Vec<u8>>`].
    /// The bytes will be checked to verify that it is a valid update.
    /// If you want to inspect the fields of the update, use [`signed_update_inspect`] before calling this method.
    pub async fn update_signed(
        &self,
        effective_canister_id: Principal,
        signed_update: Vec<u8>,
    ) -> Result<CallResponse<Vec<u8>>, AgentError> {
        let envelope: Envelope =
            serde_cbor::from_slice(&signed_update).map_err(AgentError::InvalidCborData)?;
        let EnvelopeContent::Call {
            canister_id,
            method_name,
            ..
        } = &*envelope.content
        else {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "update".to_string(),
                value_cbor: if matches!(*envelope.content, EnvelopeContent::Query { .. }) {
                    "query"
                } else {
                    "read_state"
                }
                .to_string(),
            });
        };
        let operation = Some(Operation::Call {
            canister: *canister_id,
            method: method_name.clone(),
        });
        let request_id = to_request_id(&envelope.content)?;

        let response_body = self
            .call_endpoint(effective_canister_id, signed_update)
            .await?;

        match response_body {
            TransportCallResponse::Replied { certificate } => {
                let certificate =
                    serde_cbor::from_slice(&certificate).map_err(AgentError::InvalidCborData)?;

                self.verify(&certificate, effective_canister_id)?;
                let status = lookup_request_status(&certificate, &request_id)?;

                match status {
                    RequestStatusResponse::Replied(reply) => Ok(CallResponse::Response(reply.arg)),
                    RequestStatusResponse::Rejected(reject_response) => {
                        Err(AgentError::CertifiedReject {
                            reject: reject_response,
                            operation,
                        })?
                    }
                    _ => Ok(CallResponse::Poll(request_id)),
                }
            }
            TransportCallResponse::Accepted => Ok(CallResponse::Poll(request_id)),
            TransportCallResponse::NonReplicatedRejection(reject_response) => {
                Err(AgentError::UncertifiedReject {
                    reject: reject_response,
                    operation,
                })
            }
        }
    }

    fn update_content(
        &self,
        canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry_datetime: Option<u64>,
        nonce: Option<Vec<u8>>,
    ) -> Result<EnvelopeContent, AgentError> {
        Ok(EnvelopeContent::Call {
            canister_id,
            method_name,
            arg,
            nonce,
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            ingress_expiry: ingress_expiry_datetime.unwrap_or_else(|| self.get_expiry_date()),
        })
    }

    fn get_retry_policy(&self) -> ExponentialBackoff<SystemClock> {
        ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(500))
            .with_max_interval(Duration::from_secs(1))
            .with_multiplier(1.4)
            .with_max_elapsed_time(Some(self.max_polling_time))
            .build()
    }

    /// Wait for `request_status` to return a Replied response and return the arg.
    pub async fn wait_signed(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
        signed_request_status: Vec<u8>,
    ) -> Result<(Vec<u8>, Certificate), AgentError> {
        let mut retry_policy = self.get_retry_policy();

        let mut request_accepted = false;
        let (resp, cert) = self
            .request_status_signed(
                request_id,
                effective_canister_id,
                signed_request_status.clone(),
            )
            .await?;
        loop {
            match resp {
                RequestStatusResponse::Unknown => {}

                RequestStatusResponse::Received | RequestStatusResponse::Processing => {
                    if !request_accepted {
                        retry_policy.reset();
                        request_accepted = true;
                    }
                }

                RequestStatusResponse::Replied(ReplyResponse { arg, .. }) => {
                    return Ok((arg, cert))
                }

                RequestStatusResponse::Rejected(response) => {
                    return Err(AgentError::CertifiedReject {
                        reject: response,
                        operation: None,
                    })
                }

                RequestStatusResponse::Done => {
                    return Err(AgentError::RequestStatusDoneNoReply(String::from(
                        *request_id,
                    )))
                }
            };

            match retry_policy.next_backoff() {
                Some(duration) => crate::util::sleep(duration).await,

                None => return Err(AgentError::TimeoutWaitingForResponse()),
            }
        }
    }

    /// Call `request_status` on the `RequestId` in a loop and return the response as a byte vector.
    pub async fn wait(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
    ) -> Result<(Vec<u8>, Certificate), AgentError> {
        self.wait_inner(request_id, effective_canister_id, None)
            .await
    }

    async fn wait_inner(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
        operation: Option<Operation>,
    ) -> Result<(Vec<u8>, Certificate), AgentError> {
        let mut retry_policy = self.get_retry_policy();

        let mut request_accepted = false;
        loop {
            let (resp, cert) = self
                .request_status_raw(request_id, effective_canister_id)
                .await?;
            match resp {
                RequestStatusResponse::Unknown => {}

                RequestStatusResponse::Received | RequestStatusResponse::Processing => {
                    if !request_accepted {
                        // The system will return RequestStatusResponse::Unknown
                        // until the request is accepted
                        // and we generally cannot know how long that will take.
                        // State transitions between Received and Processing may be
                        // instantaneous. Therefore, once we know the request is accepted,
                        // we should restart the backoff so the request does not time out.

                        retry_policy.reset();
                        request_accepted = true;
                    }
                }

                RequestStatusResponse::Replied(ReplyResponse { arg, .. }) => {
                    return Ok((arg, cert))
                }

                RequestStatusResponse::Rejected(response) => {
                    return Err(AgentError::CertifiedReject {
                        reject: response,
                        operation,
                    })
                }

                RequestStatusResponse::Done => {
                    return Err(AgentError::RequestStatusDoneNoReply(String::from(
                        *request_id,
                    )))
                }
            };

            match retry_policy.next_backoff() {
                Some(duration) => crate::util::sleep(duration).await,

                None => return Err(AgentError::TimeoutWaitingForResponse()),
            }
        }
    }

    /// Request the raw state tree directly, under an effective canister ID.
    /// See [the protocol docs](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state) for more information.
    pub async fn read_state_raw(
        &self,
        paths: Vec<Vec<Label>>,
        effective_canister_id: Principal,
    ) -> Result<Certificate, AgentError> {
        let content = self.read_state_content(paths)?;
        let serialized_bytes = sign_envelope(&content, self.identity.clone())?;

        let read_state_response: ReadStateResponse = self
            .read_state_endpoint(effective_canister_id, serialized_bytes)
            .await?;
        let cert: Certificate = serde_cbor::from_slice(&read_state_response.certificate)
            .map_err(AgentError::InvalidCborData)?;
        self.verify(&cert, effective_canister_id)?;
        Ok(cert)
    }

    /// Request the raw state tree directly, under a subnet ID.
    /// See [the protocol docs](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state) for more information.
    pub async fn read_subnet_state_raw(
        &self,
        paths: Vec<Vec<Label>>,
        subnet_id: Principal,
    ) -> Result<Certificate, AgentError> {
        let content = self.read_state_content(paths)?;
        let serialized_bytes = sign_envelope(&content, self.identity.clone())?;

        let read_state_response: ReadStateResponse = self
            .read_subnet_state_endpoint(subnet_id, serialized_bytes)
            .await?;
        let cert: Certificate = serde_cbor::from_slice(&read_state_response.certificate)
            .map_err(AgentError::InvalidCborData)?;
        self.verify_for_subnet(&cert, subnet_id)?;
        Ok(cert)
    }

    fn read_state_content(&self, paths: Vec<Vec<Label>>) -> Result<EnvelopeContent, AgentError> {
        Ok(EnvelopeContent::ReadState {
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            paths,
            ingress_expiry: self.get_expiry_date(),
        })
    }

    /// Verify a certificate, checking delegation if present.
    /// Only passes if the certificate also has authority over the canister.
    pub fn verify(
        &self,
        cert: &Certificate,
        effective_canister_id: Principal,
    ) -> Result<(), AgentError> {
        self.verify_cert(cert, effective_canister_id)?;
        self.verify_cert_timestamp(cert)?;
        Ok(())
    }

    fn verify_cert(
        &self,
        cert: &Certificate,
        effective_canister_id: Principal,
    ) -> Result<(), AgentError> {
        let sig = &cert.signature;

        let root_hash = cert.tree.digest();
        let mut msg = vec![];
        msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
        msg.extend_from_slice(&root_hash);

        let der_key = self.check_delegation(&cert.delegation, effective_canister_id)?;
        let key = extract_der(der_key)?;

        ic_verify_bls_signature::verify_bls_signature(sig, &msg, &key)
            .map_err(|_| AgentError::CertificateVerificationFailed())?;
        Ok(())
    }

    /// Verify a certificate, checking delegation if present.
    /// Only passes if the certificate is for the specified subnet.
    pub fn verify_for_subnet(
        &self,
        cert: &Certificate,
        subnet_id: Principal,
    ) -> Result<(), AgentError> {
        self.verify_cert_for_subnet(cert, subnet_id)?;
        self.verify_cert_timestamp(cert)?;
        Ok(())
    }

    fn verify_cert_for_subnet(
        &self,
        cert: &Certificate,
        subnet_id: Principal,
    ) -> Result<(), AgentError> {
        let sig = &cert.signature;

        let root_hash = cert.tree.digest();
        let mut msg = vec![];
        msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
        msg.extend_from_slice(&root_hash);

        let der_key = self.check_delegation_for_subnet(&cert.delegation, subnet_id)?;
        let key = extract_der(der_key)?;

        ic_verify_bls_signature::verify_bls_signature(sig, &msg, &key)
            .map_err(|_| AgentError::CertificateVerificationFailed())?;
        Ok(())
    }

    fn verify_cert_timestamp(&self, cert: &Certificate) -> Result<(), AgentError> {
        let time = lookup_time(cert)?;
        if (OffsetDateTime::now_utc()
            - OffsetDateTime::from_unix_timestamp_nanos(time.into()).unwrap())
        .abs()
            > self.ingress_expiry
        {
            Err(AgentError::CertificateOutdated(self.ingress_expiry))
        } else {
            Ok(())
        }
    }

    fn check_delegation(
        &self,
        delegation: &Option<Delegation>,
        effective_canister_id: Principal,
    ) -> Result<Vec<u8>, AgentError> {
        match delegation {
            None => Ok(self.read_root_key()),
            Some(delegation) => {
                let cert: Certificate = serde_cbor::from_slice(&delegation.certificate)
                    .map_err(AgentError::InvalidCborData)?;
                if cert.delegation.is_some() {
                    return Err(AgentError::CertificateHasTooManyDelegations);
                }
                self.verify_cert(&cert, effective_canister_id)?;
                let canister_range_lookup = [
                    "subnet".as_bytes(),
                    delegation.subnet_id.as_ref(),
                    "canister_ranges".as_bytes(),
                ];
                let canister_range = lookup_value(&cert.tree, canister_range_lookup)?;
                let ranges: Vec<(Principal, Principal)> =
                    serde_cbor::from_slice(canister_range).map_err(AgentError::InvalidCborData)?;
                if !principal_is_within_ranges(&effective_canister_id, &ranges[..]) {
                    // the certificate is not authorized to answer calls for this canister
                    return Err(AgentError::CertificateNotAuthorized());
                }

                let public_key_path = [
                    "subnet".as_bytes(),
                    delegation.subnet_id.as_ref(),
                    "public_key".as_bytes(),
                ];
                lookup_value(&cert.tree, public_key_path).map(<[u8]>::to_vec)
            }
        }
    }

    fn check_delegation_for_subnet(
        &self,
        delegation: &Option<Delegation>,
        subnet_id: Principal,
    ) -> Result<Vec<u8>, AgentError> {
        match delegation {
            None => Ok(self.read_root_key()),
            Some(delegation) => {
                let cert: Certificate = serde_cbor::from_slice(&delegation.certificate)
                    .map_err(AgentError::InvalidCborData)?;
                if cert.delegation.is_some() {
                    return Err(AgentError::CertificateHasTooManyDelegations);
                }
                self.verify_cert_for_subnet(&cert, subnet_id)?;
                let public_key_path = [
                    "subnet".as_bytes(),
                    delegation.subnet_id.as_ref(),
                    "public_key".as_bytes(),
                ];
                let pk = lookup_value(&cert.tree, public_key_path)
                    .map_err(|_| AgentError::CertificateNotAuthorized())?
                    .to_vec();
                Ok(pk)
            }
        }
    }

    /// Request information about a particular canister for a single state subkey.
    /// See [the protocol docs](https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree-canister-information) for more information.
    pub async fn read_state_canister_info(
        &self,
        canister_id: Principal,
        path: &str,
    ) -> Result<Vec<u8>, AgentError> {
        let paths: Vec<Vec<Label>> = vec![vec![
            "canister".into(),
            Label::from_bytes(canister_id.as_slice()),
            path.into(),
        ]];

        let cert = self.read_state_raw(paths, canister_id).await?;

        lookup_canister_info(cert, canister_id, path)
    }

    /// Request the controller list of a given canister.
    pub async fn read_state_canister_controllers(
        &self,
        canister_id: Principal,
    ) -> Result<Vec<Principal>, AgentError> {
        let blob = self
            .read_state_canister_info(canister_id, "controllers")
            .await?;
        let controllers: Vec<Principal> =
            serde_cbor::from_slice(&blob).map_err(AgentError::InvalidCborData)?;
        Ok(controllers)
    }

    /// Request the module hash of a given canister.
    pub async fn read_state_canister_module_hash(
        &self,
        canister_id: Principal,
    ) -> Result<Vec<u8>, AgentError> {
        self.read_state_canister_info(canister_id, "module_hash")
            .await
    }

    /// Request the bytes of the canister's custom section `icp:public <path>` or `icp:private <path>`.
    pub async fn read_state_canister_metadata(
        &self,
        canister_id: Principal,
        path: &str,
    ) -> Result<Vec<u8>, AgentError> {
        let paths: Vec<Vec<Label>> = vec![vec![
            "canister".into(),
            Label::from_bytes(canister_id.as_slice()),
            "metadata".into(),
            path.into(),
        ]];

        let cert = self.read_state_raw(paths, canister_id).await?;

        lookup_canister_metadata(cert, canister_id, path)
    }

    /// Request a list of metrics about the subnet.
    pub async fn read_state_subnet_metrics(
        &self,
        subnet_id: Principal,
    ) -> Result<SubnetMetrics, AgentError> {
        let paths = vec![vec![
            "subnet".into(),
            Label::from_bytes(subnet_id.as_slice()),
            "metrics".into(),
        ]];
        let cert = self.read_subnet_state_raw(paths, subnet_id).await?;
        lookup_subnet_metrics(cert, subnet_id)
    }

    /// Fetches the status of a particular request by its ID.
    pub async fn request_status_raw(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
    ) -> Result<(RequestStatusResponse, Certificate), AgentError> {
        let paths: Vec<Vec<Label>> =
            vec![vec!["request_status".into(), request_id.to_vec().into()]];

        let cert = self.read_state_raw(paths, effective_canister_id).await?;

        Ok((lookup_request_status(&cert, request_id)?, cert))
    }

    /// Send the signed `request_status` to the network. Will return [`RequestStatusResponse`].
    /// The bytes will be checked to verify that it is a valid `request_status`.
    /// If you want to inspect the fields of the `request_status`, use [`signed_request_status_inspect`] before calling this method.
    pub async fn request_status_signed(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
        signed_request_status: Vec<u8>,
    ) -> Result<(RequestStatusResponse, Certificate), AgentError> {
        let _envelope: Envelope =
            serde_cbor::from_slice(&signed_request_status).map_err(AgentError::InvalidCborData)?;
        let read_state_response: ReadStateResponse = self
            .read_state_endpoint(effective_canister_id, signed_request_status)
            .await?;

        let cert: Certificate = serde_cbor::from_slice(&read_state_response.certificate)
            .map_err(AgentError::InvalidCborData)?;
        self.verify(&cert, effective_canister_id)?;
        Ok((lookup_request_status(&cert, request_id)?, cert))
    }

    /// Returns an `UpdateBuilder` enabling the construction of an update call without
    /// passing all arguments.
    pub fn update<S: Into<String>>(
        &self,
        canister_id: &Principal,
        method_name: S,
    ) -> UpdateBuilder {
        UpdateBuilder::new(self, *canister_id, method_name.into())
    }

    /// Calls and returns the information returned by the status endpoint of a replica.
    pub async fn status(&self) -> Result<Status, AgentError> {
        let endpoint = "api/v2/status";
        let bytes = self.execute(Method::GET, endpoint, None).await?.1;

        let cbor: serde_cbor::Value =
            serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)?;

        Status::try_from(&cbor).map_err(|_| AgentError::InvalidReplicaStatus)
    }

    /// Returns a `QueryBuilder` enabling the construction of a query call without
    /// passing all arguments.
    pub fn query<S: Into<String>>(&self, canister_id: &Principal, method_name: S) -> QueryBuilder {
        QueryBuilder::new(self, *canister_id, method_name.into())
    }

    /// Sign a `request_status` call. This will return a [`signed::SignedRequestStatus`]
    /// which contains all fields of the `request_status` and the signed `request_status` in CBOR encoding
    pub fn sign_request_status(
        &self,
        effective_canister_id: Principal,
        request_id: RequestId,
    ) -> Result<SignedRequestStatus, AgentError> {
        let paths: Vec<Vec<Label>> =
            vec![vec!["request_status".into(), request_id.to_vec().into()]];
        let read_state_content = self.read_state_content(paths)?;
        let signed_request_status = sign_envelope(&read_state_content, self.identity.clone())?;
        let ingress_expiry = read_state_content.ingress_expiry();
        let sender = *read_state_content.sender();
        Ok(SignedRequestStatus {
            ingress_expiry,
            sender,
            effective_canister_id,
            request_id,
            signed_request_status,
        })
    }

    async fn get_subnet_by_canister(
        &self,
        canister: &Principal,
    ) -> Result<Arc<Subnet>, AgentError> {
        let subnet = self
            .subnet_key_cache
            .lock()
            .unwrap()
            .get_subnet_by_canister(canister);
        if let Some(subnet) = subnet {
            Ok(subnet)
        } else {
            self.fetch_subnet_by_canister(canister).await
        }
    }

    /// Retrieve all existing API boundary nodes from the state tree via endpoint `/api/v2/canister/<effective_canister_id>/read_state`
    pub async fn fetch_api_boundary_nodes_by_canister_id(
        &self,
        canister_id: Principal,
    ) -> Result<Vec<ApiBoundaryNode>, AgentError> {
        let paths = vec![vec!["api_boundary_nodes".into()]];
        let certificate = self.read_state_raw(paths, canister_id).await?;
        let api_boundary_nodes = lookup_api_boundary_nodes(certificate)?;
        Ok(api_boundary_nodes)
    }

    /// Retrieve all existing API boundary nodes from the state tree via endpoint `/api/v2/subnet/<subnet_id>/read_state`
    pub async fn fetch_api_boundary_nodes_by_subnet_id(
        &self,
        subnet_id: Principal,
    ) -> Result<Vec<ApiBoundaryNode>, AgentError> {
        let paths = vec![vec!["api_boundary_nodes".into()]];
        let certificate = self.read_subnet_state_raw(paths, subnet_id).await?;
        let api_boundary_nodes = lookup_api_boundary_nodes(certificate)?;
        Ok(api_boundary_nodes)
    }

    async fn fetch_subnet_by_canister(
        &self,
        canister: &Principal,
    ) -> Result<Arc<Subnet>, AgentError> {
        let cert = self
            .read_state_raw(vec![vec!["subnet".into()]], *canister)
            .await?;

        let (subnet_id, subnet) = lookup_subnet(&cert, &self.root_key.read().unwrap())?;
        let subnet = Arc::new(subnet);
        self.subnet_key_cache
            .lock()
            .unwrap()
            .insert_subnet(subnet_id, subnet.clone());
        Ok(subnet)
    }

    async fn request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), AgentError> {
        let body = body.map(Bytes::from);

        let create_request_with_generated_url = || -> Result<http::Request<Bytes>, AgentError> {
            let url = self.route_provider.route()?.join(endpoint)?;
            let uri = Uri::from_str(url.as_str())
                .map_err(|e| AgentError::InvalidReplicaUrl(e.to_string()))?;
            let body = body.clone().unwrap_or_default();
            let request = http::Request::builder()
                .method(method.clone())
                .uri(uri)
                .header(CONTENT_TYPE, "application/cbor")
                .body(body)
                .map_err(|e| {
                    AgentError::TransportError(format!("unable to create request: {e:#}"))
                })?;

            Ok(request)
        };

        let response = self
            .client
            .call(
                &create_request_with_generated_url,
                self.max_tcp_error_retries,
                self.max_response_body_size,
            )
            .await?;

        let (parts, body) = response.into_parts();

        Ok((parts.status, parts.headers, body.to_vec()))
    }

    async fn execute(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>), AgentError> {
        let request_result = self.request(method.clone(), endpoint, body.clone()).await?;

        let status = request_result.0;
        let headers = request_result.1;
        let body = request_result.2;

        if status.is_client_error() || status.is_server_error() {
            Err(AgentError::HttpError(HttpErrorPayload {
                status: status.into(),
                content_type: headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                content: body,
            }))
        } else if !(status == StatusCode::OK || status == StatusCode::ACCEPTED) {
            Err(AgentError::InvalidHttpResponse(format!(
                "Expected `200`, `202`, 4xx`, or `5xx` HTTP status code. Got: {status}",
            )))
        } else {
            Ok((status, body))
        }
    }
}

// Checks if a principal is contained within a list of principal ranges
// A range is a tuple: (low: Principal, high: Principal), as described here: https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree-subnet
fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|r| principal >= &r.0 && principal <= &r.1)
}

fn sign_envelope(
    content: &EnvelopeContent,
    identity: Arc<dyn Identity>,
) -> Result<Vec<u8>, AgentError> {
    let signature = identity.sign(content).map_err(AgentError::SigningError)?;

    let envelope = Envelope {
        content: Cow::Borrowed(content),
        sender_pubkey: signature.public_key,
        sender_sig: signature.signature,
        sender_delegation: signature.delegations,
    };

    let mut serialized_bytes = Vec::new();
    let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
    serializer.self_describe()?;
    envelope.serialize(&mut serializer)?;

    Ok(serialized_bytes)
}

/// Inspect the bytes to be sent as a query
/// Return Ok only when the bytes can be deserialized as a query and all fields match with the arguments
pub fn signed_query_inspect(
    sender: Principal,
    canister_id: Principal,
    method_name: &str,
    arg: &[u8],
    ingress_expiry: u64,
    signed_query: Vec<u8>,
) -> Result<(), AgentError> {
    let envelope: Envelope =
        serde_cbor::from_slice(&signed_query).map_err(AgentError::InvalidCborData)?;
    match envelope.content.as_ref() {
        EnvelopeContent::Query {
            ingress_expiry: ingress_expiry_cbor,
            sender: sender_cbor,
            canister_id: canister_id_cbor,
            method_name: method_name_cbor,
            arg: arg_cbor,
            nonce: _nonce,
        } => {
            if ingress_expiry != *ingress_expiry_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "ingress_expiry".to_string(),
                    value_arg: ingress_expiry.to_string(),
                    value_cbor: ingress_expiry_cbor.to_string(),
                });
            }
            if sender != *sender_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "sender".to_string(),
                    value_arg: sender.to_string(),
                    value_cbor: sender_cbor.to_string(),
                });
            }
            if canister_id != *canister_id_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "canister_id".to_string(),
                    value_arg: canister_id.to_string(),
                    value_cbor: canister_id_cbor.to_string(),
                });
            }
            if method_name != *method_name_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "method_name".to_string(),
                    value_arg: method_name.to_string(),
                    value_cbor: method_name_cbor.clone(),
                });
            }
            if arg != *arg_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "arg".to_string(),
                    value_arg: format!("{arg:?}"),
                    value_cbor: format!("{arg_cbor:?}"),
                });
            }
        }
        EnvelopeContent::Call { .. } => {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "query".to_string(),
                value_cbor: "call".to_string(),
            })
        }
        EnvelopeContent::ReadState { .. } => {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "query".to_string(),
                value_cbor: "read_state".to_string(),
            })
        }
    }
    Ok(())
}

/// Inspect the bytes to be sent as an update
/// Return Ok only when the bytes can be deserialized as an update and all fields match with the arguments
pub fn signed_update_inspect(
    sender: Principal,
    canister_id: Principal,
    method_name: &str,
    arg: &[u8],
    ingress_expiry: u64,
    signed_update: Vec<u8>,
) -> Result<(), AgentError> {
    let envelope: Envelope =
        serde_cbor::from_slice(&signed_update).map_err(AgentError::InvalidCborData)?;
    match envelope.content.as_ref() {
        EnvelopeContent::Call {
            nonce: _nonce,
            ingress_expiry: ingress_expiry_cbor,
            sender: sender_cbor,
            canister_id: canister_id_cbor,
            method_name: method_name_cbor,
            arg: arg_cbor,
        } => {
            if ingress_expiry != *ingress_expiry_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "ingress_expiry".to_string(),
                    value_arg: ingress_expiry.to_string(),
                    value_cbor: ingress_expiry_cbor.to_string(),
                });
            }
            if sender != *sender_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "sender".to_string(),
                    value_arg: sender.to_string(),
                    value_cbor: sender_cbor.to_string(),
                });
            }
            if canister_id != *canister_id_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "canister_id".to_string(),
                    value_arg: canister_id.to_string(),
                    value_cbor: canister_id_cbor.to_string(),
                });
            }
            if method_name != *method_name_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "method_name".to_string(),
                    value_arg: method_name.to_string(),
                    value_cbor: method_name_cbor.clone(),
                });
            }
            if arg != *arg_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "arg".to_string(),
                    value_arg: format!("{arg:?}"),
                    value_cbor: format!("{arg_cbor:?}"),
                });
            }
        }
        EnvelopeContent::ReadState { .. } => {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "call".to_string(),
                value_cbor: "read_state".to_string(),
            })
        }
        EnvelopeContent::Query { .. } => {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "call".to_string(),
                value_cbor: "query".to_string(),
            })
        }
    }
    Ok(())
}

/// Inspect the bytes to be sent as a `request_status`
/// Return Ok only when the bytes can be deserialized as a `request_status` and all fields match with the arguments
pub fn signed_request_status_inspect(
    sender: Principal,
    request_id: &RequestId,
    ingress_expiry: u64,
    signed_request_status: Vec<u8>,
) -> Result<(), AgentError> {
    let paths: Vec<Vec<Label>> = vec![vec!["request_status".into(), request_id.to_vec().into()]];
    let envelope: Envelope =
        serde_cbor::from_slice(&signed_request_status).map_err(AgentError::InvalidCborData)?;
    match envelope.content.as_ref() {
        EnvelopeContent::ReadState {
            ingress_expiry: ingress_expiry_cbor,
            sender: sender_cbor,
            paths: paths_cbor,
        } => {
            if ingress_expiry != *ingress_expiry_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "ingress_expiry".to_string(),
                    value_arg: ingress_expiry.to_string(),
                    value_cbor: ingress_expiry_cbor.to_string(),
                });
            }
            if sender != *sender_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "sender".to_string(),
                    value_arg: sender.to_string(),
                    value_cbor: sender_cbor.to_string(),
                });
            }

            if paths != *paths_cbor {
                return Err(AgentError::CallDataMismatch {
                    field: "paths".to_string(),
                    value_arg: format!("{paths:?}"),
                    value_cbor: format!("{paths_cbor:?}"),
                });
            }
        }
        EnvelopeContent::Query { .. } => {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "read_state".to_string(),
                value_cbor: "query".to_string(),
            })
        }
        EnvelopeContent::Call { .. } => {
            return Err(AgentError::CallDataMismatch {
                field: "request_type".to_string(),
                value_arg: "read_state".to_string(),
                value_cbor: "call".to_string(),
            })
        }
    }
    Ok(())
}

#[derive(Clone)]
struct SubnetCache {
    subnets: TimedCache<Principal, Arc<Subnet>>,
    canister_index: RangeInclusiveMap<Principal, Principal, PrincipalStep>,
}

impl SubnetCache {
    fn new() -> Self {
        Self {
            subnets: TimedCache::with_lifespan(300),
            canister_index: RangeInclusiveMap::new_with_step_fns(),
        }
    }

    fn get_subnet_by_canister(&mut self, canister: &Principal) -> Option<Arc<Subnet>> {
        self.canister_index
            .get(canister)
            .and_then(|subnet_id| self.subnets.cache_get(subnet_id).cloned())
            .filter(|subnet| subnet.canister_ranges.contains(canister))
    }

    fn insert_subnet(&mut self, subnet_id: Principal, subnet: Arc<Subnet>) {
        self.subnets.cache_set(subnet_id, subnet.clone());
        for range in subnet.canister_ranges.iter() {
            self.canister_index.insert(range.clone(), subnet_id);
        }
    }
}

#[derive(Clone, Copy)]
struct PrincipalStep;

impl StepFns<Principal> for PrincipalStep {
    fn add_one(start: &Principal) -> Principal {
        let bytes = start.as_slice();
        let mut arr = [0; 29];
        arr[..bytes.len()].copy_from_slice(bytes);
        for byte in arr[..bytes.len() - 1].iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        Principal::from_slice(&arr[..bytes.len()])
    }
    fn sub_one(start: &Principal) -> Principal {
        let bytes = start.as_slice();
        let mut arr = [0; 29];
        arr[..bytes.len()].copy_from_slice(bytes);
        for byte in arr[..bytes.len() - 1].iter_mut().rev() {
            *byte = byte.wrapping_sub(1);
            if *byte != 255 {
                break;
            }
        }
        Principal::from_slice(&arr[..bytes.len()])
    }
}

#[derive(Clone)]
pub(crate) struct Subnet {
    // This key is just fetched for completeness. Do not actually use this value as it is not authoritative in case of a rogue subnet.
    // If a future agent needs to know the subnet key then it should fetch /subnet from the *root* subnet.
    _key: Vec<u8>,
    node_keys: HashMap<Principal, Vec<u8>>,
    canister_ranges: RangeInclusiveSet<Principal, PrincipalStep>,
}

/// API boundary node, which routes /api calls to IC replica nodes.
#[derive(Debug, Clone)]
pub struct ApiBoundaryNode {
    /// Domain name
    pub domain: String,
    /// IPv6 address in the hexadecimal notation with colons.
    pub ipv6_address: String,
    /// IPv4 address in the dotted-decimal notation.
    pub ipv4_address: Option<String>,
}

/// A query request builder.
///
/// This makes it easier to do query calls without actually passing all arguments.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct QueryBuilder<'agent> {
    agent: &'agent Agent,
    /// The [effective canister ID](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-effective-canister-id) of the destination.
    pub effective_canister_id: Principal,
    /// The principal ID of the canister being called.
    pub canister_id: Principal,
    /// The name of the canister method being called.
    pub method_name: String,
    /// The argument blob to be passed to the method.
    pub arg: Vec<u8>,
    /// The Unix timestamp that the request will expire at.
    pub ingress_expiry_datetime: Option<u64>,
    /// Whether to include a nonce with the message.
    pub use_nonce: bool,
}

impl<'agent> QueryBuilder<'agent> {
    /// Creates a new query builder with an agent for a particular canister method.
    pub fn new(agent: &'agent Agent, canister_id: Principal, method_name: String) -> Self {
        Self {
            agent,
            effective_canister_id: canister_id,
            canister_id,
            method_name,
            arg: vec![],
            ingress_expiry_datetime: None,
            use_nonce: false,
        }
    }

    /// Sets the [effective canister ID](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-effective-canister-id) of the destination.
    pub fn with_effective_canister_id(mut self, canister_id: Principal) -> Self {
        self.effective_canister_id = canister_id;
        self
    }

    /// Sets the argument blob to pass to the canister. For most canisters this should be a Candid-serialized tuple.
    pub fn with_arg<A: Into<Vec<u8>>>(mut self, arg: A) -> Self {
        self.arg = arg.into();
        self
    }

    /// Sets `ingress_expiry_datetime` to the provided timestamp, at nanosecond precision.
    pub fn expire_at(mut self, time: impl Into<OffsetDateTime>) -> Self {
        self.ingress_expiry_datetime = Some(time.into().unix_timestamp_nanos() as u64);
        self
    }

    /// Sets `ingress_expiry_datetime` to `max(now, 4min)`.
    pub fn expire_after(mut self, duration: Duration) -> Self {
        self.ingress_expiry_datetime = Some(
            OffsetDateTime::now_utc()
                .saturating_add(duration.try_into().expect("negative duration"))
                .unix_timestamp_nanos() as u64,
        );
        self
    }

    /// Uses a nonce generated with the agent's configured nonce factory. By default queries do not use nonces,
    /// and thus may get a (briefly) cached response.
    pub fn with_nonce_generation(mut self) -> Self {
        self.use_nonce = true;
        self
    }

    /// Make a query call. This will return a byte vector.
    pub async fn call(self) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query_raw(
                self.canister_id,
                self.effective_canister_id,
                self.method_name,
                self.arg,
                self.ingress_expiry_datetime,
                self.use_nonce,
                None,
            )
            .await
    }

    /// Make a query call with signature verification. This will return a byte vector.
    ///
    /// Compared with [call][Self::call], this method will **always** verify the signature of the query response
    /// regardless the Agent level configuration from [`AgentBuilder::with_verify_query_signatures`].
    pub async fn call_with_verification(self) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query_raw(
                self.canister_id,
                self.effective_canister_id,
                self.method_name,
                self.arg,
                self.ingress_expiry_datetime,
                self.use_nonce,
                Some(true),
            )
            .await
    }

    /// Make a query call without signature verification. This will return a byte vector.
    ///
    /// Compared with [call][Self::call], this method will **never** verify the signature of the query response
    /// regardless the Agent level configuration from [`AgentBuilder::with_verify_query_signatures`].
    pub async fn call_without_verification(self) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query_raw(
                self.canister_id,
                self.effective_canister_id,
                self.method_name,
                self.arg,
                self.ingress_expiry_datetime,
                self.use_nonce,
                Some(false),
            )
            .await
    }

    /// Sign a query call. This will return a [`signed::SignedQuery`]
    /// which contains all fields of the query and the signed query in CBOR encoding
    pub fn sign(self) -> Result<SignedQuery, AgentError> {
        let effective_canister_id = self.effective_canister_id;
        let identity = self.agent.identity.clone();
        let content = self.into_envelope()?;
        let signed_query = sign_envelope(&content, identity)?;
        let EnvelopeContent::Query {
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
            nonce,
        } = content
        else {
            unreachable!()
        };
        Ok(SignedQuery {
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
            effective_canister_id,
            signed_query,
            nonce,
        })
    }

    /// Converts the query builder into [`EnvelopeContent`] for external signing or storage.
    pub fn into_envelope(self) -> Result<EnvelopeContent, AgentError> {
        self.agent.query_content(
            self.canister_id,
            self.method_name,
            self.arg,
            self.ingress_expiry_datetime,
            self.use_nonce,
        )
    }
}

impl<'agent> IntoFuture for QueryBuilder<'agent> {
    type IntoFuture = AgentFuture<'agent, Vec<u8>>;
    type Output = Result<Vec<u8>, AgentError>;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.call())
    }
}

/// An in-flight canister update call. Useful primarily as a `Future`.
pub struct UpdateCall<'agent> {
    agent: &'agent Agent,
    response_future: AgentFuture<'agent, CallResponse<(Vec<u8>, Certificate)>>,
    effective_canister_id: Principal,
    canister_id: Principal,
    method_name: String,
}

impl fmt::Debug for UpdateCall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateCall")
            .field("agent", &self.agent)
            .field("effective_canister_id", &self.effective_canister_id)
            .finish_non_exhaustive()
    }
}

impl Future for UpdateCall<'_> {
    type Output = Result<CallResponse<(Vec<u8>, Certificate)>, AgentError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.response_future.as_mut().poll(cx)
    }
}

impl<'a> UpdateCall<'a> {
    /// Waits for the update call to be completed, polling if necessary.
    pub async fn and_wait(self) -> Result<(Vec<u8>, Certificate), AgentError> {
        let response = self.response_future.await?;

        match response {
            CallResponse::Response(response) => Ok(response),
            CallResponse::Poll(request_id) => {
                self.agent
                    .wait_inner(
                        &request_id,
                        self.effective_canister_id,
                        Some(Operation::Call {
                            canister: self.canister_id,
                            method: self.method_name,
                        }),
                    )
                    .await
            }
        }
    }
}
/// An update request Builder.
///
/// This makes it easier to do update calls without actually passing all arguments or specifying
/// if you want to wait or not.
#[derive(Debug)]
pub struct UpdateBuilder<'agent> {
    agent: &'agent Agent,
    /// The [effective canister ID](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-effective-canister-id) of the destination.
    pub effective_canister_id: Principal,
    /// The principal ID of the canister being called.
    pub canister_id: Principal,
    /// The name of the canister method being called.
    pub method_name: String,
    /// The argument blob to be passed to the method.
    pub arg: Vec<u8>,
    /// The Unix timestamp that the request will expire at.
    pub ingress_expiry_datetime: Option<u64>,
}

impl<'agent> UpdateBuilder<'agent> {
    /// Creates a new update builder with an agent for a particular canister method.
    pub fn new(agent: &'agent Agent, canister_id: Principal, method_name: String) -> Self {
        Self {
            agent,
            effective_canister_id: canister_id,
            canister_id,
            method_name,
            arg: vec![],
            ingress_expiry_datetime: None,
        }
    }

    /// Sets the [effective canister ID](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-effective-canister-id) of the destination.
    pub fn with_effective_canister_id(mut self, canister_id: Principal) -> Self {
        self.effective_canister_id = canister_id;
        self
    }

    /// Sets the argument blob to pass to the canister. For most canisters this should be a Candid-serialized tuple.
    pub fn with_arg<A: Into<Vec<u8>>>(mut self, arg: A) -> Self {
        self.arg = arg.into();
        self
    }

    /// Sets `ingress_expiry_datetime` to the provided timestamp, at nanosecond precision.
    pub fn expire_at(mut self, time: impl Into<OffsetDateTime>) -> Self {
        self.ingress_expiry_datetime = Some(time.into().unix_timestamp_nanos() as u64);
        self
    }

    /// Sets `ingress_expiry_datetime` to `min(now, 4min)`.
    pub fn expire_after(mut self, duration: Duration) -> Self {
        self.ingress_expiry_datetime = Some(
            OffsetDateTime::now_utc()
                .saturating_add(duration.try_into().expect("negative duration"))
                .unix_timestamp_nanos() as u64,
        );
        self
    }

    /// Make an update call. This will call `request_status` on the `RequestId` in a loop and return
    /// the response as a byte vector.
    pub async fn call_and_wait(self) -> Result<Vec<u8>, AgentError> {
        self.call().and_wait().await.map(|x| x.0)
    }

    /// Make an update call. This will return a `RequestId`.
    /// The `RequestId` should then be used for `request_status` (most likely in a loop).
    pub fn call(self) -> UpdateCall<'agent> {
        let method_name = self.method_name.clone();
        let response_future = async move {
            self.agent
                .update_raw(
                    self.canister_id,
                    self.effective_canister_id,
                    self.method_name,
                    self.arg,
                    self.ingress_expiry_datetime,
                )
                .await
        };
        UpdateCall {
            agent: self.agent,
            response_future: Box::pin(response_future),
            effective_canister_id: self.effective_canister_id,
            canister_id: self.canister_id,
            method_name,
        }
    }

    /// Sign a update call. This will return a [`signed::SignedUpdate`]
    /// which contains all fields of the update and the signed update in CBOR encoding
    pub fn sign(self) -> Result<SignedUpdate, AgentError> {
        let identity = self.agent.identity.clone();
        let effective_canister_id = self.effective_canister_id;
        let content = self.into_envelope()?;
        let signed_update = sign_envelope(&content, identity)?;
        let request_id = to_request_id(&content)?;
        let EnvelopeContent::Call {
            nonce,
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
        } = content
        else {
            unreachable!()
        };
        Ok(SignedUpdate {
            nonce,
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
            effective_canister_id,
            signed_update,
            request_id,
        })
    }

    /// Converts the update builder into an [`EnvelopeContent`] for external signing or storage.
    pub fn into_envelope(self) -> Result<EnvelopeContent, AgentError> {
        let nonce = self.agent.nonce_factory.generate();
        self.agent.update_content(
            self.canister_id,
            self.method_name,
            self.arg,
            self.ingress_expiry_datetime,
            nonce,
        )
    }
}

impl<'agent> IntoFuture for UpdateBuilder<'agent> {
    type IntoFuture = AgentFuture<'agent, Vec<u8>>;
    type Output = Result<Vec<u8>, AgentError>;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.call_and_wait())
    }
}

/// HTTP client middleware. Implemented automatically for `reqwest`-compatible by-ref `tower::Service`, such as `reqwest_middleware`.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait HttpService: Send + Sync + Debug {
    /// Perform a HTTP request. Any retry logic should call `req` again to get a new request.
    async fn call<'a>(
        &'a self,
        req: &'a (dyn Fn() -> Result<http::Request<Bytes>, AgentError> + Send + Sync),
        max_retries: usize,
        size_limit: Option<usize>,
    ) -> Result<http::Response<Bytes>, AgentError>;
}

/// Convert from http Request to reqwest's one
fn from_http_request(req: http::Request<Bytes>) -> Result<Request, AgentError> {
    let (parts, body) = req.into_parts();
    let body = reqwest::Body::from(body);
    // I think it can never fail since it converts from `Url` to `Uri` and `Url` is a subset of `Uri`,
    // but just to be safe let's handle it.
    let request = http::Request::from_parts(parts, body)
        .try_into()
        .map_err(|e: reqwest::Error| AgentError::InvalidReplicaUrl(e.to_string()))?;

    Ok(request)
}

/// Convert from reqwests's Response to http one
#[cfg(not(target_family = "wasm"))]
async fn to_http_response(
    resp: Response,
    size_limit: Option<usize>,
) -> Result<http::Response<Bytes>, AgentError> {
    use http_body_util::{BodyExt, Limited};

    let resp: http::Response<reqwest::Body> = resp.into();
    let (parts, body) = resp.into_parts();
    let body = Limited::new(body, size_limit.unwrap_or(usize::MAX));
    let body = body
        .collect()
        .await
        .map_err(|e| AgentError::TransportError(format!("unable to read response body: {e:#}")))?
        .to_bytes();
    let resp = http::Response::from_parts(parts, body);

    Ok(resp)
}

/// Convert from reqwests's Response to http one
/// WASM in reqwest doesn't have direct conversion for http::Response,
/// so we have to hack around using streams.
#[cfg(target_family = "wasm")]
async fn to_http_response(
    resp: Response,
    size_limit: Option<usize>,
) -> Result<http::Response<Bytes>, AgentError> {
    use futures_util::StreamExt;
    use http_body::Frame;
    use http_body_util::{Limited, StreamBody};

    // Save headers
    let status = resp.status();
    let headers = resp.headers().clone();

    // Convert body
    let stream = resp.bytes_stream().map(|x| x.map(Frame::data));
    let body = StreamBody::new(stream);
    let body = Limited::new(body, size_limit.unwrap_or(usize::MAX));
    let body = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| AgentError::TransportError(format!("unable to read response body: {e:#}")))?
        .to_bytes();

    let mut resp = http::Response::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;

    Ok(resp)
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl<T> HttpService for T
where
    for<'a> &'a T: Service<Request, Response = Response, Error = reqwest::Error>,
    for<'a> <&'a Self as Service<Request>>::Future: Send,
    T: Send + Sync + Debug + ?Sized,
{
    #[allow(clippy::needless_arbitrary_self_type)]
    async fn call<'a>(
        mut self: &'a Self,
        req: &'a (dyn Fn() -> Result<http::Request<Bytes>, AgentError> + Send + Sync),
        max_retries: usize,
        size_limit: Option<usize>,
    ) -> Result<http::Response<Bytes>, AgentError> {
        let mut retry_count = 0;
        loop {
            let request = from_http_request(req()?)?;

            match Service::call(&mut self, request).await {
                Err(err) => {
                    // Network-related errors can be retried.
                    if err.is_connect() {
                        if retry_count >= max_retries {
                            return Err(AgentError::TransportError(err.to_string()));
                        }
                        retry_count += 1;
                    }
                }

                Ok(resp) => {
                    let resp = to_http_response(resp, size_limit).await?;
                    return Ok(resp);
                }
            }
        }
    }
}

#[cfg(target_family = "wasm")]
#[async_trait(?Send)]
impl<T> HttpService for T
where
    for<'a> &'a T: Service<Request, Response = Response, Error = reqwest::Error>,
    T: Send + Sync + Debug + ?Sized,
{
    #[allow(clippy::needless_arbitrary_self_type)]
    async fn call<'a>(
        mut self: &'a Self,
        req: &'a (dyn Fn() -> Result<http::Request<Bytes>, AgentError> + Send + Sync),
        _retries: usize,
        _size_limit: Option<usize>,
    ) -> Result<http::Response<Bytes>, AgentError> {
        Ok(Service::call(&mut self, req()?)
            .await
            .map_err(|e| AgentError::TransportError(e.to_string()))?)
    }
}

#[derive(Debug)]
struct Retry429Logic {
    client: Client,
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl HttpService for Retry429Logic {
    async fn call<'a>(
        &'a self,
        req: &'a (dyn Fn() -> Result<http::Request<Bytes>, AgentError> + Send + Sync),
        _max_tcp_retries: usize,
        _size_limit: Option<usize>,
    ) -> Result<http::Response<Bytes>, AgentError> {
        let mut retries = 0;
        loop {
            #[cfg(not(target_family = "wasm"))]
            let resp = self.client.call(req, _max_tcp_retries, _size_limit).await?;
            // Client inconveniently does not implement Service on wasm
            #[cfg(target_family = "wasm")]
            let resp = {
                let request = from_http_request(req()?)?;
                let resp = self
                    .client
                    .execute(request)
                    .await
                    .map_err(|e| AgentError::TransportError(e.to_string()))?;
                to_http_response(resp, _size_limit).await?
            };

            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                if retries == 6 {
                    break Ok(resp);
                } else {
                    retries += 1;
                    crate::util::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            } else {
                break Ok(resp);
            }
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod offline_tests {
    use super::*;
    use tokio::net::TcpListener;
    // Any tests that involve the network should go in agent_test, not here.

    #[test]
    fn rounded_expiry() {
        let agent = Agent::builder()
            .with_url("http://not-a-real-url")
            .build()
            .unwrap();
        let mut prev_expiry = None;
        let mut num_timestamps = 0;
        for _ in 0..6 {
            let update = agent
                .update(&Principal::management_canister(), "not_a_method")
                .sign()
                .unwrap();
            if prev_expiry < Some(update.ingress_expiry) {
                prev_expiry = Some(update.ingress_expiry);
                num_timestamps += 1;
            }
        }
        // in six requests, there should be no more than two timestamps
        assert!(num_timestamps <= 2, "num_timestamps:{num_timestamps} > 2");
    }

    #[tokio::test]
    async fn client_ratelimit() {
        let mock_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let count = Arc::new(Mutex::new(0));
        let port = mock_server.local_addr().unwrap().port();
        tokio::spawn({
            let count = count.clone();
            async move {
                loop {
                    let (mut conn, _) = mock_server.accept().await.unwrap();
                    *count.lock().unwrap() += 1;
                    tokio::spawn(
                        // read all data, never reply
                        async move { tokio::io::copy(&mut conn, &mut tokio::io::sink()).await },
                    );
                }
            }
        });
        let agent = Agent::builder()
            .with_http_client(Client::builder().http1_only().build().unwrap())
            .with_url(format!("http://127.0.0.1:{port}"))
            .with_max_concurrent_requests(2)
            .build()
            .unwrap();
        for _ in 0..3 {
            let agent = agent.clone();
            tokio::spawn(async move {
                agent
                    .query(&"ryjl3-tyaaa-aaaaa-aaaba-cai".parse().unwrap(), "greet")
                    .call()
                    .await
            });
        }
        crate::util::sleep(Duration::from_millis(250)).await;
        assert_eq!(*count.lock().unwrap(), 2);
    }
}
