//! The main Agent module. Contains the [Agent] type and all associated structures.
pub(crate) mod agent_config;
pub mod agent_error;
pub(crate) mod builder;
pub mod http_transport;
pub(crate) mod nonce;
pub(crate) mod response_authentication;
pub mod status;

pub use agent_config::AgentConfig;
pub use agent_error::AgentError;
pub use builder::AgentBuilder;
use cached::{Cached, TimedCache};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[doc(inline)]
pub use ic_transport_types::{
    signed, EnvelopeContent, RejectCode, RejectResponse, ReplyResponse, RequestStatusResponse,
};
pub use nonce::{NonceFactory, NonceGenerator};
use rangemap::{RangeInclusiveMap, StepFns};
use time::OffsetDateTime;

#[cfg(test)]
mod agent_test;

use crate::{
    agent::response_authentication::{
        extract_der, lookup_canister_info, lookup_canister_metadata, lookup_request_status,
        lookup_value,
    },
    export::Principal,
    identity::Identity,
    to_request_id, RequestId,
};
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use ic_certification::{Certificate, Delegation, Label};
use ic_transport_types::{
    signed::{SignedQuery, SignedRequestStatus, SignedUpdate},
    Envelope, QueryResponse, ReadStateResponse,
};
use serde::Serialize;
use status::Status;
use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryFrom,
    fmt,
    future::Future,
    ops::RangeInclusive,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use self::response_authentication::lookup_subnet;

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

#[cfg(not(target_family = "wasm"))]
type AgentFuture<'a, V> = Pin<Box<dyn Future<Output = Result<V, AgentError>> + Send + 'a>>;

#[cfg(target_family = "wasm")]
type AgentFuture<'a, V> = Pin<Box<dyn Future<Output = Result<V, AgentError>> + 'a>>;

/// A facade that connects to a Replica and does requests. These requests can be of any type
/// (does not have to be HTTP). This trait is to inverse the control from the Agent over its
/// connection code, and to resolve any direct dependencies to tokio or HTTP code from this
/// crate.
///
/// An implementation of this trait for HTTP transport is implemented using Reqwest, with the
/// feature flag `reqwest`. This might be deprecated in the future.
///
/// Any error returned by these methods will bubble up to the code that called the [Agent].
pub trait Transport: Send + Sync {
    /// Sends an asynchronous request to a Replica. The Request ID is non-mutable and
    /// depends on the content of the envelope.
    ///
    /// This normally corresponds to the `/api/v2/canister/<effective_canister_id>/call` endpoint.
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        request_id: RequestId,
    ) -> AgentFuture<()>;

    /// Sends a synchronous request to a Replica. This call includes the body of the request message
    /// itself (envelope).
    ///
    /// This normally corresponds to the `/api/v2/canister/<effective_canister_id>/read_state` endpoint.
    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>>;

    /// Sends a synchronous request to a Replica. This call includes the body of the request message
    /// itself (envelope).
    ///
    /// This normally corresponds to the `/api/v2/canister/<effective_canister_id>/query` endpoint.
    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>>;

    /// Sends a status request to the Replica, returning whatever the replica returns.
    /// In the current spec v2, this is a CBOR encoded status message, but we are not
    /// making this API attach semantics to the response.
    fn status(&self) -> AgentFuture<Vec<u8>>;
}

impl<I: Transport + ?Sized> Transport for Box<I> {
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        request_id: RequestId,
    ) -> AgentFuture<()> {
        (**self).call(effective_canister_id, envelope, request_id)
    }
    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>> {
        (**self).read_state(effective_canister_id, envelope)
    }
    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        (**self).query(effective_canister_id, envelope)
    }
    fn status(&self) -> AgentFuture<Vec<u8>> {
        (**self).status()
    }
}
impl<I: Transport + ?Sized> Transport for Arc<I> {
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        request_id: RequestId,
    ) -> AgentFuture<()> {
        (**self).call(effective_canister_id, envelope, request_id)
    }
    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>> {
        (**self).read_state(effective_canister_id, envelope)
    }
    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        (**self).query(effective_canister_id, envelope)
    }
    fn status(&self) -> AgentFuture<Vec<u8>> {
        (**self).status()
    }
}

/// Classification of the result of a request_status_raw (poll) call.
#[derive(Debug)]
pub enum PollResult {
    /// The request has been submitted, but we do not know yet if it
    /// has been accepted or not.
    Submitted,

    /// The request has been received and may be processing.
    Accepted,

    /// The request completed and returned some data.
    Completed(Vec<u8>),
}

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
/// #     let rng = ring::rand::SystemRandom::new();
/// #     let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
/// #         .expect("Could not generate a key pair.");
/// #
/// #     ic_agent::identity::BasicIdentity::from_key_pair(
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
///     .call_and_wait()
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
#[derive(Clone)]
pub struct Agent {
    nonce_factory: Arc<dyn NonceGenerator>,
    identity: Arc<dyn Identity>,
    ingress_expiry: Duration,
    root_key: Arc<RwLock<Vec<u8>>>,
    transport: Arc<dyn Transport>,
    subnet_key_cache: Arc<Mutex<SubnetCache>>,
    verify_query_signatures: bool,
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
        Ok(Agent {
            nonce_factory: config.nonce_factory,
            identity: config.identity,
            ingress_expiry: config
                .ingress_expiry
                .unwrap_or_else(|| Duration::from_secs(300)),
            root_key: Arc::new(RwLock::new(IC_ROOT_KEY.to_vec())),
            transport: config
                .transport
                .ok_or_else(AgentError::MissingReplicaTransport)?,
            subnet_key_cache: Arc::new(Mutex::new(SubnetCache::new())),
            verify_query_signatures: config.verify_query_signatures,
        })
    }

    /// Set the transport of the [`Agent`].
    pub fn set_transport<F: 'static + Transport>(&mut self, transport: F) {
        self.transport = Arc::new(transport);
    }

    /// Set the identity provider for signing messages.
    ///
    /// NOTE: if you change the identity while having update calls in
    /// flight, you will not be able to [Agent::poll] the status of these
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
    /// flight, you will not be able to [Agent::poll] the status of these
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
        let root_key = match status.root_key {
            Some(key) => key,
            None => return Err(AgentError::NoRootKeyInStatus(status)),
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
        // TODO(hansl): evaluate if we need this on the agent side (my hunch is we don't).
        let permitted_drift = Duration::from_secs(60);
        self.ingress_expiry
            .as_nanos()
            .saturating_add(OffsetDateTime::now_utc().unix_timestamp_nanos() as u128)
            .saturating_sub(permitted_drift.as_nanos()) as u64
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
        let bytes = self
            .transport
            .query(effective_canister_id, serialized_bytes)
            .await?;
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
        let bytes = self
            .transport
            .read_state(effective_canister_id, serialized_bytes)
            .await?;
        serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)
    }

    async fn call_endpoint(
        &self,
        effective_canister_id: Principal,
        request_id: RequestId,
        serialized_bytes: Vec<u8>,
    ) -> Result<RequestId, AgentError> {
        self.transport
            .call(effective_canister_id, serialized_bytes, request_id)
            .await?;
        Ok(request_id)
    }

    /// The simplest way to do a query call; sends a byte array and will return a byte vector.
    /// The encoding is left as an exercise to the user.
    async fn query_raw(
        &self,
        canister_id: Principal,
        effective_canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<Vec<u8>, AgentError> {
        let content = self.query_content(canister_id, method_name, arg, ingress_expiry_datetime)?;
        let serialized_bytes = sign_envelope(&content, self.identity.clone())?;
        self.query_inner(
            effective_canister_id,
            serialized_bytes,
            content.to_request_id(),
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
        self.query_inner(
            effective_canister_id,
            signed_query,
            envelope.content.to_request_id(),
        )
        .await
    }

    /// Helper function for performing both the query call and possibly a read_state to check the subnet node keys.
    ///
    /// This should be used instead of `query_endpoint`. No validation is performed on `signed_query`.
    async fn query_inner(
        &self,
        effective_canister_id: Principal,
        signed_query: Vec<u8>,
        request_id: RequestId,
    ) -> Result<Vec<u8>, AgentError> {
        let response = if self.verify_query_signatures {
            let (response, subnet) = futures_util::try_join!(
                self.query_endpoint::<QueryResponse>(effective_canister_id, signed_query),
                self.get_subnet_by_canister(&effective_canister_id)
            )?;
            if response.signatures().is_empty() {
                return Err(AgentError::MissingSignature);
            }
            for signature in response.signatures() {
                let signable = response.signable(request_id, signature.timestamp);
                let node_key = subnet
                    .node_keys
                    .get(&signature.identity)
                    .ok_or(AgentError::CertificateNotAuthorized())?;
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
                let pubkey = VerifyingKey::from_bytes(node_key[12..].try_into().unwrap()).unwrap();
                let sig = Signature::from_bytes(
                    signature.signature[..]
                        .try_into()
                        .map_err(|_| AgentError::CertificateVerificationFailed())?,
                );

                if pubkey.verify(&signable, &sig).is_err() {
                    return Err(AgentError::CertificateVerificationFailed());
                }
            }
            response
        } else {
            self.query_endpoint::<QueryResponse>(effective_canister_id, signed_query)
                .await?
        };

        match response {
            QueryResponse::Replied { reply, .. } => Ok(reply.arg),
            QueryResponse::Rejected { reject, .. } => Err(AgentError::ReplicaError(reject)),
        }
    }

    fn query_content(
        &self,
        canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<EnvelopeContent, AgentError> {
        Ok(EnvelopeContent::Query {
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            canister_id,
            method_name,
            arg,
            ingress_expiry: ingress_expiry_datetime.unwrap_or_else(|| self.get_expiry_date()),
        })
    }

    /// The simplest way to do an update call; sends a byte array and will return a RequestId.
    /// The RequestId should then be used for request_status (most likely in a loop).
    async fn update_raw(
        &self,
        canister_id: Principal,
        effective_canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<RequestId, AgentError> {
        let nonce = self.nonce_factory.generate();
        let content = self.update_content(
            canister_id,
            method_name,
            arg,
            ingress_expiry_datetime,
            nonce,
        )?;
        let request_id = to_request_id(&content)?;
        let serialized_bytes = sign_envelope(&content, self.identity.clone())?;

        self.call_endpoint(effective_canister_id, request_id, serialized_bytes)
            .await
    }

    /// Send the signed update to the network. Will return a [`RequestId`].
    /// The bytes will be checked to verify that it is a valid update.
    /// If you want to inspect the fields of the update, use [`signed_update_inspect`] before calling this method.
    pub async fn update_signed(
        &self,
        effective_canister_id: Principal,
        signed_update: Vec<u8>,
    ) -> Result<RequestId, AgentError> {
        let envelope: Envelope =
            serde_cbor::from_slice(&signed_update).map_err(AgentError::InvalidCborData)?;
        let request_id = to_request_id(&envelope.content)?;
        self.call_endpoint(effective_canister_id, request_id, signed_update)
            .await
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

    /// Call request_status on the RequestId once and classify the result
    pub async fn poll(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
    ) -> Result<PollResult, AgentError> {
        match self
            .request_status_raw(request_id, effective_canister_id)
            .await?
        {
            RequestStatusResponse::Unknown => Ok(PollResult::Submitted),

            RequestStatusResponse::Received | RequestStatusResponse::Processing => {
                Ok(PollResult::Accepted)
            }

            RequestStatusResponse::Replied(ReplyResponse { arg, .. }) => {
                Ok(PollResult::Completed(arg))
            }

            RequestStatusResponse::Rejected(response) => Err(AgentError::ReplicaError(response)),

            RequestStatusResponse::Done => Err(AgentError::RequestStatusDoneNoReply(String::from(
                *request_id,
            ))),
        }
    }

    /// Call request_status on the RequestId in a loop and return the response as a byte vector.
    pub async fn wait(
        &self,
        request_id: RequestId,
        effective_canister_id: Principal,
    ) -> Result<Vec<u8>, AgentError> {
        let mut retry_policy = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(500))
            .with_max_interval(Duration::from_secs(1))
            .with_multiplier(1.4)
            .with_max_elapsed_time(Some(Duration::from_secs(60 * 5)))
            .build();
        let mut request_accepted = false;
        loop {
            match self.poll(&request_id, effective_canister_id).await? {
                PollResult::Submitted => {}
                PollResult::Accepted => {
                    if !request_accepted {
                        // The system will return RequestStatusResponse::Unknown
                        // (PollResult::Submitted) until the request is accepted
                        // and we generally cannot know how long that will take.
                        // State transitions between Received and Processing may be
                        // instantaneous. Therefore, once we know the request is accepted,
                        // we should restart the backoff so the request does not time out.

                        retry_policy.reset();
                        request_accepted = true;
                    }
                }
                PollResult::Completed(result) => return Ok(result),
            };

            match retry_policy.next_backoff() {
                #[cfg(not(target_family = "wasm"))]
                Some(duration) => tokio::time::sleep(duration).await,
                #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
                Some(duration) => {
                    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |rs, rj| {
                        if let Err(e) = web_sys::window()
                            .expect("global window unavailable")
                            .set_timeout_with_callback_and_timeout_and_arguments_0(
                                &rs,
                                duration.as_millis() as _,
                            )
                        {
                            use wasm_bindgen::UnwrapThrowExt;
                            rj.call1(&rj, &e).unwrap_throw();
                        }
                    }))
                    .await
                    .expect("unable to setTimeout");
                }
                None => return Err(AgentError::TimeoutWaitingForResponse()),
            }
        }
    }

    /// Request the raw state tree directly. See [the protocol docs](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state) for more information.
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
        let sig = &cert.signature;

        let root_hash = cert.tree.digest();
        let mut msg = vec![];
        msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
        msg.extend_from_slice(&root_hash);

        let der_key = self.check_delegation(&cert.delegation, effective_canister_id)?;
        let key = extract_der(der_key)?;

        ic_verify_bls_signature::verify_bls_signature(sig, &msg, &key)
            .map_err(|_| AgentError::CertificateVerificationFailed())?;

        let time = leb128::read::unsigned(&mut lookup_value(&cert.tree, [b"time".as_ref()])?)?;
        if (OffsetDateTime::now_utc()
            - OffsetDateTime::from_unix_timestamp_nanos(time as _).unwrap())
        .whole_minutes()
            > 1
        {
            Err(AgentError::CertificateOutdated)
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
                self.verify(&cert, effective_canister_id)?;
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
                lookup_value(&cert.tree, public_key_path).map(|pk| pk.to_vec())
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

    /// Fetches the status of a particular request by its ID.
    pub async fn request_status_raw(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
    ) -> Result<RequestStatusResponse, AgentError> {
        let paths: Vec<Vec<Label>> =
            vec![vec!["request_status".into(), request_id.to_vec().into()]];

        let cert = self.read_state_raw(paths, effective_canister_id).await?;

        lookup_request_status(cert, request_id)
    }

    /// Send the signed request_status to the network. Will return [`RequestStatusResponse`].
    /// The bytes will be checked to verify that it is a valid request_status.
    /// If you want to inspect the fields of the request_status, use [`signed_request_status_inspect`] before calling this method.
    pub async fn request_status_signed(
        &self,
        request_id: &RequestId,
        effective_canister_id: Principal,
        signed_request_status: Vec<u8>,
    ) -> Result<RequestStatusResponse, AgentError> {
        let _envelope: Envelope =
            serde_cbor::from_slice(&signed_request_status).map_err(AgentError::InvalidCborData)?;
        let read_state_response: ReadStateResponse = self
            .read_state_endpoint(effective_canister_id, signed_request_status)
            .await?;

        let cert: Certificate = serde_cbor::from_slice(&read_state_response.certificate)
            .map_err(AgentError::InvalidCborData)?;
        self.verify(&cert, effective_canister_id)?;
        lookup_request_status(cert, request_id)
    }

    /// Returns an UpdateBuilder enabling the construction of an update call without
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
        let bytes = self.transport.status().await?;

        let cbor: serde_cbor::Value =
            serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)?;

        Status::try_from(&cbor).map_err(|_| AgentError::InvalidReplicaStatus)
    }

    /// Returns a QueryBuilder enabling the construction of a query call without
    /// passing all arguments.
    pub fn query<S: Into<String>>(&self, canister_id: &Principal, method_name: S) -> QueryBuilder {
        QueryBuilder::new(self, *canister_id, method_name.into())
    }

    /// Sign a request_status call. This will return a [`signed::SignedRequestStatus`]
    /// which contains all fields of the request_status and the signed request_status in CBOR encoding
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
                    value_arg: format!("{:?}", arg),
                    value_cbor: format!("{:?}", arg_cbor),
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
                    value_arg: format!("{:?}", arg),
                    value_cbor: format!("{:?}", arg_cbor),
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

/// Inspect the bytes to be sent as a request_status
/// Return Ok only when the bytes can be deserialized as a request_status and all fields match with the arguments
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
                    value_arg: format!("{:?}", paths),
                    value_cbor: format!("{:?}", paths_cbor),
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
    }

    fn insert_subnet(&mut self, subnet_id: Principal, subnet: Arc<Subnet>) {
        self.subnets.cache_set(subnet_id, subnet.clone());
        for range in &subnet.canister_ranges {
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
        for byte in arr[..bytes.len()].iter_mut().rev() {
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
        for byte in arr[..bytes.len()].iter_mut() {
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
    _key: Vec<u8>,
    node_keys: HashMap<Principal, Vec<u8>>,
    canister_ranges: Vec<RangeInclusive<Principal>>,
}

/// A Query Request Builder.
///
/// This makes it easier to do query calls without actually passing all arguments.
#[derive(Debug, Clone)]
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

    /// Sets ingress_expiry_datetime to the provided timestamp, at nanosecond precision.
    pub fn expire_at(mut self, time: impl Into<OffsetDateTime>) -> Self {
        self.ingress_expiry_datetime = Some(time.into().unix_timestamp_nanos() as u64);
        self
    }

    /// Sets ingress_expiry_datetime to `now + duration - drift`, where `drift` is a
    /// permitted drift from the duration to account for using system time and not block time.
    pub fn expire_after(mut self, duration: Duration) -> Self {
        let permitted_drift = Duration::from_secs(60);
        self.ingress_expiry_datetime = Some(
            (duration
                .as_nanos()
                .saturating_add(OffsetDateTime::now_utc().unix_timestamp_nanos() as u128)
                .saturating_sub(permitted_drift.as_nanos())) as u64,
        );
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
            )
            .await
    }

    /// Sign a query call. This will return a [`signed::SignedQuery`]
    /// which contains all fields of the query and the signed query in CBOR encoding
    pub fn sign(self) -> Result<SignedQuery, AgentError> {
        let content = self.agent.query_content(
            self.canister_id,
            self.method_name,
            self.arg,
            self.ingress_expiry_datetime,
        )?;
        let signed_query = sign_envelope(&content, self.agent.identity.clone())?;
        let EnvelopeContent::Query {
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg
        } = content else { unreachable!() };
        Ok(SignedQuery {
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
            effective_canister_id: self.effective_canister_id,
            signed_query,
        })
    }
}

/// An in-flight canister update call. Useful primarily as a `Future`.
pub struct UpdateCall<'agent> {
    agent: &'agent Agent,
    request_id: AgentFuture<'agent, RequestId>,
    effective_canister_id: Principal,
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
    type Output = Result<RequestId, AgentError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.request_id.as_mut().poll(cx)
    }
}
impl<'a> UpdateCall<'a> {
    async fn and_wait(self) -> Result<Vec<u8>, AgentError> {
        let request_id = self.request_id.await?;
        self.agent
            .wait(request_id, self.effective_canister_id)
            .await
    }
}
/// An Update Request Builder.
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
    /// Creates a new query builder with an agent for a particular canister method.
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

    /// Sets ingress_expiry_datetime to the provided timestamp, at nanosecond precision.
    pub fn expire_at(mut self, time: impl Into<OffsetDateTime>) -> Self {
        self.ingress_expiry_datetime = Some(time.into().unix_timestamp_nanos() as u64);
        self
    }

    /// Sets ingress_expiry_datetime to `now + duration - drift`, where `drift` is a
    /// permitted drift from the duration to account for using system time and not block time.
    pub fn expire_after(mut self, duration: Duration) -> Self {
        let permitted_drift = Duration::from_secs(60);
        self.ingress_expiry_datetime = Some(
            (duration
                .as_nanos()
                .saturating_add(OffsetDateTime::now_utc().unix_timestamp_nanos() as u128)
                .saturating_sub(permitted_drift.as_nanos())) as u64,
        );
        self
    }

    /// Make an update call. This will call request_status on the RequestId in a loop and return
    /// the response as a byte vector.
    pub async fn call_and_wait(self) -> Result<Vec<u8>, AgentError> {
        self.call().and_wait().await
    }

    /// Make an update call. This will return a RequestId.
    /// The RequestId should then be used for request_status (most likely in a loop).
    pub fn call(self) -> UpdateCall<'agent> {
        let request_id_future = async move {
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
            request_id: Box::pin(request_id_future),
            effective_canister_id: self.effective_canister_id,
        }
    }

    /// Sign a update call. This will return a [`signed::SignedUpdate`]
    /// which contains all fields of the update and the signed update in CBOR encoding
    pub fn sign(self) -> Result<SignedUpdate, AgentError> {
        let nonce = self.agent.nonce_factory.generate();
        let content = self.agent.update_content(
            self.canister_id,
            self.method_name,
            self.arg,
            self.ingress_expiry_datetime,
            nonce,
        )?;
        let signed_update = sign_envelope(&content, self.agent.identity.clone())?;
        let request_id = to_request_id(&content)?;
        let EnvelopeContent::Call {
            nonce,
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg
        } = content else { unreachable!() };
        Ok(SignedUpdate {
            nonce,
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
            effective_canister_id: self.effective_canister_id,
            signed_update,
            request_id,
        })
    }
}
