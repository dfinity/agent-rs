//! The main Agent module. Contains the [Agent] type and all associated structures.
pub(crate) mod agent_config;
pub mod agent_error;
pub(crate) mod builder;
pub mod http_transport;
pub(crate) mod nonce;
pub(crate) mod replica_api;
pub(crate) mod response;
mod response_authentication;

pub mod status;
pub use agent_config::AgentConfig;
pub use agent_error::AgentError;
pub use builder::AgentBuilder;
pub use nonce::NonceFactory;
pub use response::{Replied, RequestStatusResponse};

#[cfg(test)]
mod agent_test;

use crate::agent::replica_api::{
    AsyncContent, Certificate, Delegation, Envelope, ReadStateResponse, SyncContent,
};
use crate::export::Principal;
use crate::hash_tree::Label;
use crate::identity::Identity;
use crate::{to_request_id, RequestId};
use delay::Waiter;
use serde::Serialize;
use status::Status;

use crate::agent::response_authentication::{
    extract_der, initialize_bls, lookup_request_status, lookup_value,
};
use crate::bls::bls12381::bls;
use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

const IC_REQUEST_DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";
const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

/// A facade that connects to a Replica and does requests. These requests can be of any type
/// (does not have to be HTTP). This trait is to inverse the control from the Agent over its
/// connection code, and to resolve any direct dependencies to tokio or HTTP code from this
/// crate.
///
/// An implementation of this trait for HTTP transport is implemented using Reqwest, with the
/// feature flag `reqwest`. This might be deprecated in the future.
///
/// Any error returned by these methods will bubble up to the code that called the [Agent].
pub trait ReplicaV1Transport {
    /// Sends a synchronous request to a Replica. This call includes the body of the request message
    /// itself (envelope).
    ///
    /// This normally corresponds to the `/api/v1/read` endpoint.
    fn read<'a>(
        &'a self,
        envelope: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>>;

    /// Sends an asynchronous request to a Replica. The Request ID is non-mutable and
    /// depends on the content of the envelope.
    ///
    /// This normally corresponds to the `/api/v1/read` endpoint.
    fn submit<'a>(
        &'a self,
        envelope: Vec<u8>,
        request_id: RequestId,
    ) -> Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send + 'a>>;

    /// Sends a status request to the Replica, returning whatever the replica returns.
    /// In the current spec v1, this is a CBOR encoded status message, but we are not
    /// making this API attach semantics to the response.
    fn status<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>>;
}

/// A low level Agent to make calls to a Replica endpoint.
///
/// ```ignore
/// # // This test is ignored because it requires an ic to be running. We run these
/// # // in the ic-ref workflow.
/// use ic_agent::Agent;
/// use ic_types::Principal;
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
///   agent.fetch_root_key().await?;
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
#[derive(Clone)]
pub struct Agent {
    nonce_factory: NonceFactory,
    identity: Arc<dyn Identity + Send + Sync>,
    ingress_expiry_duration: Duration,
    root_key: Arc<RwLock<Option<Vec<u8>>>>,
    transport: Arc<dyn ReplicaV1Transport + Send + Sync>,
}

impl Agent {
    /// Create an instance of an [`AgentBuilder`] for building an [`Agent`]. This is simpler than
    /// using the [`AgentConfig`] and [`Agent::new()`].
    pub fn builder() -> builder::AgentBuilder {
        Default::default()
    }

    /// Create an instance of an [`Agent`].
    pub fn new(config: AgentConfig) -> Result<Agent, AgentError> {
        initialize_bls()?;

        Ok(Agent {
            nonce_factory: config.nonce_factory,
            identity: config.identity,
            ingress_expiry_duration: config
                .ingress_expiry_duration
                .unwrap_or_else(|| Duration::from_secs(300)),
            root_key: Arc::new(RwLock::new(None)),
            transport: config
                .transport
                .ok_or_else(AgentError::MissingReplicaTransport)?,
        })
    }

    /// Fetch the root key of the replica using its status end point, and update the agent's
    /// root key. This only uses the agent's specific upstream replica, and does not ensure
    /// the root key validity. In order to prevent any MITM attack, developers should try
    /// to contact multiple replicas.
    ///
    /// The root key is necessary for validating state and certificates sent by the replica.
    /// By default, it is set to [None] and validating methods will return an error.
    pub async fn fetch_root_key(&self) -> Result<(), AgentError> {
        let status = self.status().await?;
        let root_key = status
            .root_key
            .clone()
            .ok_or(AgentError::NoRootKeyInStatus(status))?;
        if let Ok(mut write_guard) = self.root_key.write() {
            *write_guard = Some(root_key);
        }
        Ok(())
    }

    fn read_root_key(&self) -> Result<Vec<u8>, AgentError> {
        if let Ok(read_lock) = self.root_key.read() {
            if let Some(root_key) = read_lock.clone() {
                Ok(root_key)
            } else {
                Err(AgentError::CouldNotReadRootKey())
            }
        } else {
            Err(AgentError::CouldNotReadRootKey())
        }
    }

    fn get_expiry_date(&self) -> u64 {
        // TODO(hansl): evaluate if we need this on the agent side (my hunch is we don't).
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
        buf.extend_from_slice(IC_REQUEST_DOMAIN_SEPARATOR);
        buf.extend_from_slice(request_id.as_slice());
        buf
    }

    async fn read_endpoint<A>(&self, request: SyncContent) -> Result<A, AgentError>
    where
        A: serde::de::DeserializeOwned,
    {
        let request_id = to_request_id(&request)?;
        let msg = self.construct_message(&request_id);
        let signature = self.identity.sign(&msg).map_err(AgentError::SigningError)?;

        let envelope = Envelope {
            content: request,
            sender_pubkey: signature.public_key,
            sender_sig: signature.signature,
        };

        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        serializer.self_describe()?;
        envelope.serialize(&mut serializer)?;

        let bytes = self.transport.read(serialized_bytes).await?;
        serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)
    }

    async fn submit_endpoint(&self, request: AsyncContent) -> Result<RequestId, AgentError> {
        let request_id = to_request_id(&request)?;
        let msg = self.construct_message(&request_id);
        let signature = self.identity.sign(&msg).map_err(AgentError::SigningError)?;

        let envelope = Envelope {
            content: request,
            sender_pubkey: signature.public_key,
            sender_sig: signature.signature,
        };

        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        serializer.self_describe()?;
        envelope.serialize(&mut serializer)?;

        self.transport.submit(serialized_bytes, request_id).await?;
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

    async fn read_state_raw(&self, paths: Vec<Vec<Label>>) -> Result<Certificate, AgentError> {
        let read_state_response: ReadStateResponse = self
            .read_endpoint(SyncContent::ReadStateRequest {
                sender: self.identity.sender().map_err(AgentError::SigningError)?,
                paths,
                ingress_expiry: self.get_expiry_date(),
            })
            .await?;

        let cert: Certificate = serde_cbor::from_slice(&read_state_response.certificate)
            .map_err(AgentError::InvalidCborData)?;
        self.verify(&cert)?;
        Ok(cert)
    }

    fn verify(&self, cert: &Certificate) -> Result<(), AgentError> {
        let sig = &cert.signature;

        let root_hash = cert.tree.digest();
        let mut msg = vec![];
        msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
        msg.extend_from_slice(&root_hash);

        let der_key = self.check_delegation(&cert.delegation)?;
        let key = extract_der(der_key)?;

        let result = bls::core_verify(sig, &*msg, &*key);
        if result != bls::BLS_OK {
            Err(AgentError::CertificateVerificationFailed())
        } else {
            Ok(())
        }
    }

    fn check_delegation(&self, delegation: &Option<Delegation>) -> Result<Vec<u8>, AgentError> {
        match delegation {
            None => self.read_root_key(),
            Some(delegation) => {
                let cert: Certificate = serde_cbor::from_slice(&delegation.certificate)
                    .map_err(AgentError::InvalidCborData)?;
                self.verify(&cert)?;
                let public_key_path = vec![
                    "subnet".into(),
                    delegation.subnet_id.clone().into(),
                    "public_key".into(),
                ];
                lookup_value(&cert, public_key_path).map(|pk| pk.to_vec())
            }
        }
    }

    pub async fn request_status_raw(
        &self,
        request_id: &RequestId,
    ) -> Result<RequestStatusResponse, AgentError> {
        let paths: Vec<Vec<Label>> =
            vec![vec!["request_status".into(), request_id.to_vec().into()]];

        let cert = self.read_state_raw(paths).await?;

        lookup_request_status(cert, request_id)
    }

    /// Returns an UpdateBuilder enabling the construction of an update call without
    /// passing all arguments.
    pub fn update<S: Into<String>>(
        &self,
        canister_id: &Principal,
        method_name: S,
    ) -> UpdateBuilder {
        UpdateBuilder::new(self, canister_id.clone(), method_name.into())
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
        QueryBuilder::new(self, canister_id.clone(), method_name.into())
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
    pub canister_id: Principal,
    pub method_name: String,
    pub arg: Vec<u8>,
    pub ingress_expiry_datetime: Option<u64>,
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
        let mut request_accepted = false;
        loop {
            match self.agent.request_status_raw(&request_id).await? {
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
                RequestStatusResponse::Received | RequestStatusResponse::Processing => {
                    // The system will return Unknown until the request is accepted
                    // and we generally cannot know how long that will take.
                    // State transitions between Received and Processing may be
                    // instantaneous. Therefore, once we know the request is accepted,
                    // we restart the waiter so the request does not time out.
                    if !request_accepted {
                        waiter
                            .restart()
                            .map_err(|_| AgentError::WaiterRestartError())?;
                        request_accepted = true;
                    }
                }
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
