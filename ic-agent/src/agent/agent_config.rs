use reqwest::Client;
use url::Url;

use crate::{
    agent::{NonceFactory, NonceGenerator},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

use super::{route_provider::RouteProvider, HttpService};

/// The default for `AgentConfig::max_certificate_delegation_age`: 30 days, the same bound
/// `@icp-sdk/core` (the JavaScript agent) applies.
///
/// Replicas refresh their NNS delegation every few minutes, and immediately when it no longer
/// matches the subnet's state (e.g. after a canister migration), so delegations seen in practice
/// are minutes old. The bound is deliberately much looser than that so that an NNS outage, during
/// which replicas keep serving their last delegation, does not make every other subnet unverifiable.
pub(crate) const DEFAULT_MAX_CERTIFICATE_DELEGATION_AGE: Duration =
    Duration::from_secs(30 * 24 * 60 * 60);

/// A configuration for an agent.
#[non_exhaustive]
pub struct AgentConfig {
    /// See [`with_nonce_factory`](super::AgentBuilder::with_nonce_factory).
    pub nonce_factory: Arc<dyn NonceGenerator>,
    /// See [`with_identity`](super::AgentBuilder::with_identity).
    pub identity: Arc<dyn Identity>,
    /// See [`with_ingress_expiry`](super::AgentBuilder::with_ingress_expiry).
    pub ingress_expiry: Duration,
    /// See [`with_max_certificate_delegation_age`](super::AgentBuilder::with_max_certificate_delegation_age).
    pub max_certificate_delegation_age: Duration,
    /// See [`with_http_client`](super::AgentBuilder::with_http_client).
    pub client: Option<Client>,
    /// See [`with_route_provider`](super::AgentBuilder::with_route_provider).
    pub route_provider: Option<Arc<dyn RouteProvider>>,
    /// See [`verify_query_signatures`](super::AgentBuilder::with_verify_query_signatures).
    pub verify_query_signatures: bool,
    /// See [`with_max_concurrent_requests`](super::AgentBuilder::with_max_concurrent_requests).
    pub max_concurrent_requests: usize,
    /// See [`with_max_response_body_size`](super::AgentBuilder::with_max_response_body_size).
    pub max_response_body_size: Option<usize>,
    /// See [`with_max_tcp_error_retries`](super::AgentBuilder::with_max_tcp_error_retries).
    pub max_tcp_error_retries: usize,
    /// See [`with_arc_http_middleware`](super::AgentBuilder::with_arc_http_middleware).
    pub http_service: Option<Arc<dyn HttpService>>,
    /// See [`with_max_polling_time`](super::AgentBuilder::with_max_polling_time).
    pub max_polling_time: Duration,
    /// See [`with_background_dynamic_routing`](super::AgentBuilder::with_background_dynamic_routing).
    pub background_dynamic_routing: bool,
    /// See [`with_url`](super::AgentBuilder::with_url).
    pub url: Option<Url>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            nonce_factory: Arc::new(NonceFactory::random()),
            identity: Arc::new(AnonymousIdentity {}),
            ingress_expiry: Duration::from_secs(3 * 60),
            max_certificate_delegation_age: DEFAULT_MAX_CERTIFICATE_DELEGATION_AGE,
            client: None,
            http_service: None,
            verify_query_signatures: true,
            max_concurrent_requests: 50,
            route_provider: None,
            max_response_body_size: None,
            max_tcp_error_retries: 0,
            max_polling_time: Duration::from_secs(60 * 5),
            background_dynamic_routing: false,
            url: None,
        }
    }
}
