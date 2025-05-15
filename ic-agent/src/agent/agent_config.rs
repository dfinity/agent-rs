use backoff::backoff::Backoff;
use reqwest::Client;
use url::Url;

use crate::{
    agent::{NonceFactory, NonceGenerator},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

use super::{route_provider::RouteProvider, HttpService};

/// A helper trait for cloning backoff policies.
pub trait CloneableBackoff: Backoff + Send + Sync {
    /// Clone the backoff policy into a `Box<dyn CloneableBackoff>`.
    fn clone_box(&self) -> Box<dyn CloneableBackoff>;
}

impl<T> CloneableBackoff for T
where
    T: Backoff + Clone + Send + Sync + 'static,
{
    fn clone_box(&self) -> Box<dyn CloneableBackoff> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn CloneableBackoff> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// A configuration for an agent.
#[non_exhaustive]
pub struct AgentConfig {
    /// See [`with_nonce_factory`](super::AgentBuilder::with_nonce_factory).
    pub nonce_factory: Arc<dyn NonceGenerator>,
    /// See [`with_identity`](super::AgentBuilder::with_identity).
    pub identity: Arc<dyn Identity>,
    /// See [`with_ingress_expiry`](super::AgentBuilder::with_ingress_expiry).
    pub ingress_expiry: Duration,
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
    /// See [`with_retry_policy`](super::AgentBuilder::with_retry_policy).
    pub retry_policy: Option<Box<dyn CloneableBackoff>>,
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
            client: None,
            http_service: None,
            verify_query_signatures: true,
            max_concurrent_requests: 50,
            route_provider: None,
            max_response_body_size: None,
            max_tcp_error_retries: 0,
            retry_policy: None,
            max_polling_time: Duration::from_secs(60 * 5),
            background_dynamic_routing: false,
            url: None,
        }
    }
}
