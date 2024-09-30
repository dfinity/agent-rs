use reqwest::Client;

use crate::{
    agent::{NonceFactory, NonceGenerator},
    identity::{anonymous::AnonymousIdentity, Identity},
};
use std::{sync::Arc, time::Duration};

use super::{route_provider::RouteProvider, HttpService};

/// A configuration for an agent.
#[non_exhaustive]
pub struct AgentConfig {
    /// See [`with_nonce_factory`](super::AgentBuilder::with_nonce_factory).
    pub nonce_factory: Arc<dyn NonceGenerator>,
    /// See [`with_identity`](super::AgentBuilder::with_identity).
    pub identity: Arc<dyn Identity>,
    /// See [`with_ingress_expiry`](super::AgentBuilder::with_ingress_expiry).
    pub ingress_expiry: Option<Duration>,
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
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            nonce_factory: Arc::new(NonceFactory::random()),
            identity: Arc::new(AnonymousIdentity {}),
            ingress_expiry: None,
            client: None,
            http_service: None,
            verify_query_signatures: true,
            max_concurrent_requests: 50,
            route_provider: None,
            max_response_body_size: None,
            max_tcp_error_retries: 0,
        }
    }
}
