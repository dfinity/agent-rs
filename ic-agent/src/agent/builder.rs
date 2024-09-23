use url::Url;

use crate::{
    agent::{agent_config::AgentConfig, Agent},
    AgentError, Identity, NonceFactory, NonceGenerator,
};
use std::sync::Arc;

use super::route_provider::RouteProvider;

/// A builder for an [`Agent`].
#[derive(Default)]
pub struct AgentBuilder {
    config: AgentConfig,
}

impl AgentBuilder {
    /// Create an instance of [Agent] with the information from this builder.
    pub fn build(self) -> Result<Agent, AgentError> {
        Agent::new(self.config)
    }

    /// Set the dynamic transport layer for the [`Agent`], performing continuous discovery of the API boundary nodes and routing traffic via them based on latency.
    #[cfg(feature = "_internal_dynamic-routing")]
    pub async fn with_discovery_transport(self, client: reqwest::Client) -> Self {
        use crate::agent::route_provider::dynamic_routing::{
            dynamic_route_provider::{DynamicRouteProviderBuilder, IC0_SEED_DOMAIN},
            node::Node,
            snapshot::latency_based_routing::LatencyRoutingSnapshot,
        };
        // TODO: This is a temporary solution to get the seed node.
        let seed = Node::new(IC0_SEED_DOMAIN).unwrap();

        let route_provider = DynamicRouteProviderBuilder::new(
            LatencyRoutingSnapshot::new(),
            vec![seed],
            client.clone(),
        )
        .build()
        .await;

        let route_provider = Arc::new(route_provider) as Arc<dyn RouteProvider>;

        self.with_arc_route_provider(route_provider)
            .with_http_client(client)
    }

    /// Set the URL of the [Agent].
    pub fn with_url<S: Into<String>>(self, url: S) -> Self {
        self.with_route_provider(url.into().parse::<Url>().unwrap())
    }

    /// Add a NonceFactory to this Agent. By default, no nonce is produced.
    pub fn with_nonce_factory(self, nonce_factory: NonceFactory) -> AgentBuilder {
        self.with_nonce_generator(nonce_factory)
    }

    /// Same as [`Self::with_nonce_factory`], but for any `NonceGenerator` type
    pub fn with_nonce_generator<N: 'static + NonceGenerator>(
        self,
        nonce_factory: N,
    ) -> AgentBuilder {
        self.with_arc_nonce_generator(Arc::new(nonce_factory))
    }

    /// Same as [`Self::with_nonce_generator`], but reuses an existing `Arc`.
    pub fn with_arc_nonce_generator(
        mut self,
        nonce_factory: Arc<dyn NonceGenerator>,
    ) -> AgentBuilder {
        self.config.nonce_factory = Arc::new(nonce_factory);
        self
    }

    /// Add an identity provider for signing messages. This is required.
    pub fn with_identity<I>(self, identity: I) -> Self
    where
        I: 'static + Identity,
    {
        self.with_arc_identity(Arc::new(identity))
    }

    /// Same as [`Self::with_identity`], but reuses an existing box
    pub fn with_boxed_identity(self, identity: Box<dyn Identity>) -> Self {
        self.with_arc_identity(Arc::from(identity))
    }

    /// Same as [`Self::with_identity`], but reuses an existing `Arc`
    pub fn with_arc_identity(mut self, identity: Arc<dyn Identity>) -> Self {
        self.config.identity = identity;
        self
    }

    /// Provides a _default_ ingress expiry. This is the delta that will be applied
    /// at the time an update or query is made. The default expiry cannot be a
    /// fixed system time. This is also used when checking certificate timestamps.
    ///
    /// The timestamp corresponding to this duration may be rounded in order to reduce
    /// cache misses. The current implementation rounds to the nearest minute if the
    /// expiry is more than a minute, but this is not guaranteed.
    pub fn with_ingress_expiry(mut self, ingress_expiry: Option<std::time::Duration>) -> Self {
        self.config.ingress_expiry = ingress_expiry;
        self
    }

    /// Allows disabling query signature verification. Query signatures improve resilience but require
    /// a separate read-state call to fetch node keys.
    pub fn with_verify_query_signatures(mut self, verify_query_signatures: bool) -> Self {
        self.config.verify_query_signatures = verify_query_signatures;
        self
    }

    /// Sets the maximum number of requests that the agent will make concurrently. The replica is configured
    /// to only permit 50 concurrent requests per client. Set this value lower if you have multiple agents,
    /// to avoid the slowdown of retrying any 429 errors.
    pub fn with_max_concurrent_requests(mut self, max_concurrent_requests: usize) -> Self {
        self.config.max_concurrent_requests = max_concurrent_requests;
        self
    }

    /// Add a `RouteProvider` to this agent, to provide the URLs of boundary nodes.
    pub fn with_route_provider(self, provider: impl RouteProvider + 'static) -> Self {
        self.with_arc_route_provider(Arc::new(provider))
    }

    /// Same as [`Self::with_route_provider`], but reuses an existing `Arc`.
    pub fn with_arc_route_provider(mut self, provider: Arc<dyn RouteProvider>) -> Self {
        self.config.route_provider = Some(provider);
        self
    }

    /// Provide a pre-configured HTTP client to use. Use this to set e.g. HTTP timeouts or proxy configuration.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.config.client = Some(client);
        self
    }

    /// Retry up to the specified number of times upon encountering underlying TCP errors.
    pub fn with_max_tcp_error_retries(mut self, retries: usize) -> Self {
        self.config.max_tcp_error_retries = retries;
        self
    }

    /// Don't accept HTTP bodies any larger than `max_size` bytes.
    pub fn with_max_response_body_size(mut self, max_size: usize) -> Self {
        self.config.max_response_body_size = Some(max_size);
        self
    }
}
