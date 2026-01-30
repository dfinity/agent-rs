//! An implementation of [`RouteProvider`] for dynamic generation of routing urls.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use candid::Principal;
use futures_util::FutureExt;
use stop_token::StopSource;
use thiserror::Error;
use url::Url;

use crate::{
    agent::{
        route_provider::{
            dynamic_routing::{
                health_check::{HealthCheck, HealthChecker, HealthManagerActor},
                messages::FetchedNodes,
                node::Node,
                nodes_fetch::{Fetch, NodesFetchActor, NodesFetcher},
                snapshot::{
                    latency_based_routing::LatencyRoutingSnapshot,
                    routing_snapshot::RoutingSnapshot,
                },
                type_aliases::AtomicSwap,
            },
            RouteProvider, RoutesStats,
        },
        HttpService,
    },
    AgentError,
};

/// The default seed domain for boundary node discovery.
#[allow(unused)]
pub const IC0_SEED_DOMAIN: &str = "ic0.app";

const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

const FETCH_PERIOD: Duration = Duration::from_secs(5);
const FETCH_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const TIMEOUT_AWAIT_HEALTHY_SEED: Duration = Duration::from_millis(1000);
#[allow(unused)]
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(1);
const HEALTH_CHECK_PERIOD: Duration = Duration::from_secs(1);
#[allow(unused)]
const DYNAMIC_ROUTE_PROVIDER: &str = "DynamicRouteProvider";

/// A dynamic route provider.
/// It spawns the discovery service (`NodesFetchActor`) for fetching the latest nodes topology.
/// It also spawns the `HealthManagerActor`, which orchestrates the health check tasks for each node and updates routing snapshot.
#[derive(Debug)]
pub struct DynamicRouteProvider {
    /// Fetcher for fetching the latest nodes topology.
    fetcher: Arc<dyn Fetch>,
    /// Periodicity of fetching the latest nodes topology.
    fetch_period: Duration,
    /// Interval for retrying fetching the nodes in case of error.
    fetch_retry_interval: Duration,
    /// Health checker for checking the health of the nodes.
    checker: Arc<dyn HealthCheck>,
    /// Periodicity of checking the health of the nodes.
    check_period: Duration,
    /// Snapshot of the routing nodes.
    routing_snapshot: AtomicSwap<LatencyRoutingSnapshot>,
    /// Initial seed nodes, which are used for the initial fetching of the nodes.
    seeds: Vec<Node>,
    /// Cancellation token for stopping the spawned tasks.
    token: StopSource,
    /// Flag indicating whether background tasks have been started.
    started: Arc<AtomicBool>,
}

/// An error that occurred when the `DynamicRouteProvider` service was running.
#[derive(Error, Debug)]
pub enum DynamicRouteProviderError {
    /// An error when fetching topology of the API nodes.
    #[error("An error when fetching API nodes: {0}")]
    NodesFetchError(String),
    /// An error when checking API node's health.
    #[error("An error when checking API node's health: {0}")]
    HealthCheckError(String),
}

/// A builder for the `DynamicRouteProvider`.
pub struct DynamicRouteProviderBuilder {
    fetcher: Arc<dyn Fetch>,
    fetch_period: Duration,
    fetch_retry_interval: Duration,
    checker: Arc<dyn HealthCheck>,
    check_period: Duration,
    routing_snapshot: AtomicSwap<LatencyRoutingSnapshot>,
    seeds: Vec<Node>,
}

impl DynamicRouteProviderBuilder {
    /// Creates a new instance of the builder with a HTTP client.
    /// Use this when you want to share an HTTP client with other components (e.g., the Agent)
    /// or when you need custom HTTP client configuration.
    /// For full control over fetcher and checker, use [`Self::from_components`].
    pub fn new(seeds: Vec<Node>, http_client: Arc<dyn HttpService>) -> Self {
        let fetcher = Arc::new(NodesFetcher::new(
            http_client.clone(),
            Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap(),
            None,
        ));
        let checker = Arc::new(HealthChecker::new(
            http_client,
            #[cfg(not(target_family = "wasm"))]
            HEALTH_CHECK_TIMEOUT,
        ));
        Self::from_components(seeds, fetcher, checker)
    }

    /// Creates a new instance of the builder with custom fetcher and checker implementations.
    /// Use this when you need full control over the node fetching and health checking behavior.
    pub fn from_components(
        seeds: Vec<Node>,
        fetcher: Arc<dyn Fetch>,
        checker: Arc<dyn HealthCheck>,
    ) -> Self {
        Self {
            fetcher,
            fetch_period: FETCH_PERIOD,
            fetch_retry_interval: FETCH_RETRY_INTERVAL,
            checker,
            check_period: HEALTH_CHECK_PERIOD,
            seeds,
            routing_snapshot: Arc::new(ArcSwap::from_pointee(LatencyRoutingSnapshot::new())),
        }
    }

    /// Sets the fetcher of the nodes in the topology.
    #[allow(unused)]
    pub fn with_fetcher(mut self, fetcher: Arc<dyn Fetch>) -> Self {
        self.fetcher = fetcher;
        self
    }

    /// Sets the fetching periodicity.
    pub fn with_fetch_period(mut self, period: Duration) -> Self {
        self.fetch_period = period;
        self
    }

    /// Sets the node health checker.
    #[allow(unused)]
    pub fn with_checker(mut self, checker: Arc<dyn HealthCheck>) -> Self {
        self.checker = checker;
        self
    }

    /// Sets the periodicity of node health checking.
    pub fn with_check_period(mut self, period: Duration) -> Self {
        self.check_period = period;
        self
    }

    /// Builds an instance of the `DynamicRouteProvider`.
    ///
    /// The provider is constructed but background tasks are not started yet.
    /// You can either:
    /// - Call `.start().await` explicitly to start background tasks and wait for initialization
    /// - Just use the provider - it will auto-start on first `route()` call (lazy initialization)
    pub fn build(self) -> DynamicRouteProvider {
        DynamicRouteProvider {
            fetcher: self.fetcher,
            fetch_period: self.fetch_period,
            fetch_retry_interval: self.fetch_retry_interval,
            checker: self.checker,
            check_period: self.check_period,
            routing_snapshot: self.routing_snapshot,
            seeds: self.seeds,
            token: StopSource::new(),
            started: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl RouteProvider for DynamicRouteProvider {
    fn route(&self) -> Result<Url, AgentError> {
        // Lazy initialization: auto-start if not already started
        self.ensure_started();

        let snapshot = self.routing_snapshot.load();
        let node = snapshot.next_node().ok_or_else(|| {
            AgentError::RouteProviderError("No healthy API nodes found.".to_string())
        })?;
        Ok(node.to_routing_url())
    }

    fn n_ordered_routes(&self, n: usize) -> Result<Vec<Url>, AgentError> {
        // Lazy initialization: auto-start if not already started
        self.ensure_started();

        let snapshot = self.routing_snapshot.load();
        let nodes = snapshot.next_n_nodes(n);
        if nodes.is_empty() {
            return Err(AgentError::RouteProviderError(
                "No healthy API nodes found.".to_string(),
            ));
        };
        let urls = nodes.iter().map(|n| n.to_routing_url()).collect();
        Ok(urls)
    }

    fn routes_stats(&self) -> RoutesStats {
        let snapshot = self.routing_snapshot.load();
        snapshot.routes_stats()
    }
}

/// Configuration and dependencies for running background tasks.
struct BackgroundTaskConfig {
    fetcher: Arc<dyn Fetch>,
    checker: Arc<dyn HealthCheck>,
    routing_snapshot: AtomicSwap<LatencyRoutingSnapshot>,
    seeds: Vec<Node>,
    fetch_period: Duration,
    fetch_retry_interval: Duration,
    check_period: Duration,
    token: stop_token::StopToken,
}

impl DynamicRouteProvider {
    /// Explicitly starts the background tasks and waits for initial health checks to complete.
    ///
    /// This method is optional - if you don't call it, the provider will auto-start
    /// on the first `route()` call. However, calling `start()` explicitly gives you:
    /// - Control over when initialization happens
    /// - Ability to await initial health checks (waits up to 1 second for seeds)
    /// - Better error visibility during startup
    ///
    /// This method is idempotent - calling it multiple times is safe.
    pub async fn start(&self) {
        // Check if already started
        if self.started.swap(true, Ordering::AcqRel) {
            // Already started, nothing to do
            return;
        }

        // Start the background tasks and wait for initial health checks
        self.run().await;
    }

    /// Ensures background tasks are started (lazy initialization).
    /// Called automatically by route() if not explicitly started.
    fn ensure_started(&self) {
        // Try to atomically change false -> true
        // If we succeed, we won the race and should start
        // If we fail, it's already true (someone else started it)
        if self
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Already started, nothing to do
            return;
        }

        // We won the race - start the background tasks
        // Clone what we need for the spawned task
        let config = BackgroundTaskConfig {
            fetcher: Arc::clone(&self.fetcher),
            checker: Arc::clone(&self.checker),
            routing_snapshot: Arc::clone(&self.routing_snapshot),
            seeds: self.seeds.clone(),
            fetch_period: self.fetch_period,
            fetch_retry_interval: self.fetch_retry_interval,
            check_period: self.check_period,
            token: self.token.token(),
        };

        // Spawn the initialization - don't wait (fire-and-forget)
        crate::util::spawn(async move {
            Self::run_background_tasks(config).await;
        });
    }

    /// Internal implementation that starts the background tasks and waits for initialization.
    async fn run(&self) {
        let config = BackgroundTaskConfig {
            fetcher: Arc::clone(&self.fetcher),
            checker: Arc::clone(&self.checker),
            routing_snapshot: Arc::clone(&self.routing_snapshot),
            seeds: self.seeds.clone(),
            fetch_period: self.fetch_period,
            fetch_retry_interval: self.fetch_retry_interval,
            check_period: self.check_period,
            token: self.token.token(),
        };
        Self::run_background_tasks(config).await;
    }

    /// Starts two background tasks:
    /// - Task1: `NodesFetchActor`
    ///   - Periodically fetches existing API nodes (gets latest nodes topology) and sends discovered nodes to `HealthManagerActor`.
    /// - Task2: `HealthManagerActor`:
    ///   - Listens to the fetched nodes messages from the `NodesFetchActor`.
    ///   - Starts/stops health check tasks (`HealthCheckActors`) based on the newly added/removed nodes.
    ///   - These spawned health check tasks periodically update the snapshot with the latest node health info.
    async fn run_background_tasks(config: BackgroundTaskConfig) {
        log!(info, "{DYNAMIC_ROUTE_PROVIDER}: started ...");
        // Communication channel between NodesFetchActor and HealthManagerActor.
        let (fetch_sender, fetch_receiver) = async_watch::channel(None);

        // Communication channel with HealthManagerActor to receive info about healthy seed nodes (used only once).
        let (init_sender, init_receiver) = async_channel::bounded(1);

        // Start the receiving part first.
        let health_manager_actor = HealthManagerActor::new(
            Arc::clone(&config.checker),
            config.check_period,
            Arc::clone(&config.routing_snapshot),
            fetch_receiver,
            init_sender,
            config.token.clone(),
        );
        crate::util::spawn(async move { health_manager_actor.run().await });

        // Dispatch all seed nodes for initial health checks
        if let Err(_err) = fetch_sender.send(Some(FetchedNodes {
            nodes: config.seeds.clone(),
        })) {
            log!(
                error,
                "{DYNAMIC_ROUTE_PROVIDER}: failed to send results to HealthManager: {_err:?}"
            );
        }

        // Try await for healthy seeds.
        let _start = Instant::now();
        futures_util::select! {
            _ = crate::util::sleep(TIMEOUT_AWAIT_HEALTHY_SEED).fuse() => {
                log!(
                    warn,
                    "{DYNAMIC_ROUTE_PROVIDER}: no healthy seeds found within {:?}",
                    _start.elapsed()
                );
            }
            _ = init_receiver.recv().fuse() => {
                log!(
                    info,
                    "{DYNAMIC_ROUTE_PROVIDER}: found healthy seeds within {:?}",
                    _start.elapsed()
                );
            }
        }
        // We can close the channel now.
        init_receiver.close();

        let fetch_actor = NodesFetchActor::new(
            Arc::clone(&config.fetcher),
            config.fetch_period,
            config.fetch_retry_interval,
            fetch_sender,
            Arc::clone(&config.routing_snapshot),
            config.token,
        );
        crate::util::spawn(async move { fetch_actor.run().await });
        log!(
            info,
            "{DYNAMIC_ROUTE_PROVIDER}: NodesFetchActor and HealthManagerActor started successfully"
        );
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use candid::Principal;
    use std::{
        sync::{Arc, Once},
        time::{Duration, Instant},
    };
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    use crate::{
        agent::route_provider::{
            dynamic_routing::{
                dynamic_route_provider::{
                    DynamicRouteProviderBuilder, IC0_SEED_DOMAIN, MAINNET_ROOT_SUBNET_ID,
                },
                node::Node,
                test_utils::{
                    assert_routed_domains, route_n_times, wait_for_routing_to_domains,
                    NodeHealthCheckerMock, NodesFetcherMock,
                },
            },
            RouteProvider, RoutesStats,
        },
        Agent, AgentError,
    };

    static TRACING_INIT: Once = Once::new();

    pub fn setup_tracing() {
        TRACING_INIT.call_once(|| {
            FmtSubscriber::builder()
                .with_max_level(Level::TRACE)
                .with_test_writer()
                .init();
        });
    }

    async fn assert_no_routing_via_domains(
        route_provider: Arc<dyn RouteProvider>,
        excluded_domains: Vec<&str>,
        timeout: Duration,
        route_call_interval: Duration,
    ) {
        if excluded_domains.is_empty() {
            panic!("List of excluded domains can't be empty");
        }

        let route_calls = 30;
        let start = Instant::now();

        while start.elapsed() < timeout {
            let routed_domains = (0..route_calls)
                .map(|_| {
                    route_provider.route().map(|url| {
                        let domain = url.domain().expect("no domain name in url");
                        domain.to_string()
                    })
                })
                .collect::<Result<Vec<String>, _>>()
                .unwrap_or_default();

            // Exit when excluded domains are not used for routing any more.
            if !routed_domains.is_empty()
                && !routed_domains
                    .iter()
                    .any(|d| excluded_domains.contains(&d.as_str()))
            {
                return;
            }

            tokio::time::sleep(route_call_interval).await;
        }
        panic!("Expected excluded domains {excluded_domains:?} are still observed in routing over the last {route_calls} calls");
    }

    #[tokio::test]
    async fn test_mainnet() {
        // Setup.
        setup_tracing();
        let seed = Node::new(IC0_SEED_DOMAIN).unwrap();
        let http_client = Arc::new(reqwest::Client::new());
        let route_provider = DynamicRouteProviderBuilder::new(vec![seed], http_client).build();
        route_provider.start().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let route_provider = Arc::new(route_provider) as Arc<dyn RouteProvider>;
        let agent = Agent::builder()
            .with_arc_route_provider(Arc::clone(&route_provider))
            .build()
            .expect("failed to create an agent");
        let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();
        // Assert that seed (ic0.app) is not used for routing. Henceforth, only discovered API nodes are used.
        assert_no_routing_via_domains(
            Arc::clone(&route_provider),
            vec![IC0_SEED_DOMAIN],
            Duration::from_secs(40),
            Duration::from_secs(2),
        )
        .await;
        // Act: perform /read_state call via dynamically discovered API BNs.
        let api_bns = agent
            .fetch_api_boundary_nodes_by_subnet_id(subnet_id)
            .await
            .expect("failed to fetch api boundary nodes");
        assert!(!api_bns.is_empty());
    }

    #[tokio::test]
    async fn test_routing_with_topology_and_node_health_updates() {
        // Setup.
        setup_tracing();
        let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
        // Set nodes fetching params: topology, fetching periodicity.
        let fetcher = Arc::new(NodesFetcherMock::new());
        fetcher.overwrite_nodes(vec![node_1.clone()]);
        let fetch_interval = Duration::from_secs(2);
        // Set health checking params: healthy nodes, checking periodicity.
        let checker = Arc::new(NodeHealthCheckerMock::new());
        let check_interval = Duration::from_secs(1);
        // A single healthy node exists in the topology. This node happens to be the seed node.
        fetcher.overwrite_nodes(vec![node_1.clone()]);
        checker.overwrite_healthy_nodes(vec![node_1.clone()]);
        // Configure RouteProvider
        let client = reqwest::Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(vec![node_1.clone()], Arc::new(client))
                .with_fetcher(fetcher.clone())
                .with_checker(checker.clone())
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build();
        route_provider.start().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let route_provider = Arc::new(route_provider);

        // This time span is required for the snapshot to be fully updated with the new nodes and their health info.
        let snapshot_update_duration = fetch_interval + 2 * check_interval;

        // Test 1: multiple route() calls return a single domain=ic0.app.
        // Only a single node exists, which is initially healthy.
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain()]);
        assert_eq!(route_provider.routes_stats(), RoutesStats::new(1, Some(1)));

        // Test 2: multiple route() calls return 3 different domains.
        // Two healthy nodes are added to the topology.
        // With latency-based routing, we use more calls to ensure all nodes are likely visited.
        let node_2 = Node::new("api1.com").unwrap();
        let node_3 = Node::new("api2.com").unwrap();
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(30, Arc::clone(&route_provider)); // Increased for probabilistic routing
        assert_routed_domains(
            routed_domains,
            vec![node_1.domain(), node_2.domain(), node_3.domain()],
        );
        assert_eq!(route_provider.routes_stats(), RoutesStats::new(3, Some(3)));

        // Test 3:  multiple route() calls return 2 different domains.
        // One node is set to unhealthy.
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(20, Arc::clone(&route_provider)); // Increased for probabilistic routing
        assert_routed_domains(routed_domains, vec![node_1.domain(), node_3.domain()]);
        assert_eq!(route_provider.routes_stats(), RoutesStats::new(3, Some(2)));

        // Test 4: multiple route() calls return 3 different domains.
        // Unhealthy node is set back to healthy.
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(30, Arc::clone(&route_provider)); // Increased for probabilistic routing
        assert_routed_domains(
            routed_domains,
            vec![node_1.domain(), node_2.domain(), node_3.domain()],
        );
        assert_eq!(route_provider.routes_stats(), RoutesStats::new(3, Some(3)));

        // Test 5: multiple route() calls return 3 different domains.
        // One healthy node is added, but another one goes unhealthy.
        let node_4 = Node::new("api3.com").unwrap();
        checker.overwrite_healthy_nodes(vec![node_2.clone(), node_3.clone(), node_4.clone()]);
        fetcher.overwrite_nodes(vec![
            node_1.clone(),
            node_2.clone(),
            node_3.clone(),
            node_4.clone(),
        ]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(30, Arc::clone(&route_provider)); // Increased for probabilistic routing
        assert_routed_domains(
            routed_domains,
            vec![node_2.domain(), node_3.domain(), node_4.domain()],
        );
        assert_eq!(route_provider.routes_stats(), RoutesStats::new(4, Some(3)));

        // Test 6: multiple route() calls return a single domain=api1.com.
        // One node is set to unhealthy and one is removed from the topology.
        checker.overwrite_healthy_nodes(vec![node_2.clone(), node_3.clone()]);
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone(), node_4.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_2.domain()]);
        assert_eq!(route_provider.routes_stats(), RoutesStats::new(3, Some(1)));
    }

    #[tokio::test]
    async fn test_route_with_initially_unhealthy_seeds_becoming_healthy() {
        // Setup.
        setup_tracing();
        let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
        let node_2 = Node::new("api1.com").unwrap();
        // Set nodes fetching params: topology, fetching periodicity.
        let fetcher = Arc::new(NodesFetcherMock::new());
        let fetch_interval = Duration::from_secs(2);
        // Set health checking params: healthy nodes, checking periodicity.
        let checker = Arc::new(NodeHealthCheckerMock::new());
        let check_interval = Duration::from_secs(1);
        // Two nodes exist, which are initially unhealthy.
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone()]);
        checker.overwrite_healthy_nodes(vec![]);
        // Configure RouteProvider
        let route_provider = DynamicRouteProviderBuilder::from_components(
            vec![node_1.clone(), node_2.clone()],
            fetcher,
            checker.clone(),
        )
        .with_fetch_period(fetch_interval)
        .with_check_period(check_interval)
        .build();
        route_provider.start().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let route_provider = Arc::new(route_provider);

        // Test 1: calls to route() return an error, as no healthy seeds exist.
        for _ in 0..4 {
            tokio::time::sleep(check_interval).await;
            let result = route_provider.route();
            assert_eq!(
                result.unwrap_err(),
                AgentError::RouteProviderError("No healthy API nodes found.".to_string())
            );
        }

        // Test 2: calls to route() return both seeds, as they become healthy.
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone()]);
        tokio::time::sleep(3 * check_interval).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain(), node_2.domain()]);
    }

    #[tokio::test]
    async fn test_routing_with_no_healthy_nodes_returns_an_error() {
        // Setup.
        setup_tracing();
        let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
        // Set nodes fetching params: topology, fetching periodicity.
        let fetcher = Arc::new(NodesFetcherMock::new());
        let fetch_interval = Duration::from_secs(2);
        // Set health checking params: healthy nodes, checking periodicity.
        let checker = Arc::new(NodeHealthCheckerMock::new());
        let check_interval = Duration::from_secs(1);
        // A single seed node which is initially healthy.
        fetcher.overwrite_nodes(vec![node_1.clone()]);
        checker.overwrite_healthy_nodes(vec![node_1.clone()]);
        // Configure RouteProvider
        let client = reqwest::Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(vec![node_1.clone()], Arc::new(client))
                .with_fetcher(fetcher)
                .with_checker(checker.clone())
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build();
        route_provider.start().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let route_provider = Arc::new(route_provider);

        // Test 1: multiple route() calls return a single domain=ic0.app, as the seed is healthy.
        tokio::time::sleep(2 * check_interval).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain()]);

        // Test 2: calls to route() return an error, as no healthy nodes exist.
        checker.overwrite_healthy_nodes(vec![]);
        tokio::time::sleep(2 * check_interval).await;
        for _ in 0..4 {
            let result = route_provider.route();
            assert_eq!(
                result.unwrap_err(),
                AgentError::RouteProviderError("No healthy API nodes found.".to_string())
            );
        }
    }

    #[tokio::test]
    async fn test_route_with_no_healthy_seeds_errors() {
        // Setup.
        setup_tracing();
        let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
        // Set nodes fetching params: topology, fetching periodicity.
        let fetcher = Arc::new(NodesFetcherMock::new());
        let fetch_interval = Duration::from_secs(2);
        // Set health checking params: healthy nodes, checking periodicity.
        let checker = Arc::new(NodeHealthCheckerMock::new());
        let check_interval = Duration::from_secs(1);
        // No healthy seed nodes present, this should lead to errors.
        fetcher.overwrite_nodes(vec![]);
        checker.overwrite_healthy_nodes(vec![]);
        // Configure RouteProvider
        let client = reqwest::Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(vec![node_1.clone()], Arc::new(client))
                .with_fetcher(fetcher)
                .with_checker(checker)
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build();

        // Test: calls to route() return an error, as no healthy seeds exist.
        for _ in 0..4 {
            tokio::time::sleep(check_interval).await;
            let result = route_provider.route();
            assert_eq!(
                result.unwrap_err(),
                AgentError::RouteProviderError("No healthy API nodes found.".to_string())
            );
        }
    }

    #[tokio::test]
    async fn test_route_with_one_healthy_and_one_unhealthy_seed() {
        // Setup.
        setup_tracing();
        let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
        let node_2 = Node::new("api1.com").unwrap();
        // Set nodes fetching params: topology, fetching periodicity.
        let fetcher = Arc::new(NodesFetcherMock::new());
        let fetch_interval = Duration::from_secs(2);
        // Set health checking params: healthy nodes, checking periodicity.
        let checker = Arc::new(NodeHealthCheckerMock::new());
        let check_interval = Duration::from_secs(1);
        // One healthy seed is present, it should be discovered during the initialization time.
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone()]);
        checker.overwrite_healthy_nodes(vec![node_1.clone()]);
        // Configure RouteProvider
        let route_provider = DynamicRouteProviderBuilder::from_components(
            vec![node_1.clone(), node_2.clone()],
            fetcher,
            checker.clone(),
        )
        .with_fetch_period(fetch_interval)
        .with_check_period(check_interval)
        .build();
        route_provider.start().await;
        let route_provider = Arc::new(route_provider);

        // Test 1: Wait for routing to stabilize and verify only the healthy seed ic0.app is returned.
        wait_for_routing_to_domains(
            Arc::clone(&route_provider),
            vec![node_1.domain()],
            Duration::from_secs(3),
        )
        .await;

        // Test 2: Make the unhealthy seed healthy and wait for routing to reflect both healthy seeds.
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone()]);
        wait_for_routing_to_domains(
            Arc::clone(&route_provider),
            vec![node_1.domain(), node_2.domain()],
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn test_routing_with_an_empty_fetched_list_of_api_nodes() {
        // Check resiliency to an empty list of fetched API nodes (this should never happen in normal IC operation).
        // Setup.
        setup_tracing();
        let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
        // Set nodes fetching params: topology, fetching periodicity.
        let fetcher = Arc::new(NodesFetcherMock::new());
        let fetch_interval = Duration::from_secs(2);
        // Set health checking params: healthy nodes, checking periodicity.
        let checker = Arc::new(NodeHealthCheckerMock::new());
        let check_interval = Duration::from_secs(1);
        // One healthy seed is initially present, but the topology has no node.
        fetcher.overwrite_nodes(vec![]);
        checker.overwrite_healthy_nodes(vec![node_1.clone()]);
        // Configure RouteProvider
        let client = reqwest::Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(vec![node_1.clone()], Arc::new(client))
                .with_fetcher(fetcher.clone())
                .with_checker(checker.clone())
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build();
        route_provider.start().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let route_provider = Arc::new(route_provider);

        // This time span is required for the snapshot to be fully updated with the new nodes topology and health info.
        let snapshot_update_duration = fetch_interval + 2 * check_interval;

        // Test 1: multiple route() calls return a single domain=ic0.app.
        // HealthManagerActor shouldn't update the snapshot, if the list of fetched nodes is empty, thus we observe the healthy seed.
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain()]);

        // Test 2: multiple route() calls should now return 3 different domains.
        // Three nodes are added to the topology, i.e. now the fetched nodes list is non-empty.
        let node_2 = Node::new("api1.com").unwrap();
        let node_3 = Node::new("api2.com").unwrap();
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(30, Arc::clone(&route_provider)); // Increased for probabilistic routing
        assert_routed_domains(
            routed_domains,
            vec![node_1.domain(), node_2.domain(), node_3.domain()],
        );
    }
}

// - none of the seeds [] are healthy
// - none of the API node [] is healthy
// - return a vector of errors: HealthCheckErrors, FetchErrors, etc.
