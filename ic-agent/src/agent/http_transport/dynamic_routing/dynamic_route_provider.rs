//! An implementation of the [`RouteProvider`](crate::agent::http_transport::route_provider::RouteProvider) for dynamic generation of routing urls.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use arc_swap::ArcSwap;
use candid::Principal;
use reqwest::Client;
use tokio::{
    runtime::Handle,
    sync::{mpsc, watch},
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, info, warn};
use url::Url;

use crate::{
    agent::http_transport::{
        dynamic_routing::{
            health_check::{HealthCheck, HealthChecker, HealthManagerActor},
            messages::FetchedNodes,
            node::Node,
            nodes_fetch::{Fetch, NodesFetchActor, NodesFetcher},
            snapshot::routing_snapshot::RoutingSnapshot,
            type_aliases::AtomicSwap,
        },
        route_provider::RouteProvider,
    },
    AgentError,
};

///
pub const IC0_SEED_DOMAIN: &str = "ic0.app";

const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

const FETCH_PERIOD: Duration = Duration::from_secs(5);
const FETCH_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const TIMEOUT_AWAIT_HEALTHY_SEED: Duration = Duration::from_millis(1000);
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);
const HEALTH_CHECK_PERIOD: Duration = Duration::from_secs(1);

const DYNAMIC_ROUTE_PROVIDER: &str = "DynamicRouteProvider";

/// A dynamic route provider.
/// It spawns the discovery service (`NodesFetchActor`) for fetching the latest nodes topology.
/// It also spawns the `HealthManagerActor`, which orchestrates the health check tasks for each node and updates routing snapshot.
#[derive(Debug)]
pub struct DynamicRouteProvider<S> {
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
    routing_snapshot: AtomicSwap<S>,
    /// Task tracker for managing the spawned tasks.
    tracker: TaskTracker,
    /// Initial seed nodes, which are used for the initial fetching of the nodes.
    seeds: Vec<Node>,
    /// Cancellation token for stopping the spawned tasks.
    token: CancellationToken,
}

/// A builder for the `DynamicRouteProvider`.
pub struct DynamicRouteProviderBuilder<S> {
    fetcher: Arc<dyn Fetch>,
    fetch_period: Duration,
    fetch_retry_interval: Duration,
    checker: Arc<dyn HealthCheck>,
    check_period: Duration,
    routing_snapshot: AtomicSwap<S>,
    seeds: Vec<Node>,
}

impl<S> DynamicRouteProviderBuilder<S> {
    /// Creates a new instance of the builder.
    pub fn new(snapshot: S, seeds: Vec<Node>, http_client: Client) -> Self {
        let fetcher = Arc::new(NodesFetcher::new(
            http_client.clone(),
            Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap(),
        ));
        let checker = Arc::new(HealthChecker::new(http_client, HEALTH_CHECK_TIMEOUT));
        Self {
            fetcher,
            fetch_period: FETCH_PERIOD,
            fetch_retry_interval: FETCH_RETRY_INTERVAL,
            checker,
            check_period: HEALTH_CHECK_PERIOD,
            seeds,
            routing_snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
        }
    }

    /// Sets the fetcher of the nodes in the topology.
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
    pub async fn build(self) -> DynamicRouteProvider<S>
    where
        S: RoutingSnapshot + 'static,
    {
        let route_provider = DynamicRouteProvider {
            fetcher: self.fetcher,
            fetch_period: self.fetch_period,
            fetch_retry_interval: self.fetch_retry_interval,
            checker: self.checker,
            check_period: self.check_period,
            routing_snapshot: self.routing_snapshot,
            tracker: TaskTracker::new(),
            seeds: self.seeds,
            token: CancellationToken::new(),
        };

        if let Err(err) = route_provider.run().await {
            error!("{DYNAMIC_ROUTE_PROVIDER}: started in unhealthy state: {err:?}");
        }

        route_provider
    }
}

impl<S> RouteProvider for DynamicRouteProvider<S>
where
    S: RoutingSnapshot + 'static,
{
    fn route(&self) -> Result<Url, AgentError> {
        let snapshot = self.routing_snapshot.load();
        let node = snapshot.next().ok_or_else(|| {
            AgentError::RouteProviderError("No healthy API nodes found.".to_string())
        })?;
        Ok(node.to_routing_url())
    }
}

impl<S> DynamicRouteProvider<S>
where
    S: RoutingSnapshot + 'static,
{
    /// Starts two background tasks:
    /// - Task1: NodesFetchActor
    ///   - Periodically fetches existing API nodes (gets latest nodes topology) and sends discovered nodes to HealthManagerActor.
    /// - Task2: HealthManagerActor:
    ///   - Listens to the fetched nodes messages from the NodesFetchActor.
    ///   - Starts/stops health check tasks (HealthCheckActors) based on the newly added/removed nodes.
    ///   - These spawned health check tasks periodically update the snapshot with the latest node health info.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("{DYNAMIC_ROUTE_PROVIDER}: start run() ");
        // Communication channel between NodesFetchActor and HealthManagerActor.
        let (fetch_sender, fetch_receiver) = watch::channel(None);

        // Communication channel with HealthManagerActor to receive info about healthy seed nodes (used only once).
        let (init_sender, mut init_receiver) = mpsc::channel(1);

        // Start the receiving part first.
        let health_manager_actor = HealthManagerActor::new(
            Arc::clone(&self.checker),
            self.check_period,
            Arc::clone(&self.routing_snapshot),
            fetch_receiver,
            init_sender,
            self.token.clone(),
        );
        self.tracker
            .spawn(async move { health_manager_actor.run().await });

        // Dispatch all seed nodes for initial health checks
        let start = Instant::now();
        if let Err(err) = fetch_sender.send(Some(FetchedNodes {
            nodes: self.seeds.clone(),
        })) {
            error!("{DYNAMIC_ROUTE_PROVIDER}: failed to send results to HealthManager: {err:?}");
        }

        // Try await for healthy seeds.
        let found_healthy_seeds =
            match timeout(TIMEOUT_AWAIT_HEALTHY_SEED, init_receiver.recv()).await {
                Ok(_) => {
                    info!(
                        "{DYNAMIC_ROUTE_PROVIDER}: found healthy seeds within {:?}",
                        start.elapsed()
                    );
                    true
                }
                Err(_) => {
                    warn!(
                        "{DYNAMIC_ROUTE_PROVIDER}: no healthy seeds found within {:?}",
                        start.elapsed()
                    );
                    false
                }
            };
        // We can close the channel now.
        init_receiver.close();

        let fetch_actor = NodesFetchActor::new(
            Arc::clone(&self.fetcher),
            self.fetch_period,
            self.fetch_retry_interval,
            fetch_sender,
            Arc::clone(&self.routing_snapshot),
            self.token.clone(),
        );
        self.tracker.spawn(async move { fetch_actor.run().await });
        info!(
            "{DYNAMIC_ROUTE_PROVIDER}: NodesFetchActor and HealthManagerActor started successfully"
        );

        (found_healthy_seeds).then_some(()).ok_or(anyhow!(
            "No healthy seeds found within {TIMEOUT_AWAIT_HEALTHY_SEED:?}, they may become healthy later ..."
        ))
    }
}

// Gracefully stop the inner spawned tasks running in the background.
impl<S> Drop for DynamicRouteProvider<S> {
    fn drop(&mut self) {
        self.token.cancel();
        self.tracker.close();
        let tracker = self.tracker.clone();
        // If no runtime is available do nothing.
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                tracker.wait().await;
                warn!("{DYNAMIC_ROUTE_PROVIDER}: stopped gracefully");
            });
        } else {
            error!("{DYNAMIC_ROUTE_PROVIDER}: no runtime available, cannot stop the spawned tasks");
        }
    }
}

#[cfg(test)]
mod tests {
    use candid::Principal;
    use reqwest::Client;
    use std::{
        sync::{Arc, Once},
        time::{Duration, Instant},
    };
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    use crate::{
        agent::http_transport::{
            dynamic_routing::{
                dynamic_route_provider::{
                    DynamicRouteProviderBuilder, IC0_SEED_DOMAIN, MAINNET_ROOT_SUBNET_ID,
                },
                node::Node,
                snapshot::{
                    latency_based_routing::LatencyRoutingSnapshot,
                    round_robin_routing::RoundRobinRoutingSnapshot,
                },
                test_utils::{
                    assert_routed_domains, route_n_times, NodeHealthCheckerMock, NodesFetcherMock,
                },
            },
            route_provider::RouteProvider,
            ReqwestTransport,
        },
        Agent, AgentError,
    };

    static TRACING_INIT: Once = Once::new();

    pub fn setup_tracing() {
        TRACING_INIT.call_once(|| {
            FmtSubscriber::builder().with_max_level(Level::TRACE).init();
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
        let client = Client::builder().build().unwrap();
        let route_provider = DynamicRouteProviderBuilder::new(
            LatencyRoutingSnapshot::new(),
            vec![seed],
            client.clone(),
        )
        .build()
        .await;
        let route_provider = Arc::new(route_provider) as Arc<dyn RouteProvider>;
        let transport =
            ReqwestTransport::create_with_client_route(Arc::clone(&route_provider), client)
                .expect("failed to create transport");
        let agent = Agent::builder()
            .with_transport(transport)
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
        let snapshot = RoundRobinRoutingSnapshot::new();
        let client = Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
                .with_fetcher(fetcher.clone())
                .with_checker(checker.clone())
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build()
                .await;
        let route_provider = Arc::new(route_provider);

        // This time span is required for the snapshot to be fully updated with the new nodes and their health info.
        let snapshot_update_duration = fetch_interval + 2 * check_interval;

        // Test 1: multiple route() calls return a single domain=ic0.app.
        // Only a single node exists, which is initially healthy.
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain()], 6);

        // Test 2: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Two healthy nodes are added to the topology.
        let node_2 = Node::new("api1.com").unwrap();
        let node_3 = Node::new("api2.com").unwrap();
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![node_1.domain(), node_2.domain(), node_3.domain()],
            2,
        );

        // Test 3:  multiple route() calls return 2 different domains with equal fairness (repetition).
        // One node is set to unhealthy.
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain(), node_3.domain()], 3);

        // Test 4: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Unhealthy node is set back to healthy.
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![node_1.domain(), node_2.domain(), node_3.domain()],
            2,
        );

        // Test 5: multiple route() calls return 3 different domains with equal fairness (repetition).
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
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![node_2.domain(), node_3.domain(), node_4.domain()],
            2,
        );

        // Test 6: multiple route() calls return a single domain=api1.com.
        // One node is set to unhealthy and one is removed from the topology.
        checker.overwrite_healthy_nodes(vec![node_2.clone(), node_3.clone()]);
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone(), node_4.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_2.domain()], 3);
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
        let snapshot = RoundRobinRoutingSnapshot::new();
        let client = Client::builder().build().unwrap();
        let route_provider = DynamicRouteProviderBuilder::new(
            snapshot,
            vec![node_1.clone(), node_2.clone()],
            client,
        )
        .with_fetcher(fetcher)
        .with_checker(checker.clone())
        .with_fetch_period(fetch_interval)
        .with_check_period(check_interval)
        .build()
        .await;
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
        assert_routed_domains(routed_domains, vec![node_1.domain(), node_2.domain()], 3);
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
        let snapshot = RoundRobinRoutingSnapshot::new();
        let client = Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
                .with_fetcher(fetcher)
                .with_checker(checker.clone())
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build()
                .await;
        let route_provider = Arc::new(route_provider);

        // Test 1: multiple route() calls return a single domain=ic0.app, as the seed is healthy.
        tokio::time::sleep(2 * check_interval).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain()], 3);

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
        let snapshot = RoundRobinRoutingSnapshot::new();
        let client = Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
                .with_fetcher(fetcher)
                .with_checker(checker)
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build()
                .await;

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
        let snapshot = RoundRobinRoutingSnapshot::new();
        let client = Client::builder().build().unwrap();
        let route_provider = DynamicRouteProviderBuilder::new(
            snapshot,
            vec![node_1.clone(), node_2.clone()],
            client,
        )
        .with_fetcher(fetcher)
        .with_checker(checker.clone())
        .with_fetch_period(fetch_interval)
        .with_check_period(check_interval)
        .build()
        .await;
        let route_provider = Arc::new(route_provider);

        // Test 1: calls to route() return only a healthy seed ic0.app.
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain()], 3);

        // Test 2: calls to route() return two healthy seeds, as the unhealthy seed becomes healthy.
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone()]);
        tokio::time::sleep(2 * check_interval).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain(), node_2.domain()], 3);
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
        let snapshot = RoundRobinRoutingSnapshot::new();
        let client = Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
                .with_fetcher(fetcher.clone())
                .with_checker(checker.clone())
                .with_fetch_period(fetch_interval)
                .with_check_period(check_interval)
                .build()
                .await;
        let route_provider = Arc::new(route_provider);

        // This time span is required for the snapshot to be fully updated with the new nodes topology and health info.
        let snapshot_update_duration = fetch_interval + 2 * check_interval;

        // Test 1: multiple route() calls return a single domain=ic0.app.
        // HealthManagerActor shouldn't update the snapshot, if the list of fetched nodes is empty, thus we observe the healthy seed.
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_1.domain()], 3);

        // Test 2: multiple route() calls should now return 3 different domains with equal fairness (repetition).
        // Three nodes are added to the topology, i.e. now the fetched nodes list is non-empty.
        let node_2 = Node::new("api1.com").unwrap();
        let node_3 = Node::new("api2.com").unwrap();
        fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![node_1.domain(), node_2.domain(), node_3.domain()],
            2,
        );
    }
}
