//! An implementation of the [`RouteProvider`](crate::agent::http_transport::route_provider::RouteProvider) for dynamic generation of routing urls.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use candid::Principal;
use futures_util::{select, FutureExt};
use reqwest::Client;
use stop_token::StopSource;
use thiserror::Error;
use tracing::{error, info, warn};
use url::Url;

use crate::{
    agent::{
        route_provider::{
            dynamic_routing::{
                health_check::health_check_manager_actor, messages::FetchedNodes,
                nodes_fetch::nodes_fetch_actor, snapshot::routing_snapshot::RoutingSnapshot,
                type_aliases::AtomicSwap,
            },
            RouteProvider,
        },
        ApiBoundaryNode,
    },
    Agent, AgentError,
};

pub(crate) const IC0_SEED_DOMAIN: &str = "ic0.app";

pub(crate) const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

const FETCH_PERIOD: Duration = Duration::from_secs(5);
const FETCH_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const TIMEOUT_AWAIT_HEALTHY_SEED: Duration = Duration::from_millis(1000);
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(1);
const HEALTH_CHECK_PERIOD: Duration = Duration::from_secs(1);

const DYNAMIC_ROUTE_PROVIDER: &str = "DynamicRouteProvider";

/// A dynamic route provider.
/// It spawns the discovery service (`NodesFetchActor`) for fetching the latest nodes topology.
/// It also spawns the `HealthManagerActor`, which orchestrates the health check tasks for each node and updates routing snapshot.
#[derive(Debug)]
pub struct DynamicRouteProvider<S> {
    /// Periodicity of fetching the latest nodes topology.
    fetch_period: Duration,
    /// Interval for retrying fetching the nodes in case of error.
    fetch_retry_interval: Duration,
    /// Periodicity of checking the health of the nodes.
    check_period: Duration,
    /// Timeout for checking the health of the nodes.
    check_timeout: Duration,
    /// Snapshot of the routing nodes.
    routing_snapshot: AtomicSwap<S>,
    /// Initial seed nodes, which are used for the initial fetching of the nodes.
    seeds: Vec<ApiBoundaryNode>,
    /// Cancellation source for stopping the spawned tasks.
    stop: StopSource,
}

/// An error that occurred when the DynamicRouteProvider service was running.
#[derive(Error, Debug)]
pub enum DynamicRouteProviderError {
    /// An error when fetching topology of the API nodes.
    #[error("An error when fetching API nodes: {0}")]
    NodesFetchError(String),
    /// An error when checking API node's health.
    #[error("An error when checking API node's health: {0}")]
    HealthCheckError(String),
    /// An invalid domain name provided.
    #[error("Provided domain name is invalid: {0}")]
    InvalidDomainName(String),
}

/// A builder for the `DynamicRouteProvider`.
pub struct DynamicRouteProviderBuilder<S> {
    fetch_period: Duration,
    fetch_retry_interval: Duration,
    check_period: Duration,
    check_timeout: Duration,
    routing_snapshot: AtomicSwap<S>,
    seeds: Vec<ApiBoundaryNode>,
}

impl<S> DynamicRouteProviderBuilder<S> {
    /// Creates a new instance of the builder.
    pub fn new(snapshot: S, seeds: Vec<ApiBoundaryNode>, http_client: Client) -> Self {
        Self {
            fetch_period: FETCH_PERIOD,
            fetch_retry_interval: FETCH_RETRY_INTERVAL,
            check_period: HEALTH_CHECK_PERIOD,
            check_timeout: HEALTH_CHECK_TIMEOUT,
            seeds,
            routing_snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
        }
    }

    /// Sets the fetching periodicity.
    pub fn with_fetch_period(mut self, period: Duration) -> Self {
        self.fetch_period = period;
        self
    }

    /// Sets the timeout for node health checking.
    pub fn with_check_timeout(mut self, timeout: Duration) -> Self {
        self.check_timeout = timeout;
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
        DynamicRouteProvider {
            fetch_period: self.fetch_period,
            fetch_retry_interval: self.fetch_retry_interval,
            check_period: self.check_period,
            check_timeout: self.check_timeout,
            routing_snapshot: self.routing_snapshot,
            seeds: self.seeds,
            stop: StopSource::new(),
        }
    }
}

impl<S> RouteProvider for DynamicRouteProvider<S>
where
    S: RoutingSnapshot + 'static,
{
    fn route(&self) -> Result<Url, AgentError> {
        let snapshot = self.routing_snapshot.load();
        let node = snapshot.next_node().ok_or_else(|| {
            AgentError::RouteProviderError("No healthy API nodes found.".to_string())
        })?;
        Ok(node.to_routing_url())
    }

    fn n_ordered_routes(&self, n: usize) -> Result<Vec<Url>, AgentError> {
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

    /// Starts two background tasks:
    /// - Task1: NodesFetchActor
    ///   - Periodically fetches existing API nodes (gets latest nodes topology) and sends discovered nodes to HealthManagerActor.
    /// - Task2: HealthManagerActor:
    ///   - Listens to the fetched nodes messages from the NodesFetchActor.
    ///   - Starts/stops health check tasks (HealthCheckActors) based on the newly added/removed nodes.
    ///   - These spawned health check tasks periodically update the snapshot with the latest node health info.
    fn notify_start(&self, agent: Agent) {
        info!("{DYNAMIC_ROUTE_PROVIDER}: started ...");
        // Communication channel between NodesFetchActor and HealthManagerActor.
        let (fetch_sender, fetch_receiver) = async_watch::channel(None);

        // Communication channel with HealthManagerActor to receive info about healthy seed nodes (used only once).
        let (init_sender, init_receiver) = async_channel::bounded(1);

        // Start the receiving part first.
        crate::util::spawn(health_check_manager_actor(
            agent.client.clone(),
            self.check_period,
            self.check_timeout,
            Arc::clone(&self.routing_snapshot),
            fetch_receiver,
            init_sender,
            self.stop.token(),
        ));
        let seeds = self.seeds.clone();
        let routing_snapshot = self.routing_snapshot.clone();
        let fetch_period = self.fetch_period;
        let fetch_retry_interval = self.fetch_retry_interval;
        let stop_token = self.stop.token();

        crate::util::spawn(async move {
            // Dispatch all seed nodes for initial health checks
            if let Err(err) = fetch_sender.send(Some(FetchedNodes { nodes: seeds })) {
                error!(
                    "{DYNAMIC_ROUTE_PROVIDER}: failed to send results to HealthManager: {err:?}"
                );
            }

            // Try await for healthy seeds.
            let start = Instant::now();
            select! {
                _ = crate::util::sleep(TIMEOUT_AWAIT_HEALTHY_SEED).fuse() => warn!(
                    "{DYNAMIC_ROUTE_PROVIDER}: no healthy seeds found within {:?}",
                    start.elapsed()
                ),
                _ = init_receiver.recv().fuse() => info!(
                    "{DYNAMIC_ROUTE_PROVIDER}: found healthy seeds within {:?}",
                    start.elapsed()
                )
            }
            // We can close the channel now.
            init_receiver.close();
            nodes_fetch_actor(
                agent,
                Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap(),
                fetch_period,
                fetch_retry_interval,
                fetch_sender,
                routing_snapshot,
                stop_token,
            )
            .await;
        });
        info!(
            "{DYNAMIC_ROUTE_PROVIDER}: NodesFetchActor and HealthManagerActor started successfully"
        );
    }
}

#[cfg(test)]
mod tests {
    use candid::Principal;
    use reqwest::Client;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, Once, OnceLock},
        time::{Duration, Instant},
    };
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    use crate::{
        agent::{
            route_provider::{
                dynamic_routing::{
                    dynamic_route_provider::{
                        DynamicRouteProviderBuilder, IC0_SEED_DOMAIN, MAINNET_ROOT_SUBNET_ID,
                    },
                    snapshot::{
                        latency_based_routing::LatencyRoutingSnapshot,
                        round_robin_routing::RoundRobinRoutingSnapshot,
                    },
                    test_utils::{assert_routed_domains, mock_node, mock_topology, route_n_times},
                },
                RouteProvider,
            },
            Agent, AgentError, ApiBoundaryNode,
        },
        identity::Secp256k1Identity,
        Identity,
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
        //TODO need a way of testing mainnet
        // Setup.
        setup_tracing();
        let client = Client::builder().build().unwrap();
        let route_provider = DynamicRouteProviderBuilder::new(
            LatencyRoutingSnapshot::new(),
            vec![ApiBoundaryNode {
                domain: IC0_SEED_DOMAIN.to_string(),
                ipv4_address: None,
                ipv6_address: None,
            }],
            client.clone(),
        )
        .build()
        .await;
        let route_provider = Arc::new(route_provider) as Arc<dyn RouteProvider>;
        let agent = Agent::builder()
            .with_arc_route_provider(route_provider.clone())
            .build()
            .expect("failed to create an agent");
        let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();
        // Assert that seed (ic0.app) is not used for routing. Henceforth, only discovered API nodes are used.
        assert_no_routing_via_domains(
            route_provider.clone(),
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
        let node_1 = mock_node("n1.routing_with_topology");
        // Set nodes fetching params: topology, fetching periodicity.
        // A single healthy node exists in the topology. This node happens to be the seed node.
        let mut mocks = mock_topology(vec![(node_1.clone(), true)], "routing_with_topology_1");
        let fetch_interval = Duration::from_secs(2);
        // Set health checking params: healthy nodes, checking periodicity.
        let check_interval = Duration::from_secs(1);
        // Configure RouteProvider
        let snapshot = RoundRobinRoutingSnapshot::new();
        let client = Client::builder().build().unwrap();
        let route_provider =
            DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
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
        assert_routed_domains(routed_domains, vec![node_1.domain.clone()], 6);

        // Test 2: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Two healthy nodes are added to the topology.
        let node_2 = mock_node("api1");
        let node_3 = mock_node("api2");
        mocks.add_nodes([(node_2.clone(), true), (node_3.clone(), true)]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![
                node_1.domain.clone(),
                node_2.domain.clone(),
                node_3.domain.clone(),
            ],
            2,
        );

        // Test 3:  multiple route() calls return 2 different domains with equal fairness (repetition).
        // One node is set to unhealthy.
        mocks.set_node_health(&node_2, false);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![node_1.domain.clone(), node_3.domain.clone()],
            3,
        );

        // Test 4: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Unhealthy node is set back to healthy.
        mocks.set_node_health(&node_2, true);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![
                node_1.domain.clone(),
                node_2.domain.clone(),
                node_3.domain.clone(),
            ],
            2,
        );

        // Test 5: multiple route() calls return 3 different domains with equal fairness (repetition).
        // One healthy node is added, but another one goes unhealthy.
        let node_4 = mock_node("api3");
        mocks.add_nodes([(node_4.clone(), true)]);
        mocks.set_node_health(&node_1, false);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec![
                node_2.domain.clone(),
                node_3.domain.clone(),
                node_4.domain.clone(),
            ],
            2,
        );

        // Test 6: multiple route() calls return a single domain=api1.com.
        // One node is set to unhealthy and one is removed from the topology.
        mocks.set_node_health(&node_4, false);
        mocks.remove_nodes([&node_3]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec![node_2.domain.clone()], 3);
    }

    // #[tokio::test]
    // async fn test_route_with_initially_unhealthy_seeds_becoming_healthy() {
    //     // Setup.
    //     setup_tracing();
    //     let node_1 = mock_node(IC0_SEED_DOMAIN);
    //     let node_2 = mock_node("api1");
    //     // Set nodes fetching params: topology, fetching periodicity.
    //     let fetcher = Arc::new(NodesFetcherMock::new());
    //     let fetch_interval = Duration::from_secs(2);
    //     // Set health checking params: healthy nodes, checking periodicity.
    //     let checker = Arc::new(NodeHealthCheckerMock::new());
    //     let check_interval = Duration::from_secs(1);
    //     // Two nodes exist, which are initially unhealthy.
    //     fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone()]);
    //     checker.overwrite_healthy_nodes(vec![]);
    //     // Configure RouteProvider
    //     let snapshot = RoundRobinRoutingSnapshot::new();
    //     let client = Client::builder().build().unwrap();
    //     let route_provider = DynamicRouteProviderBuilder::new(
    //         snapshot,
    //         vec![node_1.clone(), node_2.clone()],
    //         client,
    //     )
    //     .with_fetcher(fetcher)
    //     .with_checker(checker.clone())
    //     .with_fetch_period(fetch_interval)
    //     .with_check_period(check_interval)
    //     .build()
    //     .await;
    //     let route_provider = Arc::new(route_provider);

    //     // Test 1: calls to route() return an error, as no healthy seeds exist.
    //     for _ in 0..4 {
    //         tokio::time::sleep(check_interval).await;
    //         let result = route_provider.route();
    //         assert_eq!(
    //             result.unwrap_err(),
    //             AgentError::RouteProviderError("No healthy API nodes found.".to_string())
    //         );
    //     }

    //     // Test 2: calls to route() return both seeds, as they become healthy.
    //     checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone()]);
    //     tokio::time::sleep(3 * check_interval).await;
    //     let routed_domains = route_n_times(6, Arc::clone(&route_provider));
    //     assert_routed_domains(routed_domains, vec![node_1.domain(), node_2.domain()], 3);
    // }

    // #[tokio::test]
    // async fn test_routing_with_no_healthy_nodes_returns_an_error() {
    //     // Setup.
    //     setup_tracing();
    //     let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
    //     // Set nodes fetching params: topology, fetching periodicity.
    //     let fetcher = Arc::new(NodesFetcherMock::new());
    //     let fetch_interval = Duration::from_secs(2);
    //     // Set health checking params: healthy nodes, checking periodicity.
    //     let checker = Arc::new(NodeHealthCheckerMock::new());
    //     let check_interval = Duration::from_secs(1);
    //     // A single seed node which is initially healthy.
    //     fetcher.overwrite_nodes(vec![node_1.clone()]);
    //     checker.overwrite_healthy_nodes(vec![node_1.clone()]);
    //     // Configure RouteProvider
    //     let snapshot = RoundRobinRoutingSnapshot::new();
    //     let client = Client::builder().build().unwrap();
    //     let route_provider =
    //         DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
    //             .with_fetcher(fetcher)
    //             .with_checker(checker.clone())
    //             .with_fetch_period(fetch_interval)
    //             .with_check_period(check_interval)
    //             .build()
    //             .await;
    //     let route_provider = Arc::new(route_provider);

    //     // Test 1: multiple route() calls return a single domain=ic0.app, as the seed is healthy.
    //     tokio::time::sleep(2 * check_interval).await;
    //     let routed_domains = route_n_times(3, Arc::clone(&route_provider));
    //     assert_routed_domains(routed_domains, vec![node_1.domain()], 3);

    //     // Test 2: calls to route() return an error, as no healthy nodes exist.
    //     checker.overwrite_healthy_nodes(vec![]);
    //     tokio::time::sleep(2 * check_interval).await;
    //     for _ in 0..4 {
    //         let result = route_provider.route();
    //         assert_eq!(
    //             result.unwrap_err(),
    //             AgentError::RouteProviderError("No healthy API nodes found.".to_string())
    //         );
    //     }
    // }

    // #[tokio::test]
    // async fn test_route_with_no_healthy_seeds_errors() {
    //     // Setup.
    //     setup_tracing();
    //     let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
    //     // Set nodes fetching params: topology, fetching periodicity.
    //     let fetcher = Arc::new(NodesFetcherMock::new());
    //     let fetch_interval = Duration::from_secs(2);
    //     // Set health checking params: healthy nodes, checking periodicity.
    //     let checker = Arc::new(NodeHealthCheckerMock::new());
    //     let check_interval = Duration::from_secs(1);
    //     // No healthy seed nodes present, this should lead to errors.
    //     fetcher.overwrite_nodes(vec![]);
    //     checker.overwrite_healthy_nodes(vec![]);
    //     // Configure RouteProvider
    //     let snapshot = RoundRobinRoutingSnapshot::new();
    //     let client = Client::builder().build().unwrap();
    //     let route_provider =
    //         DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
    //             .with_fetcher(fetcher)
    //             .with_checker(checker)
    //             .with_fetch_period(fetch_interval)
    //             .with_check_period(check_interval)
    //             .build()
    //             .await;

    //     // Test: calls to route() return an error, as no healthy seeds exist.
    //     for _ in 0..4 {
    //         tokio::time::sleep(check_interval).await;
    //         let result = route_provider.route();
    //         assert_eq!(
    //             result.unwrap_err(),
    //             AgentError::RouteProviderError("No healthy API nodes found.".to_string())
    //         );
    //     }
    // }

    // #[tokio::test]
    // async fn test_route_with_one_healthy_and_one_unhealthy_seed() {
    //     // Setup.
    //     setup_tracing();
    //     let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
    //     let node_2 = Node::new("api1.com").unwrap();
    //     // Set nodes fetching params: topology, fetching periodicity.
    //     let fetcher = Arc::new(NodesFetcherMock::new());
    //     let fetch_interval = Duration::from_secs(2);
    //     // Set health checking params: healthy nodes, checking periodicity.
    //     let checker = Arc::new(NodeHealthCheckerMock::new());
    //     let check_interval = Duration::from_secs(1);
    //     // One healthy seed is present, it should be discovered during the initialization time.
    //     fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone()]);
    //     checker.overwrite_healthy_nodes(vec![node_1.clone()]);
    //     // Configure RouteProvider
    //     let snapshot = RoundRobinRoutingSnapshot::new();
    //     let client = Client::builder().build().unwrap();
    //     let route_provider = DynamicRouteProviderBuilder::new(
    //         snapshot,
    //         vec![node_1.clone(), node_2.clone()],
    //         client,
    //     )
    //     .with_fetcher(fetcher)
    //     .with_checker(checker.clone())
    //     .with_fetch_period(fetch_interval)
    //     .with_check_period(check_interval)
    //     .build()
    //     .await;
    //     let route_provider = Arc::new(route_provider);

    //     // Test 1: calls to route() return only a healthy seed ic0.app.
    //     let routed_domains = route_n_times(3, Arc::clone(&route_provider));
    //     assert_routed_domains(routed_domains, vec![node_1.domain()], 3);

    //     // Test 2: calls to route() return two healthy seeds, as the unhealthy seed becomes healthy.
    //     checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone()]);
    //     tokio::time::sleep(2 * check_interval).await;
    //     let routed_domains = route_n_times(6, Arc::clone(&route_provider));
    //     assert_routed_domains(routed_domains, vec![node_1.domain(), node_2.domain()], 3);
    // }

    // #[tokio::test]
    // async fn test_routing_with_an_empty_fetched_list_of_api_nodes() {
    //     // Check resiliency to an empty list of fetched API nodes (this should never happen in normal IC operation).
    //     // Setup.
    //     setup_tracing();
    //     let node_1 = Node::new(IC0_SEED_DOMAIN).unwrap();
    //     // Set nodes fetching params: topology, fetching periodicity.
    //     let fetcher = Arc::new(NodesFetcherMock::new());
    //     let fetch_interval = Duration::from_secs(2);
    //     // Set health checking params: healthy nodes, checking periodicity.
    //     let checker = Arc::new(NodeHealthCheckerMock::new());
    //     let check_interval = Duration::from_secs(1);
    //     // One healthy seed is initially present, but the topology has no node.
    //     fetcher.overwrite_nodes(vec![]);
    //     checker.overwrite_healthy_nodes(vec![node_1.clone()]);
    //     // Configure RouteProvider
    //     let snapshot = RoundRobinRoutingSnapshot::new();
    //     let client = Client::builder().build().unwrap();
    //     let route_provider =
    //         DynamicRouteProviderBuilder::new(snapshot, vec![node_1.clone()], client)
    //             .with_fetcher(fetcher.clone())
    //             .with_checker(checker.clone())
    //             .with_fetch_period(fetch_interval)
    //             .with_check_period(check_interval)
    //             .build()
    //             .await;
    //     let route_provider = Arc::new(route_provider);

    //     // This time span is required for the snapshot to be fully updated with the new nodes topology and health info.
    //     let snapshot_update_duration = fetch_interval + 2 * check_interval;

    //     // Test 1: multiple route() calls return a single domain=ic0.app.
    //     // HealthManagerActor shouldn't update the snapshot, if the list of fetched nodes is empty, thus we observe the healthy seed.
    //     tokio::time::sleep(snapshot_update_duration).await;
    //     let routed_domains = route_n_times(3, Arc::clone(&route_provider));
    //     assert_routed_domains(routed_domains, vec![node_1.domain()], 3);

    //     // Test 2: multiple route() calls should now return 3 different domains with equal fairness (repetition).
    //     // Three nodes are added to the topology, i.e. now the fetched nodes list is non-empty.
    //     let node_2 = Node::new("api1.com").unwrap();
    //     let node_3 = Node::new("api2.com").unwrap();
    //     fetcher.overwrite_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
    //     checker.overwrite_healthy_nodes(vec![node_1.clone(), node_2.clone(), node_3.clone()]);
    //     tokio::time::sleep(snapshot_update_duration).await;
    //     let routed_domains = route_n_times(6, Arc::clone(&route_provider));
    //     assert_routed_domains(
    //         routed_domains,
    //         vec![node_1.domain(), node_2.domain(), node_3.domain()],
    //         2,
    //     );
    // }
}

// - none of the seeds [] are healthy
// - none of the API node [] is healthy
// - return a vector of errors: HealthCheckErrors, FetchErrors, etc.
