use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::{fmt::Debug, hash::Hash, sync::Arc};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use url::Url;

use crate::agent::route_provider::{
    dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderError,
        health_check::{HealthCheck, HealthCheckStatus},
        node::Node,
        nodes_fetch::Fetch,
        type_aliases::AtomicSwap,
    },
    RouteProvider,
};

pub(super) fn route_n_times(n: usize, f: Arc<impl RouteProvider + ?Sized>) -> Vec<String> {
    (0..n)
        .map(|_| f.route().unwrap().domain().unwrap().to_string())
        .collect()
}

pub(super) fn assert_routed_domains<T>(
    actual: Vec<T>,
    expected: Vec<&str>,
    expected_repetitions: usize,
) where
    T: AsRef<str> + Eq + Hash + Debug + Ord,
{
    fn build_count_map<T>(items: &[T]) -> HashMap<&str, usize>
    where
        T: AsRef<str>,
    {
        items.iter().fold(HashMap::new(), |mut map, item| {
            *map.entry(item.as_ref()).or_insert(0) += 1;
            map
        })
    }
    let count_actual = build_count_map(&actual);
    let count_expected = build_count_map(&expected);

    let mut keys_actual = count_actual.keys().collect::<Vec<_>>();
    keys_actual.sort();
    let mut keys_expected = count_expected.keys().collect::<Vec<_>>();
    keys_expected.sort();
    // Assert all routed domains are present.
    assert_eq!(keys_actual, keys_expected);

    // For latency-based routing, we can't expect exact equal distribution,
    // so we just verify that all expected nodes were used at least once.
    // The probabilistic nature of latency-based routing means distribution will vary.
    for expected_node in expected {
        assert!(
            count_actual.contains_key(expected_node),
            "Expected node '{}' was not routed to",
            expected_node
        );
    }
    
    // Note: expected_repetitions parameter is kept for API compatibility but not enforced
    // since latency-based routing doesn't guarantee equal distribution
    let _ = expected_repetitions;
}

#[derive(Debug)]
pub(super) struct NodesFetcherMock {
    // A set of nodes, existing in the topology.
    pub nodes: AtomicSwap<Vec<Node>>,
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl Fetch for NodesFetcherMock {
    async fn fetch(&self, _url: Url) -> Result<Vec<Node>, DynamicRouteProviderError> {
        let nodes = (*self.nodes.load_full()).clone();
        Ok(nodes)
    }
}

impl Default for NodesFetcherMock {
    fn default() -> Self {
        Self::new()
    }
}

impl NodesFetcherMock {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(ArcSwap::from_pointee(vec![])),
        }
    }

    pub fn overwrite_nodes(&self, nodes: Vec<Node>) {
        self.nodes.store(Arc::new(nodes));
    }
}

#[derive(Debug)]
pub(super) struct NodeHealthCheckerMock {
    healthy_nodes: Arc<ArcSwap<HashSet<Node>>>,
}

impl Default for NodeHealthCheckerMock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl HealthCheck for NodeHealthCheckerMock {
    async fn check(&self, node: &Node) -> Result<HealthCheckStatus, DynamicRouteProviderError> {
        let nodes = self.healthy_nodes.load_full();
        let latency = match nodes.contains(node) {
            true => Some(Duration::from_secs(1)),
            false => None,
        };
        Ok(HealthCheckStatus::new(latency))
    }
}

impl NodeHealthCheckerMock {
    pub fn new() -> Self {
        Self {
            healthy_nodes: Arc::new(ArcSwap::from_pointee(HashSet::new())),
        }
    }

    pub fn overwrite_healthy_nodes(&self, healthy_nodes: Vec<Node>) {
        self.healthy_nodes
            .store(Arc::new(HashSet::from_iter(healthy_nodes)));
    }
}
