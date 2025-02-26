use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use rand::Rng;

use crate::agent::route_provider::{
    dynamic_routing::{
        health_check::HealthCheckStatus, node::Node, snapshot::routing_snapshot::RoutingSnapshot,
    },
    RoutesStats,
};

// Determines the size of the sliding window used for storing latencies and availabilities of nodes.
const WINDOW_SIZE: usize = 15;
// Determines the decay rate of the exponential decay function, which is used for generating weights over the sliding window.
const LAMBDA_DECAY: f64 = 0.3;

/// Generates exponentially decaying weights for the sliding window.
/// Weights are higher for more recent observations and decay exponentially for older ones.
fn generate_exp_decaying_weights(n: usize, lambda: f64) -> Vec<f64> {
    let mut weights: Vec<f64> = Vec::with_capacity(n);
    for i in 0..n {
        let weight = (-lambda * i as f64).exp();
        weights.push(weight);
    }
    weights
}

/// A node candidate eligible for final routing selection based on its score.
///
/// # Overview
/// This struct represents a node that has passed initial pre-selection criteria and is part of the
/// routing candidate pool. The selection process happens in two phases:
/// 1. Pre-selection: depending on the settings, either the k-top nodes or all healthy nodes are chosen
/// 2. Final selection: a node is probabilistically selected from the candidate pool based on its score
#[derive(Clone, Debug)]
struct RoutingCandidateNode {
    node: Node,
    score: f64,
}

impl RoutingCandidateNode {
    fn new(node: Node, score: f64) -> Self {
        Self { node, score }
    }
}

// Stores node's meta information and metrics (latencies, availabilities).
// Routing nodes are probabilistically selected based on the score field.
#[derive(Clone, Debug)]
struct NodeMetrics {
    // Size of the sliding window used to store latencies and availabilities of the node.
    window_size: usize,
    /// Reflects the status of the most recent health check. It should be the same as the last element in `availabilities`.
    is_healthy: bool,
    /// Sliding window with latency measurements.
    latencies: VecDeque<f64>,
    /// Sliding window with availability measurements.
    availabilities: VecDeque<bool>,
    /// Overall score of the node. Calculated based on latencies and availabilities arrays. This score is used in `next_n_nodes()` method for the final nodes selection.
    score: f64,
}

impl NodeMetrics {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            is_healthy: false,
            latencies: VecDeque::with_capacity(window_size + 1),
            availabilities: VecDeque::with_capacity(window_size + 1),
            score: 0.0,
        }
    }

    pub fn add_latency_measurement(&mut self, latency: Option<Duration>) {
        self.is_healthy = latency.is_some();
        if let Some(duration) = latency {
            self.latencies.push_back(duration.as_secs_f64());
            while self.latencies.len() > self.window_size {
                self.latencies.pop_front();
            }
            self.availabilities.push_back(true);
        } else {
            self.availabilities.push_back(false);
        }
        while self.availabilities.len() > self.window_size {
            self.availabilities.pop_front();
        }
    }
}

/// Computes the score of the node based on the latencies, availabilities and window weights.
/// `window_weights_sum` is passed for efficiency reasons, as it is pre-calculated.
fn compute_score(
    window_weights: &[f64],
    window_weights_sum: f64,
    availabilities: &VecDeque<bool>,
    latencies: &VecDeque<f64>,
    use_availability_penalty: bool,
) -> f64 {
    let weights_size = window_weights.len();
    let availabilities_size = availabilities.len();
    let latencies_size = latencies.len();

    if weights_size < availabilities_size {
        panic!(
            "Configuration error: Weights array of size {weights_size} is smaller than array of availabilities of size {availabilities_size}.",
        );
    } else if weights_size < latencies_size {
        panic!(
            "Configuration error: Weights array of size {weights_size} is smaller than array of latencies of size {latencies_size}.",
        );
    }

    // Compute normalized availability score [0.0, 1.0].
    let score_a = if !use_availability_penalty {
        1.0
    } else if availabilities.is_empty() {
        0.0
    } else {
        let mut score = 0.0;

        // Compute weighted score. Weights are applied in reverse order.
        for (idx, availability) in availabilities.iter().rev().enumerate() {
            score += window_weights[idx] * (*availability as u8 as f64);
        }

        // Normalize the score.
        let weights_sum = if availabilities_size < weights_size {
            // Use partial sum of weights, if the window is not full.
            let partial_weights_sum: f64 = window_weights.iter().take(availabilities_size).sum();
            partial_weights_sum
        } else {
            // Use pre-calculated sum, if the window is full.
            window_weights_sum
        };

        score /= weights_sum;

        score
    };

    // Compute latency score (not normalized).
    let score_l = if latencies.is_empty() {
        0.0
    } else {
        let mut score = 0.0;

        // Compute weighted score. Weights are applied in reverse order. Latency is inverted, so that smaller latencies have higher score.
        for (idx, latency) in latencies.iter().rev().enumerate() {
            score += window_weights[idx] / latency;
        }

        let weights_sum = if latencies_size < weights_size {
            let partial_weights_sum: f64 = window_weights.iter().take(latencies.len()).sum();
            partial_weights_sum
        } else {
            // Use pre-calculated sum.
            window_weights_sum
        };

        score /= weights_sum;

        score
    };

    // Combine availability and latency scores via product to emphasize the importance of both metrics.
    score_l * score_a
}

/// # Latency-based dynamic routing
///
/// This module implements a routing strategy that uses weighted random selection of nodes based on their historical data (latencies and availabilities).
///
/// Summary of the routing strategy:
/// - Uses sliding windows for storing latencies and availabilities of each node
/// - Latency and availability scores are first computed separately from the sliding windows using an additional array of weights, allowing prioritization of more recent observations. By default, exponentially decaying weights are used.
/// - The final overall score of each node is computed as a product of latency and availability scores, namely score = score_l * score_a
/// - Nodes pre-selection phase for routing candidate pool (snapshot):
///   - Criteria: if k-top-nodes setting is enabled, then only k nodes with highest scores are filtered into the routing candidate pool (snapshot), otherwise all healthy nodes are used
///   - Trigger conditions: topology updates, node health check status updates
/// - Final selection of nodes for routing from the candidate pool is probabilistic and is proportional to the score of the node
///
/// ## Configuration Options
/// - `k_top_nodes`: Limit routing to only top k nodes with highest score
/// - `use_availability_penalty`: Whether to penalize nodes for being unavailable
/// - Custom window weights can be provided for specialized decay functions
#[derive(Default, Debug, Clone)]
pub struct LatencyRoutingSnapshot {
    // If set, only k nodes with best scores are used for routing
    k_top_nodes: Option<usize>,
    // Stores all existing nodes in the topology along with their historical data (latencies and availabilities)
    existing_nodes: HashMap<Node, NodeMetrics>,
    // Snapshot of nodes, which are pre-selected as candidates for routing. Snapshot is published via publish_routing_nodes() when either: topology changes or a health check of some node is received.
    routing_candidates: Arc<ArcSwap<Vec<RoutingCandidateNode>>>,
    // Weights used to compute the availability score of a node.
    window_weights: Vec<f64>,
    // Pre-computed weights sum, passed for efficiency purpose as this sum doesn't change.
    window_weights_sum: f64,
    // Whether or not penalize nodes score for being unavailable
    use_availability_penalty: bool,
}

/// Implementation of the LatencyRoutingSnapshot.
impl LatencyRoutingSnapshot {
    /// Creates a new LatencyRoutingSnapshot with default configuration.
    pub fn new() -> Self {
        // Weights are ordered from left to right, where the leftmost weight is for the most recent health check.
        let window_weights = generate_exp_decaying_weights(WINDOW_SIZE, LAMBDA_DECAY);
        // Pre-calculate the sum of weights for efficiency reasons.
        let window_weights_sum: f64 = window_weights.iter().sum();

        Self {
            k_top_nodes: None,
            existing_nodes: HashMap::new(),
            routing_candidates: Arc::new(ArcSwap::new(vec![].into())),
            use_availability_penalty: true,
            window_weights,
            window_weights_sum,
        }
    }

    /// Sets whether to use only k nodes with the highest score for routing.
    #[allow(unused)]
    pub fn set_k_top_nodes(mut self, k_top_nodes: usize) -> Self {
        self.k_top_nodes = Some(k_top_nodes);
        self
    }

    /// Sets whether to use availability penalty in the score computation.
    #[allow(unused)]
    pub fn set_availability_penalty(mut self, use_penalty: bool) -> Self {
        self.use_availability_penalty = use_penalty;
        self
    }

    /// Sets the weights for the sliding window.
    /// The weights are ordered from left to right, where the leftmost weight is for the most recent health check.
    #[allow(unused)]
    pub fn set_window_weights(mut self, weights: &[f64]) -> Self {
        self.window_weights_sum = weights.iter().sum();
        self.window_weights = weights.to_vec();
        self
    }

    /// Atomically updates the routing_candidates
    fn publish_routing_candidates(&self) {
        let mut routing_candidates: Vec<RoutingCandidateNode> = self
            .existing_nodes
            .iter()
            .filter(|(_, v)| v.is_healthy)
            .map(|(k, v)| RoutingCandidateNode::new(k.clone(), v.score))
            .collect();

        // In case requests are routed to only k-top nodes, pre-select these candidates
        if let Some(k_top) = self.k_top_nodes {
            routing_candidates.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            if routing_candidates.len() > k_top {
                routing_candidates.truncate(k_top);
            }
        }
        // Atomically update the table of routing candidates
        self.routing_candidates.store(Arc::new(routing_candidates));
    }
}

/// Helper function to sample nodes based on their weights.
/// Node index is selected based on the input number in range [0.0, 1.0]
#[inline(always)]
fn weighted_sample(weighted_nodes: &[RoutingCandidateNode], number: f64) -> Option<usize> {
    if !(0.0..=1.0).contains(&number) || weighted_nodes.is_empty() {
        return None;
    }
    let sum: f64 = weighted_nodes.iter().map(|n| n.score).sum();

    if sum == 0.0 {
        return None;
    }

    let mut weighted_number = number * sum;
    for (idx, node) in weighted_nodes.iter().enumerate() {
        weighted_number -= node.score;
        if weighted_number <= 0.0 {
            return Some(idx);
        }
    }

    // If this part is reached due to floating-point precision, return the last index
    Some(weighted_nodes.len() - 1)
}

impl RoutingSnapshot for LatencyRoutingSnapshot {
    fn has_nodes(&self) -> bool {
        !self.routing_candidates.load().is_empty()
    }

    fn next_node(&self) -> Option<Node> {
        self.next_n_nodes(1).into_iter().next()
    }

    // Uses weighted random sampling algorithm n times. Node can be selected at most once (sampling without replacement).
    fn next_n_nodes(&self, n: usize) -> Vec<Node> {
        if n == 0 {
            return Vec::new();
        }

        let mut routing_candidates: Vec<RoutingCandidateNode> =
            self.routing_candidates.load().as_ref().clone();

        // Limit the number of returned nodes to the number of available nodes
        let n = std::cmp::min(n, routing_candidates.len());
        let mut nodes = Vec::with_capacity(n);
        let mut rng = rand::thread_rng();

        for _ in 0..n {
            let rand_num = rng.gen::<f64>();
            if let Some(idx) = weighted_sample(routing_candidates.as_slice(), rand_num) {
                let removed_node = routing_candidates.swap_remove(idx);
                nodes.push(removed_node.node);
            }
        }

        nodes
    }

    fn sync_nodes(&mut self, nodes: &[Node]) -> bool {
        let new_nodes: HashSet<&Node> = nodes.iter().collect();
        let mut has_changes = false;

        // Remove nodes that are no longer present
        self.existing_nodes.retain(|node, _| {
            let keep = new_nodes.contains(node);
            if !keep {
                has_changes = true;
            }
            keep
        });

        // Add new nodes that don't exist yet
        for node in nodes {
            if !self.existing_nodes.contains_key(node) {
                self.existing_nodes
                    .insert(node.clone(), NodeMetrics::new(self.window_weights.len()));
                has_changes = true;
            }
        }

        if has_changes {
            self.publish_routing_candidates();
        }

        has_changes
    }

    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> bool {
        // Get mut reference to the existing node metrics or return false if not found
        let updated_node: &mut NodeMetrics = match self.existing_nodes.get_mut(node) {
            Some(metrics) => metrics,
            None => return false,
        };
        // Update the node's metrics
        updated_node.add_latency_measurement(health.latency());

        updated_node.score = compute_score(
            &self.window_weights,
            self.window_weights_sum,
            &updated_node.availabilities,
            &updated_node.latencies,
            self.use_availability_penalty,
        );

        self.publish_routing_candidates();

        true
    }

    fn routes_stats(&self) -> RoutesStats {
        RoutesStats::new(
            self.existing_nodes.len(),
            Some(self.routing_candidates.load().len()),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        time::Duration,
    };

    use crate::agent::route_provider::{
        dynamic_routing::{
            health_check::HealthCheckStatus,
            node::Node,
            snapshot::{
                latency_based_routing::{
                    compute_score, weighted_sample, LatencyRoutingSnapshot, NodeMetrics,
                    RoutingCandidateNode,
                },
                routing_snapshot::RoutingSnapshot,
            },
        },
        RoutesStats,
    };

    #[test]
    fn test_snapshot_init() {
        // Arrange
        let snapshot = LatencyRoutingSnapshot::new();
        // Assert
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next_node().is_none());
        assert!(snapshot.next_n_nodes(1).is_empty());
        assert_eq!(snapshot.routes_stats(), RoutesStats::new(0, Some(0)));
    }

    #[test]
    fn test_update_for_non_existing_node_fails() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new();
        let node = Node::new("api1.com").unwrap();
        let health = HealthCheckStatus::new(Some(Duration::from_secs(1)));
        // Act
        let is_updated = snapshot.update_node(&node, health);
        // Assert
        assert!(!is_updated);
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next_node().is_none());
        assert_eq!(snapshot.routes_stats(), RoutesStats::new(0, Some(0)));
    }

    #[test]
    fn test_update_for_existing_node_succeeds() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new()
            .set_window_weights(&[2.0, 1.0])
            .set_availability_penalty(false);
        let node = Node::new("api1.com").unwrap();
        let health = HealthCheckStatus::new(Some(Duration::from_secs(1)));
        snapshot.sync_nodes(&[node.clone()]);
        assert_eq!(snapshot.routes_stats(), RoutesStats::new(1, Some(0)));
        // Check first update
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        assert!(snapshot.has_nodes());
        let metrics = snapshot.existing_nodes.get(&node).unwrap();
        assert_eq!(metrics.score, (2.0 / 1.0) / 2.0);
        assert_eq!(snapshot.next_node().unwrap(), node);
        assert_eq!(snapshot.routes_stats(), RoutesStats::new(1, Some(1)));
        // Check second update
        let health = HealthCheckStatus::new(Some(Duration::from_secs(2)));
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let metrics = snapshot.existing_nodes.get(&node).unwrap();
        assert_eq!(metrics.score, (2.0 / 2.0 + 1.0 / 1.0) / 3.0);
        // Check third update with none
        let health = HealthCheckStatus::new(None);
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let metrics = snapshot.existing_nodes.get(&node).unwrap();
        assert_eq!(metrics.score, (2.0 / 2.0 + 1.0 / 1.0) / 3.0);
        assert!(!snapshot.has_nodes());
        assert_eq!(snapshot.existing_nodes.len(), 1);
        assert!(snapshot.next_node().is_none());
        assert_eq!(snapshot.routes_stats(), RoutesStats::new(1, Some(0)));
        // Check fourth update
        let health = HealthCheckStatus::new(Some(Duration::from_secs(3)));
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let metrics = snapshot.existing_nodes.get(&node).unwrap();
        assert_eq!(metrics.score, (2.0 / 3.0 + 1.0 / 2.0) / 3.0);
    }

    #[test]
    fn test_sync_node_scenarios() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        // Sync with node_1
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(nodes_changed);
        assert!(snapshot.existing_nodes.contains_key(&node_1));
        assert!(!snapshot.has_nodes());
        // Sync with node_1 again
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(!nodes_changed);
        assert_eq!(
            snapshot.existing_nodes.keys().collect::<Vec<_>>(),
            vec![&node_1]
        );
        // Sync with node_2
        let node_2 = Node::new("api2.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_2.clone()]);
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes.keys().collect::<Vec<_>>(),
            vec![&node_2]
        );
        assert!(!snapshot.has_nodes());
        // Sync with [node_2, node_3]
        let node_3 = Node::new("api3.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_3.clone(), node_2.clone()]);
        assert!(nodes_changed);
        let mut keys = snapshot.existing_nodes.keys().collect::<Vec<_>>();
        keys.sort_by(|a, b| a.domain().cmp(b.domain()));
        assert_eq!(keys, vec![&node_2, &node_3]);
        assert!(!snapshot.has_nodes());
        // Sync with [node_2, node_3] again
        let nodes_changed = snapshot.sync_nodes(&[node_3.clone(), node_2.clone()]);
        assert!(!nodes_changed);
        let mut keys = snapshot.existing_nodes.keys().collect::<Vec<_>>();
        keys.sort_by(|a, b| a.domain().cmp(b.domain()));
        assert_eq!(keys, vec![&node_2, &node_3]);
        assert!(!snapshot.has_nodes());
        // Sync with []
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
        // Sync with [] again
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(!nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_nodes());
    }

    #[test]
    fn test_weighted_sample() {
        let node = Node::new("api1.com").unwrap();
        // Case 1: empty array
        let arr: &[RoutingCandidateNode] = &[];
        let idx = weighted_sample(arr, 0.5);
        assert_eq!(idx, None);
        // Case 2: single element in array
        let arr = &[RoutingCandidateNode::new(node.clone(), 1.0)];
        let idx = weighted_sample(arr, 0.0);
        assert_eq!(idx, Some(0));
        let idx = weighted_sample(arr, 1.0);
        assert_eq!(idx, Some(0));
        // check bounds
        let idx = weighted_sample(arr, -1.0);
        assert_eq!(idx, None);
        let idx = weighted_sample(arr, 1.1);
        assert_eq!(idx, None);
        // Case 3: two elements in array (second element has twice the weight of the first)
        let arr = &[
            RoutingCandidateNode::new(node.clone(), 1.0),
            RoutingCandidateNode::new(node.clone(), 2.0),
        ]; // prefixed_sum = [1.0, 3.0]
        let idx = weighted_sample(arr, 0.0); // 0.0 * 3.0 < 1.0
        assert_eq!(idx, Some(0));
        let idx = weighted_sample(arr, 0.33); // 0.33 * 3.0 < 1.0
        assert_eq!(idx, Some(0)); // selection probability ~0.33
        let idx = weighted_sample(arr, 0.35); // 0.35 * 3.0 > 1.0
        assert_eq!(idx, Some(1)); // selection probability ~0.66
        let idx = weighted_sample(arr, 1.0); // 1.0 * 3.0 > 1.0
        assert_eq!(idx, Some(1));
        // check bounds
        let idx = weighted_sample(arr, -1.0);
        assert_eq!(idx, None);
        let idx = weighted_sample(arr, 1.1);
        assert_eq!(idx, None);
        // Case 4: four elements in array
        let arr = &[
            RoutingCandidateNode::new(node.clone(), 1.0),
            RoutingCandidateNode::new(node.clone(), 2.0),
            RoutingCandidateNode::new(node.clone(), 1.5),
            RoutingCandidateNode::new(node.clone(), 2.5),
        ]; // prefixed_sum = [1.0, 3.0, 4.5, 7.0]
        let idx = weighted_sample(arr, 0.14); // 0.14 * 7 < 1.0
        assert_eq!(idx, Some(0)); // probability ~0.14
        let idx = weighted_sample(arr, 0.15); // 0.15 * 7 > 1.0
        assert_eq!(idx, Some(1));
        let idx = weighted_sample(arr, 0.42); // 0.42 * 7 < 3.0
        assert_eq!(idx, Some(1)); // probability ~0.28
        let idx = weighted_sample(arr, 0.43); // 0.43 * 7 > 3.0
        assert_eq!(idx, Some(2));
        let idx = weighted_sample(arr, 0.64); // 0.64 * 7 < 4.5
        assert_eq!(idx, Some(2)); // probability ~0.22
        let idx = weighted_sample(arr, 0.65); // 0.65 * 7 > 4.5
        assert_eq!(idx, Some(3));
        let idx = weighted_sample(arr, 0.99);
        assert_eq!(idx, Some(3)); // probability ~0.35
                                  // check bounds
        let idx = weighted_sample(arr, -1.0);
        assert_eq!(idx, None);
        let idx = weighted_sample(arr, 1.1);
        assert_eq!(idx, None);
    }

    #[test]
    fn test_compute_score_with_penalty() {
        let use_penalty = true;

        // Test empty arrays
        let weights: &[f64] = &[];
        let weights_sum: f64 = weights.iter().sum();
        let availabilities = VecDeque::new();
        let latencies = VecDeque::new();

        let score = compute_score(
            weights,
            weights_sum,
            &availabilities,
            &latencies,
            use_penalty,
        );
        assert_eq!(score, 0.0);

        // Test arrays with one element.
        let weights: &[f64] = &[2.0, 1.0];
        let weights_sum: f64 = weights.iter().sum();
        let availabilities = vec![true].into();
        let latencies = vec![2.0].into();
        let score = compute_score(
            weights,
            weights_sum,
            &availabilities,
            &latencies,
            use_penalty,
        );
        let score_l = (2.0 / 2.0) / 2.0;
        let score_a = 1.0;
        assert_eq!(score, score_l * score_a);

        // Test arrays with two element.
        let weights: &[f64] = &[2.0, 1.0];
        let weights_sum: f64 = weights.iter().sum();
        let availabilities = vec![true, false].into();
        let latencies = vec![1.0, 2.0].into();
        let score = compute_score(
            weights,
            weights_sum,
            &availabilities,
            &latencies,
            use_penalty,
        );
        let score_l = (2.0 / 2.0 + 1.0 / 1.0) / weights_sum;
        let score_a = (2.0 * 0.0 + 1.0 * 1.0) / weights_sum;
        assert_eq!(score, score_l * score_a);

        // Test arrays of different sizes.
        let weights: &[f64] = &[3.0, 2.0, 1.0];
        let weights_sum: f64 = weights.iter().sum();
        let availabilities = vec![true, false, true].into();
        let latencies = vec![1.0, 2.0].into();
        let score = compute_score(
            weights,
            weights_sum,
            &availabilities,
            &latencies,
            use_penalty,
        );
        let score_l = (3.0 / 2.0 + 2.0 / 1.0) / 5.0;
        let score_a = (3.0 * 1.0 + 2.0 * 0.0 + 1.0 * 1.0) / weights_sum;
        assert_eq!(score, score_l * score_a);
    }

    #[test]
    #[ignore]
    // This test is for manual runs to see the statistics for nodes selection probability.
    fn test_stats_for_next_n_nodes() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new();

        let window_size = 1;

        let node_1 = Node::new("api1.com").unwrap();
        let node_2 = Node::new("api2.com").unwrap();
        let node_3 = Node::new("api3.com").unwrap();
        let node_4 = Node::new("api4.com").unwrap();

        let mut metrics_1 = NodeMetrics::new(window_size);
        let mut metrics_2 = NodeMetrics::new(window_size);
        let mut metrics_3 = NodeMetrics::new(window_size);
        let mut metrics_4 = NodeMetrics::new(window_size);

        metrics_1.is_healthy = true;
        metrics_2.is_healthy = true;
        metrics_3.is_healthy = true;
        metrics_4.is_healthy = false;
        metrics_1.score = 16.0;
        metrics_2.score = 8.0;
        metrics_3.score = 4.0;
        // even though the score is high, this node should never be selected as it is unhealthy
        metrics_4.score = 30.0;

        snapshot.existing_nodes.extend(vec![
            (node_1, metrics_1),
            (node_2, metrics_2),
            (node_3, metrics_3),
            (node_4, metrics_4),
        ]);
        snapshot.publish_routing_candidates();
        let mut stats = HashMap::new();
        let experiments = 30;
        let select_nodes_count = 1;
        for i in 0..experiments {
            let nodes = snapshot.next_n_nodes(select_nodes_count);
            println!("Experiment {i}: selected nodes {nodes:?}");
            for item in nodes.into_iter() {
                *stats.entry(item).or_insert(1) += 1;
            }
        }
        for (node, count) in stats {
            println!(
                "Node {:?} is selected with probability {}",
                node.domain(),
                count as f64 / experiments as f64
            );
        }
    }
}
