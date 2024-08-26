use std::{
    collections::{HashSet, VecDeque},
    time::Duration,
};

use rand::Rng;

use crate::agent::http_transport::dynamic_routing::{
    health_check::HealthCheckStatus, node::Node, snapshot::routing_snapshot::RoutingSnapshot,
};

// Determines the size of the sliding window used for store latencies and availabilities of the node.
const WINDOW_SIZE: usize = 15;
// Determines the decay rate of the exponential decay function used for weights generation.
const LAMBDA_DECAY: f64 = 0.3;

/// Generates exponentially decaying weights for the sliding window.
fn generate_exp_decaying_weights(n: usize, lambda: f64) -> Vec<f64> {
    let mut weights: Vec<f64> = Vec::with_capacity(n);
    for i in 0..n {
        let weight = (-lambda * i as f64).exp();
        weights.push(weight);
    }
    weights
}

// Node with latencies and availability metrics used for generating routing URLs based on the node's score.
#[derive(Clone, Debug)]
struct NodeWithMetrics {
    // Node information.
    node: Node,
    // Size of the sliding window used for store latencies and availabilities of the node.
    window_size: usize,
    /// Reflects the status of the most recent health check. It should be the same as the last element in `availabilities`.
    is_healthy: bool,
    /// Sliding window with latency measurements.
    latencies: VecDeque<f64>,
    /// Sliding window with availability measurements.
    availabilities: VecDeque<bool>,
    /// Overall score of the node. Calculated based on latencies and availabilities arrays. This score is used in `next_n_nodes()` and `next_node()` methods.
    score: f64,
}

impl NodeWithMetrics {
    pub fn new(node: Node, window_size: usize) -> Self {
        Self {
            node,
            window_size,
            is_healthy: false,
            latencies: VecDeque::with_capacity(window_size),
            availabilities: VecDeque::with_capacity(window_size),
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
/// `window_weights_sum`` is passed for efficiency reasons, as it is pre-calculated.
fn compute_score(
    window_weights: &[f64],
    window_weights_sum: f64,
    availabilities: &VecDeque<bool>,
    latencies_secs: &VecDeque<f64>,
    use_availability_penalty: bool,
) -> f64 {
    let weights_size = window_weights.len();
    let availabilities_size = availabilities.len();
    let latencies_size = latencies_secs.len();

    if weights_size < availabilities_size {
        panic!(
            "Weights array of size {weights_size} is smaller than array of availabilities of size {availabilities_size}",
        );
    } else if weights_size < latencies_size {
        panic!(
            "Weights array of size {weights_size} is smaller than array of latencies of size {latencies_size}",
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
    let score_l = if latencies_secs.is_empty() {
        0.0
    } else {
        let mut score = 0.0;

        // Compute weighted score. Weights are applied in reverse order. Latency is inverted, so that smaller latencies have higher score.
        for (idx, latency) in latencies_secs.iter().rev().enumerate() {
            score += window_weights[idx] / latency;
        }

        let weights_sum = if latencies_size < weights_size {
            let partial_weights_sum: f64 = window_weights.iter().take(latencies_secs.len()).sum();
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

/// Routing snapshot for latency-based routing.
/// In this routing strategy, nodes are randomly selected based on their averaged latency of the last WINDOW_SIZE health checks.
/// Nodes with smaller average latencies are preferred for routing.
#[derive(Default, Debug, Clone)]
pub struct LatencyRoutingSnapshot {
    nodes_with_metrics: Vec<NodeWithMetrics>,
    existing_nodes: HashSet<Node>,
    window_weights: Vec<f64>,
    window_weights_sum: f64,
    use_availability_penalty: bool,
}

/// Implementation of the LatencyRoutingSnapshot.
impl LatencyRoutingSnapshot {
    /// Creates a new LatencyRoutingSnapshot.
    pub fn new() -> Self {
        // Weights are ordered from left to right, where the leftmost weight is for the most recent health check.
        let window_weights = generate_exp_decaying_weights(WINDOW_SIZE, LAMBDA_DECAY);
        // Pre-calculate the sum of weights for efficiency reasons.
        let window_weights_sum: f64 = window_weights.iter().sum();

        Self {
            nodes_with_metrics: vec![],
            existing_nodes: HashSet::new(),
            use_availability_penalty: true,
            window_weights,
            window_weights_sum,
        }
    }

    /// Sets whether to use availability penalty in the score computation.
    pub fn set_availability_penalty(mut self, use_penalty: bool) -> Self {
        self.use_availability_penalty = use_penalty;
        self
    }

    /// Sets the weights for the sliding window.
    /// The weights are ordered from left to right, where the leftmost weight is for the most recent health check.
    pub fn set_window_weights(mut self, weights: &[f64]) -> Self {
        self.window_weights_sum = weights.iter().sum();
        self.window_weights = weights.to_vec();
        self
    }
}

/// Helper function to sample nodes based on their weights.
/// Here weight index is selected based on the input number in range [0, 1]
#[inline(always)]
fn weighted_sample(weighted_nodes: &[(f64, &Node)], number: f64) -> Option<usize> {
    if !(0.0..=1.0).contains(&number) {
        return None;
    }
    let sum: f64 = weighted_nodes.iter().map(|n| n.0).sum();
    let mut weighted_number = number * sum;
    for (idx, &(weight, _)) in weighted_nodes.iter().enumerate() {
        weighted_number -= weight;
        if weighted_number <= 0.0 {
            return Some(idx);
        }
    }
    None
}

impl RoutingSnapshot for LatencyRoutingSnapshot {
    fn has_nodes(&self) -> bool {
        self.nodes_with_metrics.iter().any(|n| n.is_healthy)
    }

    fn next_node(&self) -> Option<Node> {
        self.next_n_nodes(1).into_iter().next()
    }

    // Uses weighted random sampling algorithm n times. Node can be selected at most once (sampling without replacement).
    fn next_n_nodes(&self, n: usize) -> Vec<Node> {
        if n == 0 {
            return Vec::new();
        }

        // Preallocate array for a better efficiency.
        let mut healthy_nodes = Vec::with_capacity(self.nodes_with_metrics.len());
        for n in &self.nodes_with_metrics {
            if n.is_healthy {
                healthy_nodes.push((n.score, &n.node));
            }
        }

        // Limit the number of returned nodes to the number of healthy nodes.
        let n = std::cmp::min(n, healthy_nodes.len());

        let mut nodes = Vec::with_capacity(n);

        let mut rng = rand::thread_rng();

        for _ in 0..n {
            // Generate a random float in the range [0, 1)
            let rand_num = rng.gen::<f64>();
            if let Some(idx) = weighted_sample(healthy_nodes.as_slice(), rand_num) {
                let node = healthy_nodes[idx].1;
                nodes.push(node.clone());
                // Remove the item, so that it can't be selected anymore.
                healthy_nodes.swap_remove(idx);
            }
        }

        nodes
    }

    fn sync_nodes(&mut self, nodes: &[Node]) -> bool {
        let new_nodes = HashSet::from_iter(nodes.iter().cloned());
        // Find nodes removed from topology.
        let nodes_removed: Vec<_> = self
            .existing_nodes
            .difference(&new_nodes)
            .cloned()
            .collect();
        let has_removed_nodes = !nodes_removed.is_empty();
        // Find nodes added to topology.
        let nodes_added: Vec<_> = new_nodes
            .difference(&self.existing_nodes)
            .cloned()
            .collect();
        let has_added_nodes = !nodes_added.is_empty();
        self.existing_nodes.extend(nodes_added);
        // NOTE: newly added nodes will appear in the weighted_nodes later.
        // This happens after the first node health check round and a consequent update_node() invocation.
        for node in nodes_removed.into_iter() {
            self.existing_nodes.remove(&node);
            let idx = self.nodes_with_metrics.iter().position(|x| x.node == node);
            idx.map(|idx| self.nodes_with_metrics.swap_remove(idx));
        }

        has_added_nodes || has_removed_nodes
    }

    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> bool {
        // Skip the update if the node is not in the existing nodes.
        if !self.existing_nodes.contains(node) {
            return false;
        }

        let idx = self
            .nodes_with_metrics
            .iter()
            .position(|x| &x.node == node)
            .unwrap_or_else(|| {
                let node = NodeWithMetrics::new(node.clone(), self.window_weights.len());
                self.nodes_with_metrics.push(node);
                self.nodes_with_metrics.len() - 1
            });

        self.nodes_with_metrics[idx].add_latency_measurement(health.latency());

        self.nodes_with_metrics[idx].score = compute_score(
            self.window_weights.as_slice(),
            self.window_weights_sum,
            &self.nodes_with_metrics[idx].availabilities,
            &self.nodes_with_metrics[idx].latencies,
            self.use_availability_penalty,
        );

        true
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        time::Duration,
    };

    use crate::agent::http_transport::dynamic_routing::{
        health_check::HealthCheckStatus,
        node::Node,
        snapshot::{
            latency_based_routing::{
                compute_score, weighted_sample, LatencyRoutingSnapshot, NodeWithMetrics,
            },
            routing_snapshot::RoutingSnapshot,
        },
    };

    #[test]
    fn test_snapshot_init() {
        // Arrange
        let snapshot = LatencyRoutingSnapshot::new();
        // Assert
        assert!(snapshot.nodes_with_metrics.is_empty());
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next_node().is_none());
        assert!(snapshot.next_n_nodes(1).is_empty());
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
        assert!(snapshot.nodes_with_metrics.is_empty());
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next_node().is_none());
    }

    #[test]
    fn test_update_for_existing_node_succeeds() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new()
            .set_window_weights(&[2.0, 1.0])
            .set_availability_penalty(false);
        let node = Node::new("api1.com").unwrap();
        let health = HealthCheckStatus::new(Some(Duration::from_secs(1)));
        snapshot.existing_nodes.insert(node.clone());
        // Check first update
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        assert!(snapshot.has_nodes());
        let node_with_metrics = snapshot.nodes_with_metrics.first().unwrap();
        assert_eq!(node_with_metrics.score, (2.0 / 1.0) / 2.0);
        assert_eq!(snapshot.next_node().unwrap(), node);
        // Check second update
        let health = HealthCheckStatus::new(Some(Duration::from_secs(2)));
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let node_with_metrics = snapshot.nodes_with_metrics.first().unwrap();
        assert_eq!(node_with_metrics.score, (2.0 / 2.0 + 1.0 / 1.0) / 3.0);
        // Check third update
        let health = HealthCheckStatus::new(Some(Duration::from_secs(3)));
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let node_with_metrics = snapshot.nodes_with_metrics.first().unwrap();
        assert_eq!(node_with_metrics.score, (2.0 / 3.0 + 1.0 / 2.0) / 3.0);
        // Check forth update with none
        let health = HealthCheckStatus::new(None);
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let node_with_metrics = snapshot.nodes_with_metrics.first().unwrap();
        assert_eq!(node_with_metrics.score, (2.0 / 3.0 + 1.0 / 2.0) / 3.0);
        assert!(!snapshot.has_nodes());
        assert_eq!(snapshot.nodes_with_metrics.len(), 1);
        assert_eq!(snapshot.existing_nodes.len(), 1);
        assert!(snapshot.next_node().is_none());
    }

    #[test]
    fn test_sync_node_scenarios() {
        // Arrange
        let window_size = 1;
        let mut snapshot = LatencyRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        // Sync with node_1
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(nodes_changed);
        assert!(snapshot.nodes_with_metrics.is_empty());
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        // Add node_1 to weighted_nodes manually
        snapshot
            .nodes_with_metrics
            .push(NodeWithMetrics::new(node_1.clone(), window_size));
        // Sync with node_1 again
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(!nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        assert_eq!(snapshot.nodes_with_metrics[0].node, node_1);
        // Sync with node_2
        let node_2 = Node::new("api2.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_2.clone()]);
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_2.clone()])
        );
        // Make sure node_1 was removed from weighted_nodes too
        assert!(snapshot.nodes_with_metrics.is_empty());
        // Add node_2 to weighted_nodes manually
        snapshot
            .nodes_with_metrics
            .push(NodeWithMetrics::new(node_2.clone(), window_size));
        // Sync with [node_2, node_3]
        let node_3 = Node::new("api3.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_3.clone(), node_2.clone()]);
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_3.clone(), node_2.clone()])
        );
        assert_eq!(snapshot.nodes_with_metrics[0].node, node_2);
        // Add node_3 to weighted_nodes manually
        snapshot
            .nodes_with_metrics
            .push(NodeWithMetrics::new(node_3, window_size));
        // Sync with []
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
        // Make sure all nodes were removed from the healthy_nodes
        assert!(snapshot.nodes_with_metrics.is_empty());
        // Sync with [] again
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(!nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_nodes());
    }

    #[test]
    fn test_weighted_sample() {
        let node = &Node::new("api1.com").unwrap();
        // Case 1: empty array
        let arr = &[];
        let idx = weighted_sample(arr, 0.5);
        assert_eq!(idx, None);
        // Case 2: single element in array
        let arr = &[(1.0, node)];
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
        let arr = &[(1.0, node), (2.0, node)]; // // prefixed_sum = [1.0, 3.0]
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
        let arr = &[(1.0, node), (2.0, node), (1.5, node), (2.5, node)]; // prefixed_sum = [1.0, 3.0, 4.5, 7.0]
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

        // Test with arrays of different sizes.
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

        let mut node_1 = NodeWithMetrics::new(node_1, window_size);
        let mut node_2 = NodeWithMetrics::new(node_2, window_size);
        let mut node_3 = NodeWithMetrics::new(node_3, window_size);
        let mut node_4 = NodeWithMetrics::new(node_4, window_size);

        node_1.is_healthy = true;
        node_2.is_healthy = true;
        node_3.is_healthy = true;
        node_4.is_healthy = false;

        node_1.score = 16.0;
        node_2.score = 8.0;
        node_3.score = 4.0;

        snapshot.nodes_with_metrics = vec![node_1, node_2, node_3, node_4];

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
