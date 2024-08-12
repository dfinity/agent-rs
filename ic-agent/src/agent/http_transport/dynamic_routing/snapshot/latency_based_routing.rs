use std::{collections::HashSet, time::Duration};

use rand::Rng;
use simple_moving_average::{SumTreeSMA, SMA};

use crate::agent::http_transport::dynamic_routing::{
    health_check::HealthCheckStatus, node::Node, snapshot::routing_snapshot::RoutingSnapshot,
};

// When a node is detected as unhealthy, we take the following actions:
// - Remove the node entirely from the routing.
// - Penalize its moving average by adding a specified value to the stored latency window. This ensures that any node exhibiting intermittent outages is appropriately penalized.
const PUNISH_LATENCY: Duration = Duration::from_secs(2);

const WINDOW_SIZE: usize = 15;

// Algorithmic complexity: add sample - O(log(N)), get average - O(1).
// Space complexity: O(N)
type LatencyMovAvg = SumTreeSMA<Duration, u32, WINDOW_SIZE>;

/// A node, which stores health check latencies in the form of moving average.
#[derive(Clone, Debug)]
struct WeightedNode {
    node: Node,
    /// Reflects the status of the most recent health check.
    is_healthy: bool,
    /// Moving mean of latencies measurements.
    latency_mov_avg: LatencyMovAvg,
    /// Weight of the node (invers of the average latency), used for stochastic weighted random sampling.
    weight: f64,
}

/// Routing snapshot for latency-based routing.
/// In this routing strategy, nodes are randomly selected based on their averaged latency of the last WINDOW_SIZE health checks.
/// Nodes with smaller average latencies are preferred for routing.
#[derive(Default, Debug, Clone)]
pub struct LatencyRoutingSnapshot {
    weighted_nodes: Vec<WeightedNode>,
    existing_nodes: HashSet<Node>,
}

/// Implementation of the LatencyRoutingSnapshot.
impl LatencyRoutingSnapshot {
    /// Creates a new LatencyRoutingSnapshot.
    pub fn new() -> Self {
        Self {
            weighted_nodes: vec![],
            existing_nodes: HashSet::new(),
        }
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
    for (idx, weighted_node) in weighted_nodes.iter().enumerate() {
        weighted_number -= weighted_node.0;
        if weighted_number <= 0.0 {
            return Some(idx);
        }
    }
    None
}

impl RoutingSnapshot for LatencyRoutingSnapshot {
    fn has_nodes(&self) -> bool {
        !self.weighted_nodes.is_empty()
    }

    fn next(&self) -> Option<Node> {
        // We select a healthy node based on its weight, using a stochastic weighted random sampling approach.

        // Preallocate array for a better efficiency.
        let mut healthy_weighted_nodes = Vec::with_capacity(self.weighted_nodes.len());
        for n in &self.weighted_nodes {
            if n.is_healthy {
                healthy_weighted_nodes.push((n.weight, &n.node));
            }
        }
        // Generate a random float in the range [0, 1)
        let mut rng = rand::thread_rng();
        let rand_num = rng.gen::<f64>();
        // Using this random float and an array of weights we get an index of the node.
        let idx = weighted_sample(healthy_weighted_nodes.as_slice(), rand_num);
        idx.map(|idx| healthy_weighted_nodes[idx].1.clone())
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
            let idx = self.weighted_nodes.iter().position(|x| x.node == node);
            idx.map(|idx| self.weighted_nodes.swap_remove(idx));
        }

        has_added_nodes || has_removed_nodes
    }

    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> bool {
        if !self.existing_nodes.contains(node) {
            return false;
        }

        // If the node is unhealthy, we penalize it's moving average.
        let latency = health.latency().unwrap_or(PUNISH_LATENCY);

        if let Some(idx) = self.weighted_nodes.iter().position(|x| &x.node == node) {
            // Node is already in the array (it is not the first update_node() call).
            self.weighted_nodes[idx].is_healthy = health.is_healthy();
            self.weighted_nodes[idx].latency_mov_avg.add_sample(latency);
            let latency_avg = self.weighted_nodes[idx].latency_mov_avg.get_average();
            // As nodes with smaller average latencies are preferred for routing, we use inverted values for weights.
            self.weighted_nodes[idx].weight = 1.0 / latency_avg.as_secs_f64();
        } else {
            // Node is not yet in array (first update_node() call).
            let mut latency_mov_avg = LatencyMovAvg::from_zero(Duration::ZERO);
            latency_mov_avg.add_sample(latency);
            let weight = 1.0 / latency_mov_avg.get_average().as_secs_f64();
            self.weighted_nodes.push(WeightedNode {
                is_healthy: health.is_healthy(),
                latency_mov_avg,
                node: node.clone(),
                weight,
            })
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

    use simple_moving_average::SMA;

    use crate::agent::http_transport::dynamic_routing::{
        health_check::HealthCheckStatus,
        node::Node,
        snapshot::{
            latency_based_routing::{
                weighted_sample, LatencyMovAvg, LatencyRoutingSnapshot, WeightedNode,
                PUNISH_LATENCY,
            },
            routing_snapshot::RoutingSnapshot,
        },
    };

    #[test]
    fn test_snapshot_init() {
        // Arrange
        let snapshot = LatencyRoutingSnapshot::new();
        // Assert
        assert!(snapshot.weighted_nodes.is_empty());
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next().is_none());
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
        assert!(snapshot.weighted_nodes.is_empty());
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_update_for_existing_node_succeeds() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new();
        let node = Node::new("api1.com").unwrap();
        let health = HealthCheckStatus::new(Some(Duration::from_secs(1)));
        snapshot.existing_nodes.insert(node.clone());
        // Check first update
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        assert!(snapshot.has_nodes());
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        assert_eq!(
            weighted_node.latency_mov_avg.get_average(),
            Duration::from_secs(1)
        );
        assert_eq!(weighted_node.weight, 1.0);
        assert_eq!(snapshot.next().unwrap(), node);
        // Check second update
        let health = HealthCheckStatus::new(Some(Duration::from_secs(2)));
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        assert_eq!(
            weighted_node.latency_mov_avg.get_average(),
            Duration::from_millis(1500)
        );
        assert_eq!(weighted_node.weight, 1.0 / 1.5);
        assert_eq!(snapshot.next().unwrap(), node);
        // Check third update
        let health = HealthCheckStatus::new(Some(Duration::from_secs(3)));
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        assert_eq!(
            weighted_node.latency_mov_avg.get_average(),
            Duration::from_millis(2000)
        );
        assert_eq!(weighted_node.weight, 0.5);
        assert_eq!(snapshot.next().unwrap(), node);
        // Check forth update with none
        let health = HealthCheckStatus::new(None);
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        let avg_latency = Duration::from_secs_f64((PUNISH_LATENCY.as_secs() as f64 + 6.0) / 4.0);
        assert_eq!(weighted_node.latency_mov_avg.get_average(), avg_latency);
        assert_eq!(weighted_node.weight, 1.0 / avg_latency.as_secs_f64());
        assert_eq!(snapshot.weighted_nodes.len(), 1);
        assert_eq!(snapshot.existing_nodes.len(), 1);
        // No nodes returned, as the node is unhealthy.
        assert!(snapshot.next().is_none());
        // Check fifth update
        let health = HealthCheckStatus::new(Some(Duration::from_secs(1)));
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        let avg_latency = Duration::from_secs_f64((PUNISH_LATENCY.as_secs() as f64 + 7.0) / 5.0);
        assert_eq!(weighted_node.latency_mov_avg.get_average(), avg_latency);
        assert_eq!(weighted_node.weight, 1.0 / avg_latency.as_secs_f64());
        assert_eq!(snapshot.weighted_nodes.len(), 1);
        assert_eq!(snapshot.existing_nodes.len(), 1);
        assert_eq!(snapshot.next().unwrap(), node);
    }

    #[test]
    fn test_sync_node_scenarios() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        // Sync with node_1
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(nodes_changed);
        assert!(snapshot.weighted_nodes.is_empty());
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        // Add node_1 to weighted_nodes manually
        snapshot.weighted_nodes.push(WeightedNode {
            is_healthy: true,
            node: node_1.clone(),
            latency_mov_avg: LatencyMovAvg::from_zero(Duration::ZERO),
            weight: 0.0,
        });
        // Sync with node_1 again
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(!nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        assert_eq!(snapshot.weighted_nodes[0].node, node_1);
        // Sync with node_2
        let node_2 = Node::new("api2.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_2.clone()]);
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_2.clone()])
        );
        // Make sure node_1 was removed from weighted_nodes too
        assert!(snapshot.weighted_nodes.is_empty());
        // Add node_2 to weighted_nodes manually
        snapshot.weighted_nodes.push(WeightedNode {
            is_healthy: true,
            node: node_2.clone(),
            latency_mov_avg: LatencyMovAvg::from_zero(Duration::ZERO),
            weight: 0.0,
        });
        // Sync with [node_2, node_3]
        let node_3 = Node::new("api3.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_3.clone(), node_2.clone()]);
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_3.clone(), node_2.clone()])
        );
        assert_eq!(snapshot.weighted_nodes[0].node, node_2);
        // Add node_3 to weighted_nodes manually
        snapshot.weighted_nodes.push(WeightedNode {
            is_healthy: true,
            node: node_3,
            latency_mov_avg: LatencyMovAvg::from_zero(Duration::ZERO),
            weight: 0.0,
        });
        // Sync with []
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
        // Make sure all nodes were removed from the healthy_nodes
        assert!(snapshot.weighted_nodes.is_empty());
        // Sync with [] again
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(!nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
    }

    #[test]
    fn test_weighted_sample() {
        // Case 1: empty array
        let node = Node::new("ic0.com").unwrap();
        let arr = &[(0.5, &node)];
        let idx = weighted_sample(arr, 0.5);
        assert_eq!(idx, None);
        // Case 2: single element in array
        let arr = &[(1.0, &node)];
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
        let arr = &[(1.0, &node), (2.0, &node)]; // prefixed_sum = [1.0, 3.0]
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
        let arr = &[(1.0, &node), (2.0, &node), (1.5, &node), (2.5, &node)]; // prefixed_sum = [1.0, 3.0, 4.5, 7.0]
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
}
