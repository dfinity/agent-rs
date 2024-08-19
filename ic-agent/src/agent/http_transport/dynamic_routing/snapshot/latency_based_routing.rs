use std::{collections::HashSet, time::Duration};

use rand::Rng;
use simple_moving_average::{SumTreeSMA, SMA};

use crate::agent::http_transport::dynamic_routing::{
    health_check::HealthCheckStatus, node::Node, snapshot::routing_snapshot::RoutingSnapshot,
};

// Some big value implying that node is unhealthy, should be much bigger than node's latency.
const MAX_LATENCY: Duration = Duration::from_secs(500);

const WINDOW_SIZE: usize = 15;

// Algorithmic complexity: add sample - O(log(N)), get average - O(1).
// Space complexity: O(N)
type LatencyMovAvg = SumTreeSMA<Duration, u32, WINDOW_SIZE>;

/// A node, which stores health check latencies in the form of moving average.
#[derive(Clone, Debug)]
struct WeightedNode {
    node: Node,
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
        !self.weighted_nodes.is_empty()
    }

    fn next_node(&self) -> Option<Node> {
        // We select a node based on it's weight, using a stochastic weighted random sampling approach.
        let weighted_nodes: Vec<_> = self
            .weighted_nodes
            .iter()
            .map(|n| (n.weight, &n.node))
            .collect();
        // Generate a random float in the range [0, 1)
        let mut rng = rand::thread_rng();
        let rand_num = rng.gen::<f64>();
        // Using this random float and an array of weights we get an index of the node.
        let idx = weighted_sample(weighted_nodes.as_slice(), rand_num);
        idx.map(|idx| self.weighted_nodes[idx].node.clone())
    }

    // Uses weighted random sampling algorithm with item replacement n times.
    fn next_n_nodes(&self, n: usize) -> Option<Vec<Node>> {
        if n == 0 {
            return Some(Vec::new());
        }

        let n = std::cmp::min(n, self.weighted_nodes.len());

        let mut nodes = Vec::with_capacity(n);

        let mut weighted_nodes: Vec<_> = self
            .weighted_nodes
            .iter()
            .map(|n| (n.weight, &n.node))
            .collect();

        let mut rng = rand::thread_rng();

        for _ in 0..n {
            // Generate a random float in the range [0, 1)
            let rand_num = rng.gen::<f64>();
            if let Some(idx) = weighted_sample(weighted_nodes.as_slice(), rand_num) {
                let node = weighted_nodes[idx].1;
                nodes.push(node.clone());
                // Remove the item, so that it can't be selected anymore.
                weighted_nodes.swap_remove(idx);
            }
        }

        Some(nodes)
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

        // If latency is None (meaning Node is unhealthy), we assign some big value
        let latency = health.latency().unwrap_or(MAX_LATENCY);

        if let Some(idx) = self.weighted_nodes.iter().position(|x| &x.node == node) {
            // Node is already in the array (it is not the first update_node() call).
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
    use std::{
        collections::{HashMap, HashSet},
        time::Duration,
    };

    use simple_moving_average::SMA;

    use crate::agent::http_transport::dynamic_routing::{
        health_check::HealthCheckStatus,
        node::Node,
        snapshot::{
            latency_based_routing::{
                weighted_sample, LatencyMovAvg, LatencyRoutingSnapshot, WeightedNode, MAX_LATENCY,
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
        assert!(snapshot.next_node().is_none());
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
        assert!(snapshot.next_node().is_none());
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
        assert_eq!(snapshot.next_node().unwrap(), node);
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
        // Check forth update with none
        let health = HealthCheckStatus::new(None);
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        let avg_latency = Duration::from_secs_f64((MAX_LATENCY.as_secs() as f64 + 6.0) / 4.0);
        assert_eq!(weighted_node.latency_mov_avg.get_average(), avg_latency);
        assert_eq!(weighted_node.weight, 1.0 / avg_latency.as_secs_f64());
        assert_eq!(snapshot.weighted_nodes.len(), 1);
        assert_eq!(snapshot.existing_nodes.len(), 1);
        assert_eq!(snapshot.next_node().unwrap(), node);
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
    #[ignore]
    // This test is for manual runs to see the statistics for nodes selection probability.
    fn test_stats_for_next_n_nodes() {
        // Arrange
        let mut snapshot = LatencyRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        let node_2 = Node::new("api2.com").unwrap();
        let node_3 = Node::new("api3.com").unwrap();
        let node_4 = Node::new("api4.com").unwrap();
        let node_5 = Node::new("api5.com").unwrap();
        let node_6 = Node::new("api6.com").unwrap();
        let latency_mov_avg = LatencyMovAvg::from_zero(Duration::ZERO);
        snapshot.weighted_nodes = vec![
            WeightedNode {
                node: node_2.clone(),
                latency_mov_avg: latency_mov_avg.clone(),
                weight: 8.0,
            },
            WeightedNode {
                node: node_3.clone(),
                latency_mov_avg: latency_mov_avg.clone(),
                weight: 4.0,
            },
            WeightedNode {
                node: node_1.clone(),
                latency_mov_avg: latency_mov_avg.clone(),
                weight: 16.0,
            },
            WeightedNode {
                node: node_6.clone(),
                latency_mov_avg: latency_mov_avg.clone(),
                weight: 2.0,
            },
            WeightedNode {
                node: node_5.clone(),
                latency_mov_avg: latency_mov_avg.clone(),
                weight: 1.0,
            },
            WeightedNode {
                node: node_4.clone(),
                latency_mov_avg: latency_mov_avg.clone(),
                weight: 4.1,
            },
        ];

        let mut stats = HashMap::new();
        let experiments = 30;
        let select_nodes_count = 2;
        for i in 0..experiments {
            let nodes = snapshot.next_n_nodes(select_nodes_count).unwrap();
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
