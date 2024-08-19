use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::agent::http_transport::dynamic_routing::{
    health_check::HealthCheckStatus, node::Node, snapshot::routing_snapshot::RoutingSnapshot,
};

/// Routing snapshot, which samples nodes in a round-robin fashion.
#[derive(Default, Debug, Clone)]
pub struct RoundRobinRoutingSnapshot {
    current_idx: Arc<AtomicUsize>,
    healthy_nodes: HashSet<Node>,
    existing_nodes: HashSet<Node>,
}

impl RoundRobinRoutingSnapshot {
    /// Creates a new instance of `RoundRobinRoutingSnapshot`.
    pub fn new() -> Self {
        Self {
            current_idx: Arc::new(AtomicUsize::new(0)),
            healthy_nodes: HashSet::new(),
            existing_nodes: HashSet::new(),
        }
    }
}

impl RoutingSnapshot for RoundRobinRoutingSnapshot {
    fn has_nodes(&self) -> bool {
        !self.healthy_nodes.is_empty()
    }

    fn next_node(&self) -> Option<Node> {
        if self.healthy_nodes.is_empty() {
            return None;
        }
        let prev_idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        self.healthy_nodes
            .iter()
            .nth(prev_idx % self.healthy_nodes.len())
            .cloned()
    }

    fn next_n_nodes(&self, n: usize) -> Option<Vec<Node>> {
        if n == 0 {
            return Some(Vec::new());
        }

        let healthy_nodes = Vec::from_iter(self.healthy_nodes.clone());
        let healthy_count = healthy_nodes.len();

        if n >= healthy_count {
            return Some(healthy_nodes.clone());
        }

        let idx = self.current_idx.fetch_add(n, Ordering::Relaxed) % healthy_count;
        let mut nodes = Vec::with_capacity(n);

        if healthy_count - idx >= n {
            nodes.extend_from_slice(&healthy_nodes[idx..idx + n]);
        } else {
            nodes.extend_from_slice(&healthy_nodes[idx..]);
            nodes.extend_from_slice(&healthy_nodes[..n - nodes.len()]);
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
        // NOTE: newly added nodes will appear in the healthy_nodes later.
        // This happens after the first node health check round and a consequent update_node() invocation.
        self.existing_nodes.extend(nodes_added);
        nodes_removed.iter().for_each(|node| {
            self.existing_nodes.remove(node);
            self.healthy_nodes.remove(node);
        });

        has_added_nodes || has_removed_nodes
    }

    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> bool {
        if !self.existing_nodes.contains(node) {
            return false;
        }
        if health.is_healthy() {
            self.healthy_nodes.insert(node.clone())
        } else {
            self.healthy_nodes.remove(node)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;
    use std::{collections::HashSet, sync::atomic::Ordering};

    use crate::agent::http_transport::dynamic_routing::{
        health_check::HealthCheckStatus,
        node::Node,
        snapshot::{
            round_robin_routing::RoundRobinRoutingSnapshot, routing_snapshot::RoutingSnapshot,
        },
    };

    #[test]
    fn test_snapshot_init() {
        // Arrange
        let snapshot = RoundRobinRoutingSnapshot::new();
        // Assert
        assert!(snapshot.healthy_nodes.is_empty());
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_nodes());
        assert_eq!(snapshot.current_idx.load(Ordering::SeqCst), 0);
        assert!(snapshot.next_node().is_none());
    }

    #[test]
    fn test_update_of_non_existing_node_always_returns_false() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        // This node is not present in existing_nodes
        let node = Node::new("api1.com").unwrap();
        let healthy = HealthCheckStatus::new(Some(Duration::from_secs(1)));
        let unhealthy = HealthCheckStatus::new(None);
        // Act 1
        let is_updated = snapshot.update_node(&node, healthy);
        // Assert
        assert!(!is_updated);
        assert!(snapshot.existing_nodes.is_empty());
        assert!(snapshot.next_node().is_none());
        // Act 2
        let is_updated = snapshot.update_node(&node, unhealthy);
        // Assert
        assert!(!is_updated);
        assert!(snapshot.existing_nodes.is_empty());
        assert!(snapshot.next_node().is_none());
    }

    #[test]
    fn test_update_of_existing_unhealthy_node_with_healthy_node_returns_true() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node = Node::new("api1.com").unwrap();
        // node is present in existing_nodes, but not in healthy_nodes
        snapshot.existing_nodes.insert(node.clone());
        let health = HealthCheckStatus::new(Some(Duration::from_secs(1)));
        // Act
        let is_updated = snapshot.update_node(&node, health);
        assert!(is_updated);
        assert!(snapshot.has_nodes());
        assert_eq!(snapshot.next_node().unwrap(), node);
        assert_eq!(snapshot.current_idx.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_update_of_existing_healthy_node_with_unhealthy_node_returns_true() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node = Node::new("api1.com").unwrap();
        snapshot.existing_nodes.insert(node.clone());
        snapshot.healthy_nodes.insert(node.clone());
        let unhealthy = HealthCheckStatus::new(None);
        // Act
        let is_updated = snapshot.update_node(&node, unhealthy);
        assert!(is_updated);
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next_node().is_none());
    }

    #[test]
    fn test_sync_node_scenarios() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        // Sync with node_1
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(nodes_changed);
        assert!(snapshot.healthy_nodes.is_empty());
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        // Add node_1 to healthy_nodes manually
        snapshot.healthy_nodes.insert(node_1.clone());
        // Sync with node_1 again
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]);
        assert!(!nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        assert_eq!(snapshot.healthy_nodes, HashSet::from_iter(vec![node_1]));
        // Sync with node_2
        let node_2 = Node::new("api2.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_2.clone()]);
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_2.clone()])
        );
        // Make sure node_1 was removed from healthy nodes
        assert!(snapshot.healthy_nodes.is_empty());
        // Add node_2 to healthy_nodes manually
        snapshot.healthy_nodes.insert(node_2.clone());
        // Sync with [node_2, node_3]
        let node_3 = Node::new("api3.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_3.clone(), node_2.clone()]);
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_3.clone(), node_2.clone()])
        );
        assert_eq!(snapshot.healthy_nodes, HashSet::from_iter(vec![node_2]));
        snapshot.healthy_nodes.insert(node_3);
        // Sync with []
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
        // Make sure all nodes were removed from the healthy_nodes
        assert!(snapshot.healthy_nodes.is_empty());
        // Sync with [] again
        let nodes_changed = snapshot.sync_nodes(&[]);
        assert!(!nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
    }

    #[test]
    fn test_next_node() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        let node_2 = Node::new("api2.com").unwrap();
        let node_3 = Node::new("api3.com").unwrap();
        let nodes = vec![node_1, node_2, node_3];
        snapshot.existing_nodes.extend(nodes.clone());
        snapshot.healthy_nodes.extend(nodes);
        // Act + Assert
        let node = snapshot.next_node().unwrap();
        assert_eq!(node.domain().as_str(), "api1.com");
        let node = snapshot.next_node().unwrap();
        assert_eq!(node.domain().as_str(), "api2.com");
        let node = snapshot.next_node().unwrap();
        assert_eq!(node.domain().as_str(), "api3.com");
        let node = snapshot.next_node().unwrap();
        assert_eq!(node.domain().as_str(), "api1.com");
    }

    #[test]
    fn test_n_nodes() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        let node_2 = Node::new("api2.com").unwrap();
        let node_3 = Node::new("api3.com").unwrap();
        let node_4 = Node::new("api4.com").unwrap();
        let node_5 = Node::new("api5.com").unwrap();
        let nodes = vec![
            node_1.clone(),
            node_2.clone(),
            node_3.clone(),
            node_4.clone(),
            node_5.clone(),
        ];
        snapshot.healthy_nodes.extend(nodes.clone());
        // First call
        let mut n_nodes: Vec<_> = snapshot.next_n_nodes(3).expect("failed to get nodes");
        // Second call
        n_nodes.extend(snapshot.next_n_nodes(3).expect("failed to get nodes"));
        // Third call
        n_nodes.extend(snapshot.next_n_nodes(4).expect("failed to get nodes"));
        // Fourth call
        n_nodes.extend(snapshot.next_n_nodes(5).expect("failed to get nodes"));
        // Assert each node was returned 2 times
        let k = 2;
        let mut count_map = HashMap::new();
        for item in nodes.iter() {
            *count_map.entry(item).or_insert(1) += 1;
        }
        assert_eq!(
            count_map.len(),
            nodes.len(),
            "The number of unique elements is not {}",
            nodes.len()
        );
        for (item, &count) in &count_map {
            assert_eq!(
                count, k,
                "Element {:?} does not appear exactly {} times",
                item, k
            );
        }
    }
}
