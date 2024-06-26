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

///
#[derive(Default, Debug, Clone)]
pub struct RoundRobinRoutingSnapshot {
    current_idx: Arc<AtomicUsize>,
    healthy_nodes: HashSet<Node>,
    existing_nodes: HashSet<Node>,
}

impl RoundRobinRoutingSnapshot {
    ///
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

    fn next(&self) -> Option<Node> {
        if self.healthy_nodes.is_empty() {
            return None;
        }
        let prev_idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        self.healthy_nodes
            .iter()
            .nth(prev_idx % self.healthy_nodes.len())
            .cloned()
    }

    fn sync_nodes(&mut self, nodes: &[Node]) -> anyhow::Result<bool> {
        let new_nodes = HashSet::from_iter(nodes.iter().cloned());
        // Find nodes removed from snapshot.
        let nodes_removed: Vec<_> = self
            .existing_nodes
            .difference(&new_nodes)
            .cloned()
            .collect();
        let has_removed_nodes = !nodes_removed.is_empty();
        // Find nodes added to snapshot.
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
        Ok(has_added_nodes || has_removed_nodes)
    }

    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> anyhow::Result<bool> {
        if !self.existing_nodes.contains(node) {
            return Ok(false);
        }
        if health.latency.is_some() {
            Ok(self.healthy_nodes.insert(node.clone()))
        } else {
            Ok(self.healthy_nodes.remove(node))
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_update_of_non_existing_node_always_returns_false() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        // This node is not present in existing_nodes
        let node = Node::new("api1.com").unwrap();
        let healthy = HealthCheckStatus {
            latency: Some(Duration::from_secs(1)),
        };
        let unhealthy = HealthCheckStatus { latency: None };
        // Act 1
        let is_updated = snapshot
            .update_node(&node, healthy)
            .expect("node update failed");
        // Assert
        assert!(!is_updated);
        assert!(snapshot.existing_nodes.is_empty());
        assert!(snapshot.next().is_none());
        // Act 2
        let is_updated = snapshot
            .update_node(&node, unhealthy)
            .expect("node update failed");
        // Assert
        assert!(!is_updated);
        assert!(snapshot.existing_nodes.is_empty());
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_update_of_existing_unhealthy_node_with_healthy_node_returns_true() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node = Node::new("api1.com").unwrap();
        // node is present in existing_nodes, but not in healthy_nodes
        snapshot.existing_nodes.insert(node.clone());
        let health = HealthCheckStatus {
            latency: Some(Duration::from_secs(1)),
        };
        // Act
        let is_updated = snapshot
            .update_node(&node, health)
            .expect("node update failed");
        assert!(is_updated);
        assert!(snapshot.has_nodes());
        assert_eq!(snapshot.next().unwrap(), node);
        assert_eq!(snapshot.current_idx.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_update_of_existing_healthy_node_with_unhealthy_node_returns_true() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node = Node::new("api1.com").unwrap();
        snapshot.existing_nodes.insert(node.clone());
        snapshot.healthy_nodes.insert(node.clone());
        let unhealthy = HealthCheckStatus { latency: None };
        // Act
        let is_updated = snapshot
            .update_node(&node, unhealthy)
            .expect("node update failed");
        assert!(is_updated);
        assert!(!snapshot.has_nodes());
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_sync_node_scenarios() {
        // Arrange
        let mut snapshot = RoundRobinRoutingSnapshot::new();
        let node_1 = Node::new("api1.com").unwrap();
        // Sync with node_1
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]).unwrap();
        assert!(nodes_changed);
        assert!(snapshot.healthy_nodes.is_empty());
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        // Add node_1 to healthy_nodes manually
        snapshot.healthy_nodes.insert(node_1.clone());
        // Sync with node_1 again
        let nodes_changed = snapshot.sync_nodes(&[node_1.clone()]).unwrap();
        assert!(!nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_1.clone()])
        );
        assert_eq!(snapshot.healthy_nodes, HashSet::from_iter(vec![node_1]));
        // Sync with node_2
        let node_2 = Node::new("api2.com").unwrap();
        let nodes_changed = snapshot.sync_nodes(&[node_2.clone()]).unwrap();
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
        let nodes_changed = snapshot
            .sync_nodes(&[node_3.clone(), node_2.clone()])
            .unwrap();
        assert!(nodes_changed);
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_3.clone(), node_2.clone()])
        );
        assert_eq!(snapshot.healthy_nodes, HashSet::from_iter(vec![node_2]));
        snapshot.healthy_nodes.insert(node_3);
        // Sync with []
        let nodes_changed = snapshot.sync_nodes(&[]).unwrap();
        assert!(nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
        // Make sure all nodes were removed from the healthy_nodes
        assert!(snapshot.healthy_nodes.is_empty());
        // Sync with [] again
        let nodes_changed = snapshot.sync_nodes(&[]).unwrap();
        assert!(!nodes_changed);
        assert!(snapshot.existing_nodes.is_empty());
    }
}
