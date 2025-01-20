use std::fmt::Debug;

use crate::agent::route_provider::dynamic_routing::{health_check::HealthCheckStatus, node::Node};

/// A trait for interacting with the snapshot of nodes (routing table).
pub trait RoutingSnapshot: Send + Sync + Clone + Debug {
    /// Returns `true` if the snapshot has nodes.
    #[allow(unused)]
    fn has_nodes(&self) -> bool;
    /// Get next node from the snapshot.
    fn next_node(&self) -> Option<Node>;
    /// Get up to n different nodes from the snapshot.
    fn next_n_nodes(&self, n: usize) -> Vec<Node>;
    /// Syncs the nodes in the snapshot with the provided list of nodes, returning `true` if the snapshot was updated.
    fn sync_nodes(&mut self, nodes: &[Node]) -> bool;
    /// Updates the health status of a specific node, returning `true` if the node was found and updated.
    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> bool;
    /// Returns the total number of nodes and healthy nodes as a tuple.
    ///
    /// - First element is the total number of nodes available (both healthy and unhealthy)
    /// - Second element is the number of currently healthy nodes, or None if health status information is unavailable
    ///
    /// The specific criteria for what constitutes a "healthy" node is implementation dependent.
    fn nodes_stats(&self) -> (usize, Option<usize>);
}
