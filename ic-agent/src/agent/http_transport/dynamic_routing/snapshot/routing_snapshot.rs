use std::fmt::Debug;

use crate::agent::http_transport::dynamic_routing::{health_check::HealthCheckStatus, node::Node};

/// A trait for interacting with the snapshot of nodes (routing table).
pub trait RoutingSnapshot: Send + Sync + Clone + Debug {
    /// Returns `true` if the snapshot has nodes.
    fn has_nodes(&self) -> bool;
    /// Get the next node in the snapshot.
    fn next(&self) -> Option<Node>;
    /// Syncs the nodes in the snapshot with the provided list of nodes, returning `true` if the snapshot was updated.
    fn sync_nodes(&mut self, nodes: &[Node]) -> bool;
    /// Updates the health status of a specific node, returning `true` if the node was found and updated.
    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> bool;
}
