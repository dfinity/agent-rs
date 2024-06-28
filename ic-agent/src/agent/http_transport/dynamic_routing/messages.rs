use crate::agent::http_transport::dynamic_routing::{health_check::HealthCheckStatus, node::Node};

/// Represents a message with fetched nodes.
#[derive(Debug, Clone)]
pub struct FetchedNodes {
    /// The fetched nodes.
    pub nodes: Vec<Node>,
}

/// Represents a message with the health state of a node.
pub struct NodeHealthState {
    /// The node.
    pub node: Node,
    /// The health state of the node.
    pub health: HealthCheckStatus,
}
