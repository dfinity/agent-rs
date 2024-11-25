use crate::agent::{
    route_provider::dynamic_routing::health_check::HealthCheckStatus, ApiBoundaryNode,
};

/// Represents a message with fetched nodes.
#[derive(Debug, Clone)]
pub struct FetchedNodes {
    /// The fetched nodes.
    pub nodes: Vec<ApiBoundaryNode>,
}

/// Represents a message with the health state of a node.
pub struct NodeHealthState {
    /// The node.
    pub node: ApiBoundaryNode,
    /// The health state of the node.
    pub health: HealthCheckStatus,
}
