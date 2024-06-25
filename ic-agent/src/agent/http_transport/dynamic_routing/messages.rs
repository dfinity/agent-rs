use crate::agent::http_transport::dynamic_routing::{health_check::HealthCheckStatus, node::Node};

#[derive(Debug, Clone)]
pub struct FetchedNodes {
    pub nodes: Vec<Node>,
}

pub struct NodeHealthState {
    pub node: Node,
    pub health: HealthCheckStatus,
}
