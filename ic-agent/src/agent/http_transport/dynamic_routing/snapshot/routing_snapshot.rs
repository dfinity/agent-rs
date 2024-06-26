use std::fmt::Debug;

use crate::agent::http_transport::dynamic_routing::{health_check::HealthCheckStatus, node::Node};

///
pub trait RoutingSnapshot: Send + Sync + Clone + Debug {
    ///
    fn has_nodes(&self) -> bool;
    ///
    fn next(&self) -> Option<Node>;
    ///
    fn sync_nodes(&mut self, nodes: &[Node]) -> anyhow::Result<bool>;
    ///
    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> anyhow::Result<bool>;
}
