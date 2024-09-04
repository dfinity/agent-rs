use async_trait::async_trait;
use futures_util::FutureExt;
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use std::{
    fmt::Debug,
    sync::Arc,
    time::{Duration, Instant},
};
use stop_token::{StopSource, StopToken};
use tracing::{debug, error, info, trace, warn};
use url::Url;

use crate::agent::route_provider::dynamic_routing::{
    dynamic_route_provider::DynamicRouteProviderError,
    messages::{FetchedNodes, NodeHealthState},
    node::Node,
    snapshot::routing_snapshot::RoutingSnapshot,
    type_aliases::{AtomicSwap, ReceiverMpsc, ReceiverWatch, SenderMpsc},
};

const CHANNEL_BUFFER: usize = 128;

/// A trait representing a health check of the node.
#[async_trait]
pub trait HealthCheck: Send + Sync + Debug {
    /// Checks the health of the node.
    async fn check(&self, node: &Node) -> Result<HealthCheckStatus, DynamicRouteProviderError>;
}

/// A struct representing the health check status of the node.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct HealthCheckStatus {
    latency: Option<Duration>,
}

impl HealthCheckStatus {
    /// Creates a new `HealthCheckStatus` instance.
    pub fn new(latency: Option<Duration>) -> Self {
        Self { latency }
    }

    /// Checks if the node is healthy.
    pub fn is_healthy(&self) -> bool {
        self.latency.is_some()
    }

    /// Get the latency of the health check.
    pub fn latency(&self) -> Option<Duration> {
        self.latency
    }
}

/// A struct implementing the `HealthCheck` for the nodes.
#[derive(Debug)]
pub struct HealthChecker {
    http_client: Client,
    timeout: Duration,
}

impl HealthChecker {
    /// Creates a new `HealthChecker` instance.
    pub fn new(http_client: Client, timeout: Duration) -> Self {
        Self {
            http_client,
            timeout,
        }
    }
}

const HEALTH_CHECKER: &str = "HealthChecker";

#[async_trait]
impl HealthCheck for HealthChecker {
    async fn check(&self, node: &Node) -> Result<HealthCheckStatus, DynamicRouteProviderError> {
        // API boundary node exposes /health endpoint and should respond with 204 (No Content) if it's healthy.
        let url = Url::parse(&format!("https://{}/health", node.domain())).unwrap();

        let mut request = Request::new(Method::GET, url.clone());
        *request.timeout_mut() = Some(self.timeout);

        let start = Instant::now();
        let response = self.http_client.execute(request).await.map_err(|err| {
            DynamicRouteProviderError::HealthCheckError(format!(
                "Failed to execute GET request to {url}: {err}"
            ))
        })?;
        let latency = start.elapsed();

        if response.status() != StatusCode::NO_CONTENT {
            let err_msg = format!(
                "{HEALTH_CHECKER}: Unexpected http status code {} for url={url} received",
                response.status()
            );
            error!(err_msg);
            return Err(DynamicRouteProviderError::HealthCheckError(err_msg));
        }

        Ok(HealthCheckStatus::new(Some(latency)))
    }
}

const HEALTH_CHECK_ACTOR: &str = "HealthCheckActor";

/// A struct performing the health check of the node and sending the health status to the listener.
struct HealthCheckActor {
    /// The health checker.
    checker: Arc<dyn HealthCheck>,
    /// The period of the health check.
    period: Duration,
    /// The node to check.
    node: Node,
    /// The sender channel (listener) to send the health status.
    sender_channel: SenderMpsc<NodeHealthState>,
    /// The cancellation token of the actor.
    token: StopToken,
}

impl HealthCheckActor {
    fn new(
        checker: Arc<dyn HealthCheck>,
        period: Duration,
        node: Node,
        sender_channel: SenderMpsc<NodeHealthState>,
        token: StopToken,
    ) -> Self {
        Self {
            checker,
            period,
            node,
            sender_channel,
            token,
        }
    }

    /// Runs the actor.
    async fn run(self) {
        loop {
            futures_util::select! {
                _ = crate::util::sleep(self.period).fuse() => {
                    let health = self.checker.check(&self.node).await.unwrap_or_default();
                    let message = NodeHealthState {
                        node: self.node.clone(),
                        health,
                    };
                    // Inform the listener about node's health. It can only fail if the listener was closed/dropped.
                    self.sender_channel.send(message).await.expect("Failed to send node's health state");
                }
                _ = self.token.clone().fuse() => {
                    info!("{HEALTH_CHECK_ACTOR}: was gracefully cancelled for node {:?}", self.node);
                    break;
                }
            }
        }
    }
}

/// The name of the health manager actor.
pub(super) const HEALTH_MANAGER_ACTOR: &str = "HealthManagerActor";

/// A struct managing the health checks of the nodes.
/// It receives the fetched nodes from the `NodesFetchActor` and starts the health checks for them.
/// It also receives the health status of the nodes from the `HealthCheckActor/s` and updates the routing snapshot.
pub(super) struct HealthManagerActor<S> {
    /// The health checker.
    checker: Arc<dyn HealthCheck>,
    /// The period of the health check.
    period: Duration,
    /// The routing snapshot, storing the nodes.   
    routing_snapshot: AtomicSwap<S>,
    /// The receiver channel to listen to the fetched nodes messages.
    fetch_receiver: ReceiverWatch<FetchedNodes>,
    /// The sender channel to send the health status of the nodes back to HealthManagerActor.
    check_sender: SenderMpsc<NodeHealthState>,
    /// The receiver channel to receive the health status of the nodes from the `HealthCheckActor/s`.
    check_receiver: ReceiverMpsc<NodeHealthState>,
    /// The sender channel to send the initialization status to DynamicRouteProvider (used only once in the init phase).
    init_sender: SenderMpsc<bool>,
    /// The cancellation token of the actor.
    token: StopToken,
    /// The cancellation source for all the health checks.
    nodes_stop: StopSource,
    /// The flag indicating if this actor is initialized with healthy nodes.
    is_initialized: bool,
}

impl<S> HealthManagerActor<S>
where
    S: RoutingSnapshot,
{
    /// Creates a new `HealthManagerActor` instance.
    pub fn new(
        checker: Arc<dyn HealthCheck>,
        period: Duration,
        routing_snapshot: AtomicSwap<S>,
        fetch_receiver: ReceiverWatch<FetchedNodes>,
        init_sender: SenderMpsc<bool>,
        token: StopToken,
    ) -> Self {
        let (check_sender, check_receiver) = async_channel::bounded(CHANNEL_BUFFER);

        Self {
            checker,
            period,
            routing_snapshot,
            fetch_receiver,
            check_sender,
            check_receiver,
            init_sender,
            token,
            nodes_stop: StopSource::new(),
            is_initialized: false,
        }
    }

    /// Runs the actor.
    pub async fn run(mut self) {
        loop {
            futures_util::select_biased! {
                _ = self.token.clone().fuse() => {
                    self.check_receiver.close();
                    trace!("{HEALTH_MANAGER_ACTOR}: was gracefully cancelled, all nodes health checks stopped");
                    break;
                }
                // Process a new array of fetched nodes from NodesFetchActor, if it appeared in the channel.
                result = self.fetch_receiver.recv().fuse() => {
                    match result {
                        Err(err) => {
                            error!("{HEALTH_MANAGER_ACTOR}: nodes fetch sender has been dropped: {err:?}");
                            continue; // will hit the stoptoken next
                        }
                        Ok(Some(FetchedNodes { nodes })) => {
                            self.handle_fetch_update(nodes).await;
                        }
                        Ok(None) => continue,
                    }
                }
                // Receive health check messages from all running HealthCheckActor/s.
                msg = self.check_receiver.recv().fuse() => {
                    if let Ok(msg) = msg {
                        self.handle_health_update(msg).await;
                    }
                }
            }
        }
    }

    async fn handle_health_update(&mut self, msg: NodeHealthState) {
        let current_snapshot = self.routing_snapshot.load_full();
        let mut new_snapshot = (*current_snapshot).clone();
        new_snapshot.update_node(&msg.node, msg.health.clone());
        self.routing_snapshot.store(Arc::new(new_snapshot));
        if !self.is_initialized && msg.health.is_healthy() {
            self.is_initialized = true;
            // If TIMEOUT_AWAIT_HEALTHY_SEED has been exceeded, the receiver was dropped and send would thus fail. We ignore the failure.
            let _ = self.init_sender.send(true).await;
        }
    }

    async fn handle_fetch_update(&mut self, nodes: Vec<Node>) {
        if nodes.is_empty() {
            // This is a bug in the IC registry. There should be at least one API Boundary Node in the registry.
            // Updating nodes snapshot with an empty array, would lead to an irrecoverable error, as new nodes couldn't be fetched.
            // We avoid such updates and just wait for a non-empty list.
            error!("{HEALTH_MANAGER_ACTOR}: list of fetched nodes is empty");
            return;
        }
        debug!("{HEALTH_MANAGER_ACTOR}: fetched nodes received {:?}", nodes);
        let current_snapshot = self.routing_snapshot.load_full();
        let mut new_snapshot = (*current_snapshot).clone();
        // If the snapshot has changed, store it and restart all node's health checks.
        if new_snapshot.sync_nodes(&nodes) {
            self.routing_snapshot.store(Arc::new(new_snapshot));
            warn!("{HEALTH_MANAGER_ACTOR}: stopping all running health checks");
            self.reset_checks(nodes.to_vec());
        }
    }

    fn reset_checks(&mut self, nodes: Vec<Node>) {
        // Create a cancellation source for all started health checks.
        self.nodes_stop = StopSource::new();
        for node in nodes {
            debug!("{HEALTH_MANAGER_ACTOR}: starting health check for node {node:?}");
            let actor = HealthCheckActor::new(
                Arc::clone(&self.checker),
                self.period,
                node,
                self.check_sender.clone(),
                self.nodes_stop.token(),
            );
            crate::util::spawn(async move { actor.run().await });
        }
    }
}
