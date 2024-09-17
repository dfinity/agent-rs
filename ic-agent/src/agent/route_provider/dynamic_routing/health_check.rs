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
    type_aliases::{AtomicSwap, ReceiverWatch, SenderMpsc},
};

const CHANNEL_BUFFER: usize = 128;

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

const HEALTH_CHECKER: &str = "HealthChecker";

pub(crate) async fn health_check(
    client: &Client,
    check_timeout: Duration,
    node: &Node,
) -> Result<HealthCheckStatus, DynamicRouteProviderError> {
    // API boundary node exposes /health endpoint and should respond with 204 (No Content) if it's healthy.
    let url = Url::parse(&format!("https://{}/health", node.domain())).unwrap();

    let mut request = Request::new(Method::GET, url.clone());
    *request.timeout_mut() = Some(check_timeout);

    let start = Instant::now();
    let response = client.execute(request).await.map_err(|err| {
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

const HEALTH_CHECK_ACTOR: &str = "HealthCheckActor";

/// The name of the health manager actor.
pub(super) const HEALTH_MANAGER_ACTOR: &str = "HealthManagerActor";

pub(crate) async fn health_check_actor(
    client: Client,
    period: Duration,
    timeout: Duration,
    node: Node,
    sender_channel: SenderMpsc<NodeHealthState>,
    token: StopToken,
) {
    loop {
        futures_util::select! {
            _ = crate::util::sleep(period).fuse() => {
                let health = health_check(&client, timeout, &node).await.unwrap_or_default();
                let message = NodeHealthState {
                    node: node.clone(),
                    health,
                };
                // Inform the listener about node's health. It can only fail if the listener was closed/dropped.
                sender_channel.send(message).await.expect("Failed to send node's health state");
            }
            _ = token.clone().fuse() => {
                info!("{HEALTH_CHECK_ACTOR}: was gracefully cancelled for node {node:?}");
                break;
            }
        }
    }
}

pub(crate) async fn health_check_manager_actor<S: RoutingSnapshot>(
    client: Client,
    period: Duration,
    timeout: Duration,
    routing_snapshot: AtomicSwap<S>,
    mut fetch_receiver: ReceiverWatch<FetchedNodes>,
    init_sender: SenderMpsc<bool>,
    token: StopToken,
) {
    let (check_sender, check_receiver) = async_channel::bounded(CHANNEL_BUFFER);
    let mut is_initialized = false;
    let mut nodes_stop: StopSource;
    loop {
        futures_util::select_biased! {
            _ = token.clone().fuse() => {
                check_receiver.close();
                trace!("{HEALTH_MANAGER_ACTOR}: was gracefully cancelled, all nodes health checks stopped");
                break;
            }
            // Process a new array of fetched nodes from NodesFetchActor, if it appeared in the channel.
            result = fetch_receiver.recv().fuse() => {
                match result {
                    Err(err) => {
                        error!("{HEALTH_MANAGER_ACTOR}: nodes fetch sender has been dropped: {err:?}");
                        continue; // will hit the stoptoken next
                    }
                    Ok(Some(FetchedNodes { nodes })) => {
                        if nodes.is_empty() {
                            // This is a bug in the IC registry. There should be at least one API Boundary Node in the registry.
                            // Updating nodes snapshot with an empty array, would lead to an irrecoverable error, as new nodes couldn't be fetched.
                            // We avoid such updates and just wait for a non-empty list.
                            error!("{HEALTH_MANAGER_ACTOR}: list of fetched nodes is empty");
                            return;
                        }
                        debug!("{HEALTH_MANAGER_ACTOR}: fetched nodes received {:?}", nodes);
                        let current_snapshot = routing_snapshot.load_full();
                        let mut new_snapshot = (*current_snapshot).clone();
                        // If the snapshot has changed, store it and restart all node's health checks.
                        if new_snapshot.sync_nodes(&nodes) {
                            routing_snapshot.store(Arc::new(new_snapshot));
                            warn!("{HEALTH_MANAGER_ACTOR}: stopping all running health checks");
                            nodes_stop = StopSource::new();
                            for node in &nodes {
                                debug!("{HEALTH_MANAGER_ACTOR}: starting health check for node {node:?}");
                                crate::util::spawn(health_check_actor(
                                    client.clone(),
                                    period,
                                    timeout,
                                    node.clone(),
                                    check_sender.clone(),
                                    nodes_stop.token(),
                                ));
                            }
                        }
                    }
                    Ok(None) => continue,
                }
            }
            // Receive health check messages from all running HealthCheckActor/s.
            msg = check_receiver.recv().fuse() => {
                if let Ok(msg) = msg {
                    let current_snapshot = routing_snapshot.load_full();
                    let mut new_snapshot = (*current_snapshot).clone();
                    new_snapshot.update_node(&msg.node, msg.health.clone());
                    routing_snapshot.store(Arc::new(new_snapshot));
                    if !is_initialized && msg.health.is_healthy() {
                        is_initialized = true;
                        // If TIMEOUT_AWAIT_HEALTHY_SEED has been exceeded, the receiver was dropped and send would thus fail. We ignore the failure.
                        let _ = init_sender.send(true).await;
                    }
                }
            }
        }
    }
}
