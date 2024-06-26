use anyhow::bail;
use async_trait::async_trait;
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use std::{
    fmt::Debug,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, time};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, error, info, warn};
use url::Url;

use crate::agent::http_transport::dynamic_routing::{
    messages::{FetchedNodes, NodeHealthState},
    node::Node,
    snapshot::routing_snapshot::RoutingSnapshot,
    type_aliases::{GlobalShared, ReceiverMpsc, ReceiverWatch, SenderMpsc},
};

const CHANNEL_BUFFER: usize = 128;

///
#[async_trait]
pub trait HealthCheck: Send + Sync + Debug {
    ///
    async fn check(&self, node: &Node) -> anyhow::Result<HealthCheckStatus>;
}

///
#[derive(Clone, PartialEq, Debug, Default)]
pub struct HealthCheckStatus {
    ///
    pub latency: Option<Duration>,
}

///
impl HealthCheckStatus {
    ///
    pub fn new(latency: Option<Duration>) -> Self {
        Self { latency }
    }

    ///
    pub fn is_healthy(&self) -> bool {
        self.latency.is_some()
    }
}

///
#[derive(Debug)]
pub struct HealthChecker {
    http_client: Client,
    timeout: Duration,
}

///
impl HealthChecker {
    ///
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
    async fn check(&self, node: &Node) -> anyhow::Result<HealthCheckStatus> {
        // API boundary node exposes /health endpoint and should respond with 204 (No Content) if it's healthy.
        let url = Url::parse(&format!("https://{}/health", node.domain()))?;

        let mut request = Request::new(Method::GET, url.clone());
        *request.timeout_mut() = Some(self.timeout);

        let start = Instant::now();
        let response = self.http_client.execute(request).await?;
        let latency = start.elapsed();

        if response.status() != StatusCode::NO_CONTENT {
            let err_msg = format!(
                "{HEALTH_CHECKER}: Unexpected http status code {} for url={url} received",
                response.status()
            );
            error!(err_msg);
            bail!(err_msg);
        }

        Ok(HealthCheckStatus::new(Some(latency)))
    }
}

const HEALTH_CHECK_ACTOR: &str = "HealthCheckActor";

struct HealthCheckActor {
    checker: Arc<dyn HealthCheck>,
    period: Duration,
    node: Node,
    sender_channel: SenderMpsc<NodeHealthState>,
    token: CancellationToken,
}

impl HealthCheckActor {
    pub fn new(
        checker: Arc<dyn HealthCheck>,
        period: Duration,
        node: Node,
        sender_channel: SenderMpsc<NodeHealthState>,
        token: CancellationToken,
    ) -> Self {
        Self {
            checker,
            period,
            node,
            sender_channel,
            token,
        }
    }

    pub async fn run(self) {
        let mut interval = time::interval(self.period);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let health = self.checker.check(&self.node).await.unwrap_or_default();
                    let message = NodeHealthState {
                        node: self.node.clone(),
                        health,
                    };
                    // Inform the listener about node's health. It can only fail if the listener was closed/dropped.
                    self.sender_channel.send(message).await.expect("Failed to send node's health state");
                }
                _ = self.token.cancelled() => {
                    info!("{HEALTH_CHECK_ACTOR}: was gracefully cancelled for node {:?}", self.node);
                    break;
                }
            }
        }
    }
}

///
pub const HEALTH_MANAGER_ACTOR: &str = "HealthManagerActor";

///
pub struct HealthManagerActor<S> {
    checker: Arc<dyn HealthCheck>,
    period: Duration,
    nodes_snapshot: GlobalShared<S>,
    fetch_receiver: ReceiverWatch<FetchedNodes>,
    check_sender: SenderMpsc<NodeHealthState>,
    check_receiver: ReceiverMpsc<NodeHealthState>,
    init_sender: SenderMpsc<bool>,
    token: CancellationToken,
    nodes_token: CancellationToken,
    nodes_tracker: TaskTracker,
    is_initialized: bool,
}

impl<S> HealthManagerActor<S>
where
    S: RoutingSnapshot,
{
    ///
    pub fn new(
        checker: Arc<dyn HealthCheck>,
        period: Duration,
        nodes_snapshot: GlobalShared<S>,
        fetch_receiver: ReceiverWatch<FetchedNodes>,
        init_sender: SenderMpsc<bool>,
        token: CancellationToken,
    ) -> Self {
        let (check_sender, check_receiver) = mpsc::channel(CHANNEL_BUFFER);

        Self {
            checker,
            period,
            nodes_snapshot,
            fetch_receiver,
            check_sender,
            check_receiver,
            init_sender,
            token,
            nodes_token: CancellationToken::new(),
            nodes_tracker: TaskTracker::new(),
            is_initialized: false,
        }
    }

    ///
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                // Check if a new array of fetched nodes appeared in the channel from NodesFetchService.
                result = self.fetch_receiver.changed() => {
                    if let Err(err) = result {
                        error!("{HEALTH_MANAGER_ACTOR}: nodes fetch sender has been dropped: {err:?}");
                        self.token.cancel();
                        continue;
                    }
                    // Get the latest value from the channel and mark it as seen.
                    let Some(FetchedNodes { nodes }) = self.fetch_receiver.borrow_and_update().clone() else { continue };
                    self.handle_fetch_update(nodes).await;
                }
                // Receive health check messages from all running NodeHealthChecker/s.
                Some(msg) = self.check_receiver.recv() => {
                    self.handle_health_update(msg).await;
                }
                _ = self.token.cancelled() => {
                    self.stop_all_checks().await;
                    self.check_receiver.close();
                    warn!("{HEALTH_MANAGER_ACTOR}: was gracefully cancelled, all nodes health checks stopped");
                    break;
                }
            }
        }
    }

    async fn handle_health_update(&mut self, msg: NodeHealthState) {
        let current_snapshot = self.nodes_snapshot.load_full();
        let mut new_snapshot = (*current_snapshot).clone();
        if let Err(err) = new_snapshot.update_node(&msg.node, msg.health.clone()) {
            error!("{HEALTH_MANAGER_ACTOR}: failed to update snapshot: {err:?}");
            return;
        }
        self.nodes_snapshot.store(Arc::new(new_snapshot));
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
        let current_snapshot = self.nodes_snapshot.load_full();
        let mut new_snapshot = (*current_snapshot).clone();
        // If the snapshot has changed, store it and restart all node's health checks.
        if let Ok(true) = new_snapshot.sync_nodes(&nodes) {
            self.nodes_snapshot.store(Arc::new(new_snapshot));
            self.stop_all_checks().await;
            self.start_checks(nodes.to_vec());
        }
    }

    fn start_checks(&mut self, nodes: Vec<Node>) {
        // Create a single cancellation token for all started health checks.
        self.nodes_token = CancellationToken::new();
        for node in nodes {
            debug!("{HEALTH_MANAGER_ACTOR}: starting health check for node {node:?}");
            let actor = HealthCheckActor::new(
                Arc::clone(&self.checker),
                self.period,
                node,
                self.check_sender.clone(),
                self.nodes_token.clone(),
            );
            self.nodes_tracker.spawn(async move { actor.run().await });
        }
    }

    async fn stop_all_checks(&self) {
        warn!("{HEALTH_MANAGER_ACTOR}: stopping all running health checks");
        self.nodes_token.cancel();
        self.nodes_tracker.close();
        self.nodes_tracker.wait().await;
    }
}
