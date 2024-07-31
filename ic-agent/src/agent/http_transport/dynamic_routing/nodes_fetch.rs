use async_trait::async_trait;
use candid::Principal;
use reqwest::Client;
use std::{fmt::Debug, sync::Arc, time::Duration};
use tokio::time::{self, sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};
use url::Url;

use crate::agent::{
    http_transport::{
        dynamic_routing::{
            dynamic_route_provider::DynamicRouteProviderError,
            health_check::HEALTH_MANAGER_ACTOR,
            messages::FetchedNodes,
            node::Node,
            snapshot::routing_snapshot::RoutingSnapshot,
            type_aliases::{AtomicSwap, SenderWatch},
        },
        reqwest_transport::ReqwestTransport,
    },
    Agent,
};

const NODES_FETCH_ACTOR: &str = "NodesFetchActor";

/// Fetcher of nodes in the topology.
#[async_trait]
pub trait Fetch: Sync + Send + Debug {
    /// Fetches the nodes from the topology.
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, DynamicRouteProviderError>;
}

/// A struct representing the fetcher of the nodes from the topology.
#[derive(Debug)]
pub struct NodesFetcher {
    http_client: Client,
    subnet_id: Principal,
    // By default, the nodes fetcher is configured to talk to the mainnet of Internet Computer, and verifies responses using a hard-coded public key.
    // However, for testnets one can set up a custom public key.
    root_key: Option<Vec<u8>>,
}

impl NodesFetcher {
    /// Creates a new `NodesFetcher` instance.
    pub fn new(http_client: Client, subnet_id: Principal, root_key: Option<Vec<u8>>) -> Self {
        Self {
            http_client,
            subnet_id,
            root_key,
        }
    }
}

#[async_trait]
impl Fetch for NodesFetcher {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, DynamicRouteProviderError> {
        let transport = ReqwestTransport::create_with_client(url, self.http_client.clone())
            .map_err(|err| {
                DynamicRouteProviderError::NodesFetchError(format!(
                    "Failed to build transport: {err}"
                ))
            })?;
        let agent = Agent::builder()
            .with_transport(transport)
            .build()
            .map_err(|err| {
                DynamicRouteProviderError::NodesFetchError(format!(
                    "Failed to build the agent: {err}"
                ))
            })?;
        if let Some(key) = self.root_key.clone() {
            agent.set_root_key(key);
        }
        let api_bns = agent
            .fetch_api_boundary_nodes_by_subnet_id(self.subnet_id)
            .await
            .map_err(|err| {
                DynamicRouteProviderError::NodesFetchError(format!(
                    "Failed to fetch API nodes: {err}"
                ))
            })?;
        // If some API BNs have invalid domain names, they are discarded.
        let nodes = api_bns
            .iter()
            .filter_map(|api_node| api_node.try_into().ok())
            .collect();
        return Ok(nodes);
    }
}

/// A struct representing the actor responsible for fetching existing nodes and communicating it with the listener.
pub(super) struct NodesFetchActor<S> {
    /// The fetcher object responsible for fetching the nodes.
    fetcher: Arc<dyn Fetch>,
    /// Time period between fetches.
    period: Duration,
    /// The interval to wait before retrying to fetch the nodes in case of failures.
    fetch_retry_interval: Duration,
    /// Communication channel with the listener.
    fetch_sender: SenderWatch<FetchedNodes>,
    /// The snapshot of the routing table.
    routing_snapshot: AtomicSwap<S>,
    /// The token to cancel/stop the actor.
    token: CancellationToken,
}

impl<S> NodesFetchActor<S>
where
    S: RoutingSnapshot,
{
    /// Creates a new `NodesFetchActor` instance.
    pub fn new(
        fetcher: Arc<dyn Fetch>,
        period: Duration,
        retry_interval: Duration,
        fetch_sender: SenderWatch<FetchedNodes>,
        snapshot: AtomicSwap<S>,
        token: CancellationToken,
    ) -> Self {
        Self {
            fetcher,
            period,
            fetch_retry_interval: retry_interval,
            fetch_sender,
            routing_snapshot: snapshot,
            token,
        }
    }

    /// Runs the actor.
    pub async fn run(self) {
        let mut interval = time::interval(self.period);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                        // Retry until success:
                        // - try to get a healthy node from the routing snapshot
                        //   - if snapshot is empty, break the cycle and wait for the next fetch cycle
                        // - using the healthy node, try to fetch nodes from topology
                        //   - if failure, sleep and retry
                        // - try send fetched nodes to the listener
                        //   - failure should never happen, but we trace it if it does
                        loop {
                            let snapshot = self.routing_snapshot.load();
                            if let Some(node) = snapshot.next() {
                                match self.fetcher.fetch((&node).into()).await {
                                    Ok(nodes) => {
                                        let msg = Some(
                                            FetchedNodes {nodes});
                                        match self.fetch_sender.send(msg) {
                                            Ok(()) => break, // message sent successfully, exist the loop
                                            Err(err) => {
                                                error!("{NODES_FETCH_ACTOR}: failed to send results to {HEALTH_MANAGER_ACTOR}: {err:?}");
                                            }
                                        }
                                    },
                                    Err(err) => {
                                        error!("{NODES_FETCH_ACTOR}: failed to fetch nodes: {err:?}");
                                    }
                                };
                            } else {
                                // No healthy nodes in the snapshot, break the cycle and wait for the next fetch cycle
                                error!("{NODES_FETCH_ACTOR}: no nodes in the snapshot");
                                break;
                            };
                            warn!("Retrying to fetch the nodes in {:?}", self.fetch_retry_interval);
                            sleep(self.fetch_retry_interval).await;
                        }
                }
                _ = self.token.cancelled() => {
                    warn!("{NODES_FETCH_ACTOR}: was gracefully cancelled");
                    break;
                }
            }
        }
    }
}
