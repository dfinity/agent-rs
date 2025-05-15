use async_trait::async_trait;
use futures_util::FutureExt;
use ic_principal::Principal;
use std::{fmt::Debug, sync::Arc, time::Duration};
use stop_token::StopToken;
use url::Url;

#[allow(unused)]
use crate::agent::route_provider::dynamic_routing::health_check::HEALTH_MANAGER_ACTOR;
use crate::agent::{
    route_provider::dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderError,
        messages::FetchedNodes,
        node::Node,
        snapshot::routing_snapshot::RoutingSnapshot,
        type_aliases::{AtomicSwap, SenderWatch},
    },
    Agent, HttpService,
};
#[allow(unused)]
const NODES_FETCH_ACTOR: &str = "NodesFetchActor";

/// Fetcher of nodes in the topology.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait Fetch: Sync + Send + Debug {
    /// Fetches the nodes from the topology.
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, DynamicRouteProviderError>;
}

/// A struct representing the fetcher of the nodes from the topology.
#[derive(Debug)]
pub struct NodesFetcher {
    http_client: Arc<dyn HttpService>,
    subnet_id: Principal,
    // By default, the nodes fetcher is configured to talk to the mainnet of Internet Computer, and verifies responses using a hard-coded public key.
    // However, for testnets one can set up a custom public key.
    root_key: Option<Vec<u8>>,
}

impl NodesFetcher {
    /// Creates a new `NodesFetcher` instance.
    pub fn new(
        http_client: Arc<dyn HttpService>,
        subnet_id: Principal,
        root_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            http_client,
            subnet_id,
            root_key,
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl Fetch for NodesFetcher {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, DynamicRouteProviderError> {
        let agent = Agent::builder()
            .with_url(url)
            .with_arc_http_middleware(self.http_client.clone())
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
            .into_iter()
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
    token: StopToken,
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
        token: StopToken,
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
        loop {
            // Retry until success:
            // - try to get a healthy node from the routing snapshot
            //   - if snapshot is empty, break the cycle and wait for the next fetch cycle
            // - using the healthy node, try to fetch nodes from topology
            //   - if failure, sleep and retry
            // - try send fetched nodes to the listener
            //   - failure should never happen, but we trace it if it does
            loop {
                let snapshot = self.routing_snapshot.load();
                if let Some(node) = snapshot.next_node() {
                    match self.fetcher.fetch((&node).into()).await {
                        Ok(nodes) => {
                            let msg = Some(FetchedNodes { nodes });
                            match self.fetch_sender.send(msg) {
                                Ok(()) => break, // message sent successfully, exist the loop
                                Err(_err) => {
                                    log!(error, "{NODES_FETCH_ACTOR}: failed to send results to {HEALTH_MANAGER_ACTOR}: {_err:?}");
                                }
                            }
                        }
                        Err(_err) => {
                            log!(
                                error,
                                "{NODES_FETCH_ACTOR}: failed to fetch nodes: {_err:?}"
                            );
                        }
                    };
                } else {
                    // No healthy nodes in the snapshot, break the cycle and wait for the next fetch cycle
                    log!(error, "{NODES_FETCH_ACTOR}: no nodes in the snapshot");
                    break;
                };
                log!(
                    warn,
                    "Retrying to fetch the nodes in {:?}",
                    self.fetch_retry_interval
                );
                crate::util::sleep(self.fetch_retry_interval).await;
            }
            futures_util::select! {
                _ = crate::util::sleep(self.period).fuse() => {
                    continue;
                }
                _ = self.token.clone().fuse() => {
                    log!(warn, "{NODES_FETCH_ACTOR}: was gracefully cancelled");
                    break;
                }
            }
        }
    }
}
