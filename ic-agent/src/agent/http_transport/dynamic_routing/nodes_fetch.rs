use anyhow::Context;
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
            health_check::HEALTH_MANAGER_ACTOR, messages::FetchedNodes, node::Node,
            snapshot::routing_snapshot::RoutingSnapshot, type_aliases::GlobalShared,
            type_aliases::SenderWatch,
        },
        reqwest_transport::ReqwestTransport,
    },
    Agent,
};

const NODES_FETCH_ACTOR: &str = "NodesFetchActor";

#[async_trait]
pub trait Fetch: Sync + Send + Debug {
    async fn fetch(&self, url: Url) -> anyhow::Result<Vec<Node>>;
}

#[derive(Debug)]
pub struct NodesFetcher {
    http_client: Client,
    subnet_id: Principal,
}

impl NodesFetcher {
    pub fn new(http_client: Client, subnet_id: Principal) -> Self {
        Self {
            http_client,
            subnet_id,
        }
    }
}

#[async_trait]
impl Fetch for NodesFetcher {
    async fn fetch(&self, url: Url) -> anyhow::Result<Vec<Node>> {
        let transport = ReqwestTransport::create_with_client(url, self.http_client.clone())
            .with_context(|| "Failed to build transport: {err}")?;
        let agent = Agent::builder()
            .with_transport(transport)
            .build()
            .with_context(|| "Failed to build an agent: {err}")?;
        agent
            .fetch_root_key()
            .await
            .with_context(|| "Failed to fetch root key: {err}")?;
        let api_bns = agent
            .fetch_api_boundary_nodes_by_subnet_id(self.subnet_id)
            .await?;
        let nodes: Vec<Node> = api_bns.iter().map(|node| node.into()).collect();
        return Ok(nodes);
    }
}

pub struct NodesFetchActor<S> {
    fetcher: Arc<dyn Fetch>,
    period: Duration,
    fetch_retry_interval: Duration,
    fetch_sender: SenderWatch<FetchedNodes>,
    snapshot: GlobalShared<S>,
    token: CancellationToken,
}

impl<S> NodesFetchActor<S>
where
    S: RoutingSnapshot,
{
    pub fn new(
        fetcher: Arc<dyn Fetch>,
        period: Duration,
        retry_interval: Duration,
        fetch_sender: SenderWatch<FetchedNodes>,
        snapshot: GlobalShared<S>,
        token: CancellationToken,
    ) -> Self {
        Self {
            fetcher,
            period,
            fetch_retry_interval: retry_interval,
            fetch_sender,
            snapshot,
            token,
        }
    }

    pub async fn run(self) {
        let mut interval = time::interval(self.period);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                        // Retry until success:
                        // - try to get a healthy node from the snapshot
                        //   - if snapshot is empty, break the cycle and wait for the next fetch cycle
                        // - using the healthy node, try to fetch new nodes from topology
                        //   - if failure, sleep and retry
                        // - try send fetched nodes to the listener
                        //   - failure should never happen
                        loop {
                            let snapshot = self.snapshot.load();
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
