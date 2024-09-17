use candid::Principal;
use futures_util::FutureExt;
use std::time::Duration;
use stop_token::StopToken;
use tracing::{error, warn};
use url::Url;

use crate::{
    agent::{
        route_provider::dynamic_routing::{
            health_check::HEALTH_MANAGER_ACTOR,
            messages::FetchedNodes,
            node::Node,
            snapshot::routing_snapshot::RoutingSnapshot,
            type_aliases::{AtomicSwap, SenderWatch},
        },
        Agent,
    },
    AgentError,
};

const NODES_FETCH_ACTOR: &str = "NodesFetchActor";

async fn fetch_subnet_nodes(
    agent: &Agent,
    subnet_id: Principal,
    url: Url,
) -> Result<Vec<Node>, AgentError> {
    let agent = agent.clone_with_url(url);
    let api_bns = agent
        .fetch_api_boundary_nodes_by_subnet_id(subnet_id)
        .await?;
    // If some API BNs have invalid domain names, they are discarded.
    let nodes = api_bns
        .iter()
        .filter_map(|api_node| api_node.try_into().ok())
        .collect();
    Ok(nodes)
}

pub(crate) async fn nodes_fetch_actor<S: RoutingSnapshot>(
    agent: Agent,
    subnet_id: Principal,
    period: Duration,
    retry_interval: Duration,
    fetch_sender: SenderWatch<FetchedNodes>,
    snapshot: AtomicSwap<S>,
    token: StopToken,
) {
    loop {
        futures_util::select! {
            _ = crate::util::sleep(period).fuse() => {
                    // Retry until success:
                    // - try to get a healthy node from the routing snapshot
                    //   - if snapshot is empty, break the cycle and wait for the next fetch cycle
                    // - using the healthy node, try to fetch nodes from topology
                    //   - if failure, sleep and retry
                    // - try send fetched nodes to the listener
                    //   - failure should never happen, but we trace it if it does
                    loop {
                        let snapshot = snapshot.load();
                        if let Some(node) = snapshot.next_node() {
                            match fetch_subnet_nodes(&agent, subnet_id, (&node).into()).await {
                                Ok(nodes) => {
                                    let msg = Some(FetchedNodes {nodes});
                                    match fetch_sender.send(msg) {
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
                        warn!("Retrying to fetch the nodes in {:?}", retry_interval);
                        crate::util::sleep(retry_interval).await;
                    }
            }
            _ = token.clone().fuse() => {
                warn!("{NODES_FETCH_ACTOR}: was gracefully cancelled");
                break;
            }
        }
    }
}
