use std::{collections::BTreeMap, sync::Arc, time::Duration};

use ic_agent::agent::route_provider::{
    dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderBuilder, node::Node,
        snapshot::latency_based_routing::LatencyRoutingSnapshot,
    },
    RouteProvider,
};
use reqwest::Client;
use tokio::time::sleep;

// Demo 4: Dynamic latency-based routing via API boundary nodes
// $ cargo run --bin demo_4_dynamic_routing --features _internal_dynamic-routing

#[tokio::main]
async fn main() {
    // Dynamic weighted round-robin routing based on the latency of the API boundary nodes
    let routing_strategy = LatencyRoutingSnapshot::new(); // RoundRobinRoutingSnapshot

    let seed_api_node = vec![Node::new("zh3-dll02.tenderloin.ch").unwrap()];

    let client = Client::builder()
        .build()
        .expect("failed to build http client");

    let route_provider =
        DynamicRouteProviderBuilder::new(routing_strategy, seed_api_node, Arc::new(client))
            .with_check_period(Duration::from_secs(2))
            // .with_checker(custom_checker) // provide custom API nodes health checker
            // .with_fetcher(custom_fetcher) // provide custom API nodes discovery implementation
            .build()
            .await;

    // let _agent = Agent::builder()
    //     .with_arc_route_provider(route_provider)  // agent calls route_provider.route()
    //     .build()
    //     .expect("failed to build ic-agent");

    let mut urls_statistics = BTreeMap::new();

    // Wait a bit to assemble statistics over API nodes latencies
    sleep(Duration::from_secs(3)).await;

    for _ in 0..2000 {
        let url = route_provider
            .route()
            .expect("failed to get a routing url")
            .to_string();

        urls_statistics
            .entry(url)
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
    }

    let mut count_sorted: Vec<_> = urls_statistics.into_iter().collect();
    count_sorted.sort_by(|a, b| b.1.cmp(&a.1));

    println!("{:<50} | {:<10}", format!("URLs (total {})", count_sorted.len()), "Count");
    println!("{:-<50}-+-{:-<10}", "", "");

    for (url, count) in &count_sorted {
        println!("{:<50} | {:<10}", url, count);
    }
}
