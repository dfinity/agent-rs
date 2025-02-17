use ic_agent::agent::route_provider::{
    dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderBuilder, node::Node,
        snapshot::latency_based_routing::LatencyRoutingSnapshot,
    },
    RouteProvider,
};
use reqwest::Client;
use std::{
    collections::BTreeMap,
    env,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let calls = args[1].parse::<u32>().unwrap();
    let pre_start_wait_secs = args[2].parse::<u64>().unwrap();
    let sleep_between_calls_ms = args[3].parse::<u64>().unwrap();
    let k_top_nodes = args[4].parse::<u32>().unwrap() as usize;
    let with_output = args[5].parse::<u32>().unwrap() == 1;

    let mut routing_strategy = LatencyRoutingSnapshot::new();
    
    if k_top_nodes > 0 {
        println!("routing to {} top nodes", k_top_nodes);
        routing_strategy = routing_strategy.set_k_top_nodes(k_top_nodes);
    }

    let seed_api_node = vec![Node::new("zh3-dll02.tenderloin.ch").unwrap()];

    let client = Client::builder()
        .build()
        .expect("failed to build http client");

    let route_provider =
        DynamicRouteProviderBuilder::new(routing_strategy, seed_api_node, Arc::new(client))
            .build()
            .await;

    let client = Client::builder().build().unwrap();

    let mut urls_statistics: BTreeMap<String, (u32, Duration)> = BTreeMap::new();
    let mut total_latency = Duration::ZERO;

    println!(
        "Wait for {} seconds to assemble nodes latency statistics",
        pre_start_wait_secs
    );
    sleep(Duration::from_secs(pre_start_wait_secs)).await;

    for _ in 0..calls {
        let url = route_provider
            .route()
            .expect("failed to get a routing url")
            .to_string();

        let url_status = format!("{url}api/v2/status");

        let instant = Instant::now();

        match client.get(url_status).send().await {
            Ok(resp) => {
                if with_output {
                    println!("request succeeded {:?}", resp.status());
                }
            }
            Err(err) => {
                if with_output {
                    println!("request failed {err:?}");
                }
            }
        };
        let elapsed = instant.elapsed();

        urls_statistics
            .entry(url)
            .and_modify(|(counter, latency)| {
                *counter += 1;
                *latency += elapsed;
            })
            .or_insert((1, elapsed));

        total_latency += instant.elapsed();

        sleep(Duration::from_millis(sleep_between_calls_ms)).await;
    }

    let mut count_sorted: Vec<_> = urls_statistics.into_iter().collect();
    count_sorted.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));

    println!(
        "average latency {}",
        total_latency.as_millis() as f64 / calls as f64
    );

    println!(
        "{:<50} | {:<10}| {:<10} ",
        format!("URLs (total {})", count_sorted.len()),
        "Count",
        "Latency avg, ms"
    );
    println!("{:-<50}-+-{:-<10}-+-{:-<10}", "", "", "");

    for (url, (count, latency)) in &count_sorted {
        println!(
            "{:<50} | {:<10}| {:<10}",
            url,
            count,
            (latency.as_millis() as f64 / *count as f64) as u32
        );
    }
}
