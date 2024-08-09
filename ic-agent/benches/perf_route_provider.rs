use std::{sync::Arc, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion};
use ic_agent::agent::http_transport::{
    dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderBuilder,
        node::Node,
        snapshot::{
            latency_based_routing::LatencyRoutingSnapshot,
            round_robin_routing::RoundRobinRoutingSnapshot, routing_snapshot::RoutingSnapshot,
        },
        test_utils::{NodeHealthCheckerMock, NodesFetcherMock},
    },
    route_provider::{RoundRobinRouteProvider, RouteProvider},
};
use reqwest::Client;
use tokio::{runtime::Handle, sync::oneshot, time::sleep};

// To run the benchmark use the command:
// $ cargo bench --bench perf_route_provider --features bench

// Benchmarking function
fn benchmark_route_providers(c: &mut Criterion) {
    // For displaying trace messages of the inner running tasks in dynamic route providers, enable the subscriber below

    // use tracing::Level;
    // use tracing_subscriber::FmtSubscriber;
    // FmtSubscriber::builder().with_max_level(Level::TRACE).init();

    // Number of different domains for each route provider
    let nodes_count = 100;

    let mut group = c.benchmark_group("RouteProviders");
    group.sample_size(10000);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create runtime");

    // Setup all route providers
    let route_providers = setup_route_providers(nodes_count, runtime.handle().clone());

    for (name, instance) in route_providers {
        group.bench_function(name, |b| {
            b.iter(|| {
                let _url = instance.route().unwrap();
            })
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_route_providers);
criterion_main!(benches);

fn setup_static_route_provider(nodes_count: usize) -> Arc<dyn RouteProvider> {
    let urls: Vec<_> = (0..nodes_count)
        .map(|idx| format!("https://domain_{idx}.app"))
        .collect();
    Arc::new(RoundRobinRouteProvider::new(urls).unwrap())
}

async fn setup_dynamic_route_provider<S: RoutingSnapshot + 'static>(
    nodes_count: usize,
    snapshot: S,
) -> Arc<dyn RouteProvider> {
    let client = Client::builder().build().expect("failed to build a client");

    let nodes: Vec<_> = (0..nodes_count)
        .map(|idx| Node::new(&format!("https://domain_{idx}.app")).unwrap())
        .collect();

    let fetcher = Arc::new(NodesFetcherMock::new());
    let checker = Arc::new(NodeHealthCheckerMock::new());
    let fetch_interval = Duration::from_secs(1);
    let check_interval = Duration::from_secs(1);

    fetcher.overwrite_nodes(nodes.clone());
    checker.overwrite_healthy_nodes(nodes.clone());

    // Use e.g. a couple of nodes as seeds.
    let seeds = nodes[..2].to_vec();

    let route_provider = DynamicRouteProviderBuilder::new(snapshot, seeds, client.clone())
        .with_fetch_period(fetch_interval)
        .with_fetcher(fetcher)
        .with_check_period(check_interval)
        .with_checker(checker)
        .build()
        .await;

    Arc::new(route_provider)
}

fn setup_route_providers(
    nodes_count: usize,
    runtime: Handle,
) -> Vec<(String, Arc<dyn RouteProvider>)> {
    // Assemble all instances for benching.
    let mut route_providers = vec![];
    // Setup static round-robin route provider
    route_providers.push((
        "Static round-robin RouteProvider".to_string(),
        setup_static_route_provider(nodes_count),
    ));
    // Setup dynamic round-robin route provider
    let (tx, rx) = oneshot::channel();
    runtime.spawn(async move {
        let rp = setup_dynamic_route_provider(nodes_count, RoundRobinRoutingSnapshot::new()).await;
        tx.send(rp).unwrap();
        sleep(Duration::from_secs(100000)).await;
    });
    let route_provider = runtime.block_on(async { rx.await.unwrap() });
    route_providers.push((
        "Dynamic round-robin RouteProvider".to_string(),
        route_provider,
    ));
    // Setup dynamic latency-based route provider
    let (tx, rx) = oneshot::channel();
    runtime.spawn(async move {
        let rp = setup_dynamic_route_provider(nodes_count, LatencyRoutingSnapshot::new()).await;
        tx.send(rp).unwrap();
        sleep(Duration::from_secs(100000)).await;
    });
    let route_provider = runtime.block_on(async { rx.await.unwrap() });
    route_providers.push((
        "Dynamic latency-based RouteProvider".to_string(),
        route_provider,
    ));
    route_providers
}
