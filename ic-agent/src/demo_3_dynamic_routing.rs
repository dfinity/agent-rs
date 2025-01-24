use std::time::Duration;

use candid::Principal;
use ic_agent::Agent;
use tokio::time::sleep;
use url::Url;

const ROOT_SUBNET_ID: &str = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

// Demo 3: Dynamic routing via API boundary nodes (high-level interface)
// $ cargo run --bin demo_3_dynamic_routing

#[tokio::main]
async fn main() {
    let seed_api_node = Url::parse("https://zh3-dll02.tenderloin.ch").expect("failed to parse url");

    let agent = Agent::builder()
        .with_url(seed_api_node)
        .with_background_dynamic_routing()
        .await
        .build()
        .expect("failed to build ic-agent");

    let subnet_id = Principal::from_text(ROOT_SUBNET_ID).expect("failed to parse principal");

    for _ in 0..100 {
        let _api_nodes = agent
            .fetch_api_boundary_nodes_by_subnet_id(subnet_id)
            .await
            .expect("failed to fetch nodes");

        sleep(Duration::from_millis(30)).await;
    }
}
