use candid::Principal;
use ic_agent::Agent;
use url::Url;

const ROOT_SUBNET_ID: &str = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

// Demo 2: Discover API nodes via one of the decentralized API boundary nodes
// $ cargo run --bin demo_2_fetch_nodes_via_api

#[tokio::main]
async fn main() {
    // Use API boundary node with domain zh3-dll02.tenderloin.ch
    let url = Url::parse("https://zh3-dll02.tenderloin.ch").expect("failed to parse url");

    let agent = Agent::builder()
        .with_url(url)
        .build()
        .expect("failed to build ic-agent");

    let subnet_id = Principal::from_text(ROOT_SUBNET_ID).expect("failed to parse principal");

    let api_nodes = agent
        .fetch_api_boundary_nodes_by_subnet_id(subnet_id) // https://ic0.app/api/v2/subnet/subnet_id/read_state
        .await
        .expect("failed to fetch nodes");

    println!("{} API nodes found: {api_nodes:#?}", api_nodes.len());
}
