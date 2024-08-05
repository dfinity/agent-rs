use std::{env, fs, path::PathBuf};

use candid::Principal;
use ic_agent::Agent;

const OUTPUT_DIR: &str = "OUT_DIR";
// Generated Rust file storing API seed nodes.
const OUTPUT_SEEDS_FILE: &str = "api_seed_nodes.rs";

const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

// An initial seed list of API nodes used for fetching all existing API nodes.
const API_SEED_NODES: [&str; 4] = [
    "ic0.app",
    "br1-dll01.aviatelabs.co",
    "dll02.sg2.icp.162.technology",
    "br1-dll01.aviatelabs.co",
];

async fn try_generate_seeds_file(url: &str) -> Result<(), String> {
    let agent = Agent::builder()
        .with_url(url)
        .build()
        .map_err(|err| format!("Failed to build an agent: {err:?}"))?;

    let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();

    let api_nodes = agent
        .fetch_api_boundary_nodes_by_subnet_id(subnet_id)
        .await
        .map_err(|err| format!("Failed to fetch API nodes via {url}: {err:?}"))?;

    let out_dir = env::var(OUTPUT_DIR).unwrap();
    let dest_path = PathBuf::from(out_dir).join(OUTPUT_SEEDS_FILE);

    // Save all discovered API nodes into a generated file.
    let mut file_content = String::new();
    file_content.push_str("const API_SEED_NODES: &[&str] = &[\n");
    for seed in api_nodes {
        file_content.push_str(&format!("\"{}\",\n", seed.domain));
    }
    file_content.push_str("];\n");

    fs::write(dest_path, file_content)
        .map_err(|err| format!("Failed to write seed_nodes to file: {err:?}"))?;

    Ok(())
}

#[tokio::main]
async fn main() {
    for seed_node in API_SEED_NODES {
        let url = format!("https://{seed_node}");
        match try_generate_seeds_file(&url).await {
            Ok(()) => return,
            Err(err) => println!("{err}"),
        }
    }
    panic!("Failed to fetch API nodes with any of hard-coded seeds={API_SEED_NODES:?}");
}
