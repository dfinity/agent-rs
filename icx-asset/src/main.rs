use clap::{crate_authors, crate_version, AppSettings, Clap};
use ic_agent::identity::{AnonymousIdentity, BasicIdentity};
use ic_agent::{agent, Agent, Identity};
use candid::Principal;
use candid::Principal as CanisterId;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_IC_GATEWAY: &str = "https://ic0.app";

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clap)]
#[clap(
version = crate_version!(),
author = crate_authors!(),
global_setting = AppSettings::GlobalVersion,
global_setting = AppSettings::ColoredHelp
)]
struct Opts {
    /// Some input. Because this isn't an Option<T> it's required to be used
    #[clap(long, default_value = "http://localhost:8000/")]
    replica: String,

    /// An optional PEM file to read the identity from. If none is passed,
    /// a random identity will be created.
    #[clap(long)]
    pem: Option<PathBuf>,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Synchronize a directory to the asset canister
    Sync(SyncOpts),
}

#[derive(Clap)]
struct SyncOpts {
    /// The canister ID.
    #[clap()]
    canister_id: String,

    /// The directory to synchronize
    #[clap()]
    directory: PathBuf,
}
fn create_identity(maybe_pem: Option<PathBuf>) -> Box<dyn Identity + Sync + Send> {
    if let Some(pem_path) = maybe_pem {
        Box::new(BasicIdentity::from_pem_file(pem_path).expect("Could not read the key pair."))
    } else {
      Box::new(AnonymousIdentity)
    }
}

pub fn expiry_duration() -> Duration {
    // 5 minutes is max ingress timeout
    Duration::from_secs(60 * 5)
}

async fn sync(agent: &Agent, canister_id: &CanisterId, o: &SyncOpts) -> Result {
    let timeout = expiry_duration();
    ic_asset::sync(&agent, &o.directory, canister_id, timeout).await?;
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> Result {
    let opts: Opts = Opts::parse();

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestHttpReplicaV2Transport::create(opts.replica.clone())?,
        )
        .with_boxed_identity(create_identity(opts.pem))
        .build()?;

    let normalized_replica = opts.replica.strip_suffix("/").unwrap_or(&opts.replica);
    if normalized_replica != DEFAULT_IC_GATEWAY {
        agent.fetch_root_key().await?;
    }

    match &opts.subcommand {
        SubCommand::Sync(o) => {
            let canister_id = Principal::from_text(&o.canister_id)?;
            sync(&agent, &canister_id, o).await?;
        }
    }

    Ok(())
}
