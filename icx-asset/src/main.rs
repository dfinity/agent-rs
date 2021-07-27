use candid::CandidType;
use candid::Principal;
use candid::Principal as CanisterId;
use clap::{crate_authors, crate_version, AppSettings, Clap};
use ic_agent::identity::{AnonymousIdentity, BasicIdentity};
use ic_agent::{agent, Agent, Identity};
use ic_utils::call::SyncCall;

use ic_utils::Canister;
use num_traits::ToPrimitive;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

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

    /// An optional field to set the expiry time on requests. Can be a human
    /// readable time (like `100s`) or a number of seconds.
    #[clap(long)]
    ttl: Option<humantime::Duration>,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// List keys from the asset canister.
    #[clap(name = "ls")]
    List(ListOpts),

    /// Synchronize a directory to the asset canister
    Sync(SyncOpts),
}

#[derive(Clap)]
struct ListOpts {
    /// The canister ID.
    #[clap()]
    canister_id: String,
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

async fn sync(agent: &Agent, canister_id: &CanisterId, timeout: Duration, o: &SyncOpts) -> Result {
    ic_asset::sync(&agent, &o.directory, canister_id, timeout).await?;
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> Result {
    let opts: Opts = Opts::parse();

    let ttl: std::time::Duration = opts
        .ttl
        .map(|ht| ht.into())
        .unwrap_or_else(|| Duration::from_secs(60 * 5)); // 5 minutes is max ingress timeout

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
        SubCommand::List(o) => {
            let canister = ic_utils::Canister::builder()
                .with_agent(&agent)
                .with_canister_id(Principal::from_text(&o.canister_id)?)
                .build()?;
            list(&canister).await?;
        }
        SubCommand::Sync(o) => {
            let canister_id = Principal::from_text(&o.canister_id)?;
            sync(&agent, &canister_id, ttl, o).await?;
        }
    }

    Ok(())
}

async fn list(canister: &Canister<'_>) -> Result {
    #[derive(CandidType, Deserialize)]
    struct Encoding {
        modified: candid::Int,
        content_encoding: String,
        sha256: Option<Vec<u8>>,
        length: candid::Nat,
    }

    #[derive(CandidType, Deserialize)]
    struct ListEntry {
        key: String,
        content_type: String,
        encodings: Vec<Encoding>,
    }

    #[derive(CandidType, Deserialize)]
    struct EmptyRecord {}

    let (entries,): (Vec<ListEntry>,) = canister
        .query_("list")
        .with_arg(EmptyRecord {})
        .build()
        .call()
        .await?;

    use chrono::offset::Local;
    use chrono::DateTime;

    for entry in entries {
        for encoding in entry.encodings {
            let modified = encoding.modified;
            let modified = SystemTime::UNIX_EPOCH
                + std::time::Duration::from_nanos(modified.0.to_u64().unwrap());

            eprintln!(
                "{:>20} {:>15} {:50} ({}, {})",
                DateTime::<Local>::from(modified).format("%F %X"),
                encoding.length.0.to_string(),
                entry.key,
                entry.content_type,
                encoding.content_encoding
            );
        }
    }
    Ok(())
}
