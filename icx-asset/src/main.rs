use clap::{crate_authors, crate_version, AppSettings, Clap};
use ic_agent::identity::{AnonymousIdentity, BasicIdentity};
use ic_agent::{agent, Agent, Identity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

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

    /// The asset canister ID to manage.
    #[clap()]
    canister_id: String,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Uploads an asset to an asset canister.
    Upload(UploadOpts),
    // /// List keys from the asset canister.
    // Ls(CallOpts),
}

#[derive(Clap)]
struct UploadOpts {
    /// Files or folders to send.
    #[clap()]
    files: Vec<String>,
}

fn create_identity(maybe_pem: Option<PathBuf>) -> Box<dyn Identity> {
    // if let Some(pem_path) = maybe_pem {
    //     Box::new(BasicIdentity::from_pem_file(pem_path).expect("Could not read the key pair."))
    // } else {
    Box::new(AnonymousIdentity)
    // }
}

fn upload(agent: Agent, opts: &Opts, o: &UploadOpts) -> Result<(), Box<dyn std::error::Error>> {
    // let canister = ic_utils::Canister::builder().with_agent(&agent ).with_canister_id(Principal::from_text(&opts.canister_id)?).build()?;

    let mut key_map: HashMap<String, PathBuf> = HashMap::new();
    for arg in &o.files {
        let (key, source): (String, PathBuf) = {
            if let Some(index) = arg.find('=') {
                (
                    arg[..index].to_string(),
                    PathBuf::from_str(&arg[index + 1..])?,
                )
            } else {
                (arg.clone(), PathBuf::from_str(&arg.clone())?)
            }
        };

        if source.is_file() {
            key_map.insert(key, source);
        } else {
            for p in WalkDir::new(source.clone())
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| !e.file_type().is_dir())
            {
                let p: &Path = p.path();
                key_map.insert(key.to_string() + "/" + &p.to_string_lossy(), source.join(p));
            }
        }
    }

    eprintln!("  {:?}", key_map);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::parse();

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestHttpReplicaV1Transport::create(opts.replica.clone())?,
        )
        // .with_boxed_identity((create_identity(opts.pem)))
        .build()?;

    match &opts.subcommand {
        SubCommand::Upload(o) => {
            upload(agent, &opts, o)?;
        }
    }

    Ok(())
}
