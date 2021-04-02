use clap::{crate_authors, crate_version, AppSettings, Clap};
use ic_agent::identity::AnonymousIdentity;
use ic_agent::{agent, Agent, Identity};
use ic_types::Principal;
use ic_utils::Canister;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

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

struct ChunkIterator<T>
where
    T: Read,
{
    pub source: T,
    pub chunk_size: usize,
}

struct Chunk(pub Vec<u8>);

impl<T> Iterator for ChunkIterator<T>
where
    T: Read,
{
    type Item = Chunk;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = vec![0; self.chunk_size];
        match self.source.read(buffer.as_mut_slice()) {
            Ok(count) => {
                if count > 0 {
                    buffer.split_off(count);
                    Some(Chunk(buffer))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

#[derive(CandidType, Deserialize)]
struct CreateChunkArg<'a> {
    pub batch_id: &'a candid::Nat,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
struct CreateChunkReturn {
    pub chunk_id: candid::Nat,
}

/// Upload an iterator of file paths to the asset canister, in a batch. The batch should be created
/// prior to calling this. This does not apply any logic currently as to whether files should
/// be uploaded; all files passed in WILL uploaded.
async fn do_upload(
    canister: &Canister<'_>,
    batch_id: candid::Nat,
    files: impl Iterator<Item = (String, PathBuf)>,
    chunk_size: usize,
) -> Result<Vec<(String, Vec<candid::Nat>)>> {
    // First, split the files into chunks.
    let files = files
        .filter_map(|(name, path)| Some((name, std::fs::File::open(path).ok()?)))
        .flat_map(|(name, file)| {
            let chunks = ChunkIterator {
                source: file,
                chunk_size,
            };

            // Since no chunk really own the name, we create an Arc that share a reference
            // to it.
            let name = std::sync::Arc::new(name);

            chunks.map(move |chunk| (std::sync::Arc::clone(&name), chunk))
        });

    let result = Vec::new();
    for (name, chunk) in files {
        canister
            .update_("create_chunk")
            .with_arg(CreateChunkArg {
                batch_id: &batch_id,
                content: chunk.0,
            })
            .build()
            .call_and_wait()
            .await?;
    }

    Ok(result)
}

async fn upload(agent: Agent, opts: &Opts, o: &UploadOpts) -> Result {
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
                .filter_map(std::result::Result::ok)
                .filter(|e| !e.file_type().is_dir())
            {
                let p: &Path = p.path();
                let key = key.to_string() + "/" + &p.to_string_lossy();
                let source = p.to_path_buf();
                key_map.insert(key, source);
            }
        }
    }

    let canister = ic_utils::Canister::builder()
        .with_agent(&agent)
        .with_canister_id(Principal::from_text(&opts.canister_id)?)
        .build()?;

    eprintln!("{:#?}", key_map);
    do_upload(&canister, key_map.into_iter(), 1024 * 1024).await?;

    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> Result {
    let opts: Opts = Opts::parse();

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestHttpReplicaV1Transport::create(opts.replica.clone())?,
        )
        // .with_boxed_identity((create_identity(opts.pem)))
        .build()?;

    match &opts.subcommand {
        SubCommand::Upload(o) => {
            upload(agent, &opts, o).await?;
        }
    }

    Ok(())
}
