use candid::CandidType;
use clap::{crate_authors, crate_version, AppSettings, Clap};
use ic_agent::identity::AnonymousIdentity;
use ic_agent::{agent, Agent, Identity};
use ic_types::Principal;
use ic_utils::call::SyncCall;
use ic_utils::Canister;
use num_traits::ToPrimitive;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
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

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Uploads an asset to an asset canister.
    Upload(UploadOpts),
    /// List keys from the asset canister.
    #[clap(name = "ls")]
    List(ListOpts),
}

#[derive(Clap)]
struct UploadOpts {
    /// The asset canister ID to manage.
    #[clap()]
    canister_id: String,

    /// Files or folders to send.
    #[clap()]
    files: Vec<String>,
}

#[derive(Clap)]
struct ListOpts {
    /// The canister ID.
    #[clap()]
    canister_id: String,
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

struct Content {
    reader: Arc<dyn Read>,
    encodings: Vec<ContentEncoding>,
}

impl Content {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = Arc::new(std::fs::File::open(path)?);

        Ok(Self {
            reader,
            encodings: vec![ContentEncoding::Identity],
        })
    }
}

enum ContentEncoding {
    Identity,
    Gzip,
}

impl ContentEncoding {
    pub fn read<R: Read>(&self, mut reader: R) -> Result<Vec<u8>> {
        match self {
            ContentEncoding::Identity => {
                let mut vec = Vec::new();
                reader.read_to_end(&mut vec)?;
                Ok(vec)
            }
            ContentEncoding::Gzip => {
                let mut encoder = libflate::gzip::Encoder::new(Vec::new())?;
                std::io::copy(&mut reader, &mut encoder)?;

                Ok(encoder.finish().into_result()?)
            }
        }
    }
}

struct Asset {
    name: String,
    file: std::fs::File,
    // content: Vec<ContentEncoding>,
}

impl Asset {
    pub fn new<N: Into<String>, P: Into<PathBuf>>(name: N, path: P) -> Result<Self> {
        Ok(Self {
            name: name.into(),
            file: std::fs::File::open(path.into())?,
            // content: Content::from_path(path),
        })
    }
}

impl Read for Asset {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

#[derive(CandidType, Deserialize)]
struct CreateChunkArg {
    pub batch_id: candid::Nat,
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
        // .flat_map(|(name, file)| {
        //     // Return an iterator over encodings of this file.
        //     (name, file)
        // })
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
                batch_id: batch_id.clone(),
                content: chunk.0,
            })
            .build()
            .call_and_wait(garcon::Delay::exponential_backoff(
                Duration::from_secs(1),
                1.2,
            ))
            .await?;
    }

    Ok(result)
}

async fn upload(canister: &Canister<'_>, _opts: &Opts, o: &UploadOpts) -> Result {
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

    eprintln!("{:#?}", key_map);
    do_upload(
        canister,
        candid::Nat::from(0),
        key_map.into_iter(),
        1024 * 1024,
    )
    .await?;

    Ok(())
}

async fn list(canister: &Canister<'_>, _opts: &Opts, _o: &ListOpts) -> Result {
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

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> Result {
    let opts: Opts = Opts::parse();

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestHttpReplicaV2Transport::create(opts.replica.clone())?,
        )
        // .with_boxed_identity((create_identity(opts.pem)))
        .build()?;

    agent.fetch_root_key().await?;

    match &opts.subcommand {
        SubCommand::Upload(o) => {
            let canister = ic_utils::Canister::builder()
                .with_agent(&agent)
                .with_canister_id(Principal::from_text(&o.canister_id)?)
                .build()?;

            upload(&canister, &opts, o).await?;
        }
        SubCommand::List(o) => {
            let canister = ic_utils::Canister::builder()
                .with_agent(&agent)
                .with_canister_id(Principal::from_text(&o.canister_id)?)
                .build()?;

            list(&canister, &opts, o).await?;
        }
    }

    Ok(())
}
