use crate::asset_canister::protocol::AssetDetails;
use crate::content::Content;
use crate::content_encoder::ContentEncoder;
use crate::params::CanisterCallParams;

use crate::asset_canister::chunk::create_chunk;
use candid::Nat;
use futures::future::try_join_all;
use futures::TryFutureExt;
use futures_intrusive::sync::SharedSemaphore;
use mime::Mime;
use std::collections::HashMap;
use std::path::PathBuf;

const CONTENT_ENCODING_IDENTITY: &str = "identity";

// The most mb any one file is considered to have for purposes of limiting data loaded at once.
// Any file counts as at least 1 mb.
const MAX_COST_SINGLE_FILE_MB: usize = 45;

// Maximum MB of file data to load at once.  More memory may be used, due to encodings.
const MAX_SIMULTANEOUS_LOADED_MB: usize = 50;

// How many simultaneous Agent.call() to create_chunk
const MAX_SIMULTANEOUS_CREATE_CHUNK_CALLS: usize = 1;

// How many simultaneous Agent.wait() on create_chunk result
const MAX_SIMULTANEOUS_CREATE_CHUNK_WAITS: usize = 1;

const MAX_CHUNK_SIZE: usize = 1_900_000;

#[derive(Clone, Debug)]
pub(crate) struct AssetLocation {
    pub(crate) source: PathBuf,
    pub(crate) key: String,
}

pub(crate) struct ProjectAssetEncoding {
    pub(crate) chunk_ids: Vec<Nat>,
    pub(crate) sha256: Vec<u8>,
    pub(crate) already_in_place: bool,
}

pub(crate) struct ProjectAsset {
    pub(crate) asset_location: AssetLocation,
    pub(crate) media_type: Mime,
    pub(crate) encodings: HashMap<String, ProjectAssetEncoding>,
}

#[allow(clippy::too_many_arguments)]
async fn make_project_asset_encoding(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    asset_location: &AssetLocation,
    container_assets: &HashMap<String, AssetDetails>,
    content: &Content,
    content_encoding: &str,
    create_chunk_call_semaphore: &SharedSemaphore,
    create_chunk_wait_semaphore: &SharedSemaphore,
) -> anyhow::Result<ProjectAssetEncoding> {
    let sha256 = content.sha256();

    let already_in_place = if let Some(container_asset) = container_assets.get(&asset_location.key)
    {
        if container_asset.content_type != content.media_type.to_string() {
            false
        } else if let Some(container_asset_encoding_sha256) = container_asset
            .encodings
            .iter()
            .find(|details| details.content_encoding == content_encoding)
            .and_then(|details| details.sha256.as_ref())
        {
            container_asset_encoding_sha256 == &sha256
        } else {
            false
        }
    } else {
        false
    };

    let chunk_ids = if already_in_place {
        println!(
            "  {}{} ({} bytes) sha {} is already installed",
            &asset_location.key,
            content_encoding_descriptive_suffix(content_encoding),
            content.data.len(),
            hex::encode(&sha256),
        );
        vec![]
    } else {
        upload_content_chunks(
            canister_call_params,
            batch_id,
            &asset_location,
            content,
            content_encoding,
            create_chunk_call_semaphore,
            create_chunk_wait_semaphore,
        )
        .await?
    };

    Ok(ProjectAssetEncoding {
        chunk_ids,
        sha256,
        already_in_place,
    })
}

#[allow(clippy::too_many_arguments)]
async fn make_encoding(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    asset_location: &AssetLocation,
    container_assets: &HashMap<String, AssetDetails>,
    content: &Content,
    encoder: &Option<ContentEncoder>,
    create_chunk_call_semaphore: &SharedSemaphore,
    create_chunk_wait_semaphore: &SharedSemaphore,
) -> anyhow::Result<Option<(String, ProjectAssetEncoding)>> {
    match encoder {
        None => {
            let identity_asset_encoding = make_project_asset_encoding(
                canister_call_params,
                batch_id,
                &asset_location,
                container_assets,
                &content,
                CONTENT_ENCODING_IDENTITY,
                create_chunk_call_semaphore,
                create_chunk_wait_semaphore,
            )
            .await?;
            Ok(Some((
                CONTENT_ENCODING_IDENTITY.to_string(),
                identity_asset_encoding,
            )))
        }
        Some(encoder) => {
            let encoded = content.encode(&encoder)?;
            if encoded.data.len() < content.data.len() {
                let content_encoding = format!("{}", encoder);
                let project_asset_encoding = make_project_asset_encoding(
                    canister_call_params,
                    batch_id,
                    &asset_location,
                    container_assets,
                    &encoded,
                    &content_encoding,
                    create_chunk_call_semaphore,
                    create_chunk_wait_semaphore,
                )
                .await?;
                Ok(Some((content_encoding, project_asset_encoding)))
            } else {
                Ok(None)
            }
        }
    }
}

async fn make_encodings(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    asset_location: &AssetLocation,
    container_assets: &HashMap<String, AssetDetails>,
    content: &Content,
    create_chunk_call_semaphore: &SharedSemaphore,
    create_chunk_wait_semaphore: &SharedSemaphore,
) -> anyhow::Result<HashMap<String, ProjectAssetEncoding>> {
    let mut encoders = vec![None];
    for encoder in applicable_encoders(&content.media_type) {
        encoders.push(Some(encoder));
    }

    let encoding_futures: Vec<_> = encoders
        .iter()
        .map(|maybe_encoder| {
            make_encoding(
                canister_call_params,
                batch_id,
                asset_location,
                container_assets,
                content,
                maybe_encoder,
                create_chunk_call_semaphore,
                create_chunk_wait_semaphore,
            )
        })
        .collect();

    let encodings = try_join_all(encoding_futures).await?;

    let mut result: HashMap<String, ProjectAssetEncoding> = HashMap::new();

    for (key, value) in encodings.into_iter().flatten() {
        result.insert(key, value);
    }
    Ok(result)
}

async fn make_project_asset(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    asset_location: AssetLocation,
    container_assets: &HashMap<String, AssetDetails>,
    file_semaphore: &SharedSemaphore,
    create_chunk_call_semaphore: &SharedSemaphore,
    create_chunk_wait_semaphore: &SharedSemaphore,
) -> anyhow::Result<ProjectAsset> {
    let file_size = std::fs::metadata(&asset_location.source)?.len();
    let permits = std::cmp::max(
        1,
        std::cmp::min(
            ((file_size + 999999) / 1000000) as usize,
            MAX_COST_SINGLE_FILE_MB,
        ),
    );
    let _releaser = file_semaphore.acquire(permits).await;
    let content = Content::load(&asset_location.source)?;

    let encodings = make_encodings(
        canister_call_params,
        batch_id,
        &asset_location,
        container_assets,
        &content,
        create_chunk_call_semaphore,
        create_chunk_wait_semaphore,
    )
    .await?;

    Ok(ProjectAsset {
        asset_location,
        media_type: content.media_type,
        encodings,
    })
}

pub(crate) async fn make_project_assets(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    locs: Vec<AssetLocation>,
    container_assets: &HashMap<String, AssetDetails>,
) -> anyhow::Result<HashMap<String, ProjectAsset>> {
    // The "file" semaphore limits how much file data to load at once.  A given loaded file's data
    // may be simultaneously encoded (gzip and so forth).
    let file_semaphore = SharedSemaphore::new(true, MAX_SIMULTANEOUS_LOADED_MB);

    // The create_chunk call semaphore limits the number of simultaneous
    // agent.call()s to create_chunk.
    let create_chunk_call_semaphore =
        SharedSemaphore::new(true, MAX_SIMULTANEOUS_CREATE_CHUNK_CALLS);

    // The create_chunk wait semaphore limits the number of simultaneous
    // agent.wait() calls for outstanding create_chunk requests.
    let create_chunk_wait_semaphore =
        SharedSemaphore::new(true, MAX_SIMULTANEOUS_CREATE_CHUNK_WAITS);

    let project_asset_futures: Vec<_> = locs
        .iter()
        .map(|loc| {
            make_project_asset(
                canister_call_params,
                batch_id,
                loc.clone(),
                &container_assets,
                &file_semaphore,
                &create_chunk_call_semaphore,
                &create_chunk_wait_semaphore,
            )
        })
        .collect();
    let project_assets = try_join_all(project_asset_futures).await?;

    let mut hm = HashMap::new();
    for project_asset in project_assets {
        hm.insert(project_asset.asset_location.key.clone(), project_asset);
    }
    Ok(hm)
}

async fn upload_content_chunks(
    canister_call_params: &CanisterCallParams<'_>,
    batch_id: &Nat,
    asset_location: &AssetLocation,
    content: &Content,
    content_encoding: &str,
    create_chunk_call_semaphore: &SharedSemaphore,
    create_chunk_wait_semaphore: &SharedSemaphore,
) -> anyhow::Result<Vec<Nat>> {
    if content.data.is_empty() {
        let empty = vec![];
        let chunk_id = create_chunk(
            canister_call_params,
            batch_id,
            &empty,
            create_chunk_call_semaphore,
            create_chunk_wait_semaphore,
        )
        .await?;
        println!(
            "  {}{} 1/1 (0 bytes)",
            &asset_location.key,
            content_encoding_descriptive_suffix(content_encoding)
        );
        return Ok(vec![chunk_id]);
    }

    let count = (content.data.len() + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    let chunks_futures: Vec<_> = content
        .data
        .chunks(MAX_CHUNK_SIZE)
        .enumerate()
        .map(|(i, data_chunk)| {
            create_chunk(
                canister_call_params,
                batch_id,
                data_chunk,
                create_chunk_call_semaphore,
                create_chunk_wait_semaphore,
            )
            .map_ok(move |chunk_id| {
                println!(
                    "  {}{} {}/{} ({} bytes)",
                    &asset_location.key,
                    content_encoding_descriptive_suffix(content_encoding),
                    i + 1,
                    count,
                    data_chunk.len(),
                );
                chunk_id
            })
        })
        .collect();
    try_join_all(chunks_futures).await
}

fn content_encoding_descriptive_suffix(content_encoding: &str) -> String {
    if content_encoding == CONTENT_ENCODING_IDENTITY {
        "".to_string()
    } else {
        format!(" ({})", content_encoding)
    }
}

// todo: make this configurable https://github.com/dfinity/dx-triage/issues/152
fn applicable_encoders(media_type: &Mime) -> Vec<ContentEncoder> {
    match (media_type.type_(), media_type.subtype()) {
        (mime::TEXT, _) | (_, mime::JAVASCRIPT) | (_, mime::HTML) => vec![ContentEncoder::Gzip],
        _ => vec![],
    }
}
