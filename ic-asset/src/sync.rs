use crate::asset_canister::batch::{commit_batch, create_batch};
use crate::asset_canister::list::list_assets;
use crate::asset_canister::protocol::{AssetDetails, BatchOperationKind};
use crate::asset_config::AssetSourceDirectoryConfiguration;
use crate::params::CanisterCallParams;

use crate::operations::{
    create_new_assets, delete_obsolete_assets, set_encodings, unset_obsolete_encodings,
};
use crate::plumbing::{make_project_assets, AssetLocation, ProjectAsset};
use anyhow::bail;
use ic_utils::Canister;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use walkdir::WalkDir;

/// Sets the contents of the asset canister to the contents of a directory, including deleting old assets.
pub async fn sync(
    canister: &Canister<'_>,
    dirs: &[&Path],
    timeout: Duration,
) -> anyhow::Result<()> {
    let asset_locations = gather_asset_locations(dirs)?;

    println!("{:?}", asset_locations);
    let configuration = AssetSourceDirectoryConfiguration::load(dir)?;

    let canister_call_params = CanisterCallParams { canister, timeout };

    let container_assets = list_assets(&canister_call_params).await?;

    println!("Starting batch.");

    let batch_id = create_batch(&canister_call_params).await?;

    println!("Staging contents of new and changed assets:");

    let project_assets = make_project_assets(
        &canister_call_params,
        &batch_id,
        asset_locations,
        &container_assets,
        configuration,
    )
    .await?;

    let operations = assemble_synchronization_operations(project_assets, container_assets);

    println!("Committing batch.");
    commit_batch(&canister_call_params, &batch_id, operations).await?;

    Ok(())
}

fn filename_starts_with_dot(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

fn gather_asset_locations(dirs: &[&Path]) -> anyhow::Result<Vec<AssetLocation>> {
    let mut asset_descriptors: HashMap<String, AssetLocation> = HashMap::new();
    for dir in dirs {
        let asset_locations = WalkDir::new(dir)
            .into_iter()
            .filter_entry(|entry| !filename_starts_with_dot(entry))
            .filter_map(|r| {
                r.ok().filter(|entry| entry.file_type().is_file()).map(|e| {
                    let source = e.path().to_path_buf();
                    let relative = source.strip_prefix(dir).expect("cannot strip prefix");
                    let key = String::from("/") + relative.to_string_lossy().as_ref();

                    AssetLocation { source, key }
                })
            })
            .collect::<Vec<_>>();
        for asset_location in asset_locations {
            if let Some(already_seen) = asset_descriptors.get(&asset_location.key) {
                bail!(
                    "Asset with key '{}' defined at {} and {}",
                    &asset_location.key,
                    asset_location.source.display(),
                    already_seen.source.display()
                )
            }
            asset_descriptors.insert(asset_location.key.clone(), asset_location);
        }
    }
    Ok(asset_descriptors.into_values().collect())
}

fn assemble_synchronization_operations(
    project_assets: HashMap<String, ProjectAsset>,
    container_assets: HashMap<String, AssetDetails>,
) -> Vec<BatchOperationKind> {
    let mut container_assets = container_assets;

    let mut operations = vec![];

    delete_obsolete_assets(&mut operations, &project_assets, &mut container_assets);
    create_new_assets(&mut operations, &project_assets, &container_assets);
    unset_obsolete_encodings(&mut operations, &project_assets, &container_assets);
    set_encodings(&mut operations, project_assets);

    operations
}
