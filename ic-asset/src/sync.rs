use crate::asset_canister::batch::{commit_batch, create_batch};
use crate::asset_canister::list::list_assets;
use crate::asset_canister::protocol::{AssetDetails, BatchOperationKind};
use crate::params::CanisterCallParams;

use crate::operations::{
    create_new_assets, delete_obsolete_assets, set_encodings, unset_obsolete_encodings,
};
use crate::plumbing::{make_project_assets, AssetLocation, ProjectAsset};
use ic_utils::Canister;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use walkdir::WalkDir;

pub async fn sync(canister: &Canister<'_>, dir: &Path, timeout: Duration) -> anyhow::Result<()> {
    let asset_locations = gather_asset_locations(dir);

    let canister_call_params = CanisterCallParams { canister, timeout };

    let container_assets = list_assets(&canister_call_params).await?;

    let batch_id = create_batch(&canister_call_params).await?;

    let project_assets = make_project_assets(
        &canister_call_params,
        &batch_id,
        asset_locations,
        &container_assets,
    )
    .await?;

    let operations = assemble_synchronization_operations(project_assets, container_assets);

    commit_batch(&canister_call_params, &batch_id, operations).await?;

    Ok(())
}

fn gather_asset_locations(dir: &Path) -> Vec<AssetLocation> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|r| {
            r.ok().filter(|entry| entry.file_type().is_file()).map(|e| {
                let source = e.path().to_path_buf();
                let relative = source.strip_prefix(dir).expect("cannot strip prefix");
                let key = String::from("/") + relative.to_string_lossy().as_ref();

                AssetLocation { source, key }
            })
        })
        .collect()
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
