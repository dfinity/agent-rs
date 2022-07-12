use crate::asset_canister::batch::{commit_batch, create_batch};
use crate::asset_canister::list::list_assets;
use crate::asset_canister::protocol::{AssetDetails, BatchOperationKind};
use crate::asset_config::{AssetSourceDirectoryConfiguration, ASSETS_CONFIG_FILENAME};
use crate::params::CanisterCallParams;

use crate::operations::{
    create_new_assets, delete_obsolete_assets, set_encodings, unset_obsolete_encodings,
};
use crate::plumbing::{make_project_assets, AssetDescriptor, ProjectAsset};
use anyhow::{bail, Context};
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
    let asset_descriptors = gather_asset_descriptors(dirs)?;

    let canister_call_params = CanisterCallParams { canister, timeout };

    let container_assets = list_assets(&canister_call_params).await?;

    println!("Starting batch.");

    let batch_id = create_batch(&canister_call_params).await?;

    println!("Staging contents of new and changed assets:");

    let project_assets = make_project_assets(
        &canister_call_params,
        &batch_id,
        asset_descriptors,
        &container_assets,
    )
    .await?;

    let operations = assemble_synchronization_operations(project_assets, container_assets);

    println!("Committing batch.");
    commit_batch(&canister_call_params, &batch_id, operations).await?;

    Ok(())
}

fn doesnt_start_with_a_dot_or_explicitly_included(
    entry: &walkdir::DirEntry,
    config: &AssetSourceDirectoryConfiguration,
) -> bool {
    let starts_with_a_dot = entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false);

    if starts_with_a_dot {
        config.hidden_explicitly_included(&entry.path())
    } else {
        true
    }
}

fn gather_asset_descriptors(dirs: &[&Path]) -> anyhow::Result<Vec<AssetDescriptor>> {
    let mut asset_descriptors: HashMap<String, AssetDescriptor> = HashMap::new();
    for dir in dirs {
        let dir = dir.canonicalize().with_context(|| {
            format!(
                "unable to canonicalize the following path: {}",
                dir.display()
            )
        })?;
        let configuration = AssetSourceDirectoryConfiguration::load(&dir)?;
        let mut asset_descriptors_interim = vec![];
        for e in WalkDir::new(&dir)
            .into_iter()
            .filter_entry(|entry| {
                doesnt_start_with_a_dot_or_explicitly_included(entry, &configuration)
            })
            .filter_map(|r| r.ok())
            .filter(|entry| {
                entry.file_type().is_file() && entry.file_name() != ASSETS_CONFIG_FILENAME
            })
        {
            let source = e.path().canonicalize().with_context(|| {
                format!(
                    "unable to canonicalize the path when gathering asset descriptors: {}",
                    dir.display()
                )
            })?;
            let relative = source.strip_prefix(&dir).expect("cannot strip prefix");
            let key = String::from("/") + relative.to_string_lossy().as_ref();
            let config = configuration.get_asset_config(&source).context(format!(
                "failed to get config for asset: {}",
                source.display()
            ))?;

            asset_descriptors_interim.push(AssetDescriptor {
                source,
                key,
                config,
            })
        }

        for asset_descriptor in asset_descriptors_interim {
            if let Some(already_seen) = asset_descriptors.get(&asset_descriptor.key) {
                bail!(
                    "Asset with key '{}' defined at {} and {}",
                    &asset_descriptor.key,
                    asset_descriptor.source.display(),
                    already_seen.source.display()
                )
            }
            asset_descriptors.insert(asset_descriptor.key.clone(), asset_descriptor);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn get_test_assets_directory() -> PathBuf {
        let crate_root = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        Path::new(&crate_root).join("tests").join("assets")
    }

    #[test]
    fn hidden_dir_included() {
        let example_assets_dir =
            get_test_assets_directory().join("example_project_assets_with_hidden_dir_included");
        let asset_descriptors = dbg!(gather_asset_descriptors(&[&example_assets_dir]).unwrap());
        let expected: Vec<AssetDescriptor> = vec![];
        assert_eq!(asset_descriptors, expected);
        assert_ne!(asset_descriptors, expected);
    }

    #[test]
    // #[ignore]
    fn hidden_dir_not_included() {
        let example_assets_dir =
            get_test_assets_directory().join("example_project_assets_with_hidden_dir_not_included");
        let asset_descriptors = dbg!(gather_asset_descriptors(&[&example_assets_dir]).unwrap());
        let expected: Vec<AssetDescriptor> = vec![];
        assert_eq!(asset_descriptors, expected);
    }
}
