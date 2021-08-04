use crate::{support, UploadOpts};
use ic_utils::Canister;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use walkdir::WalkDir;

/// examples:
///   icx-asset upload a.txt       # upload a.txt to /a.txt
///   icx-asset upload directory   # uploads directory to /directory
///   icx-asset upload assets /    # same as icx-asset sync
///   icx-asset upload assets      # uploads assets to /assets (important, different from sync!)
///   icx-asset upload /some/absolute/path # uploads to /path
///   icx-asset upload some/relative/path  # uploads to /some/relative/path
///   icx-asset upload some/relative/*.txt # uploads to /some/relative/\1
/// or
///   icx-asset upload /=assets
pub(crate) async fn upload(canister: &Canister<'_>, opts: &UploadOpts) -> support::Result {
    println!("*** icx-asset upload {:?} ***", &opts);

    let key_map = get_key_map(&opts.files)?;
    for (k, v) in &key_map {
        println!("k: {}  v: {}", k, v.to_string_lossy());
    }
    ic_asset::upload(canister, Duration::from_secs(500), key_map).await?;
    Ok(())
}

fn get_key_map(files: &[String]) -> anyhow::Result<HashMap<String, PathBuf>> {
    println!("*** icx-asset get_key_map ***");
    let mut key_map: HashMap<String, PathBuf> = HashMap::new();

    for arg in files {
        let (key, source): (String, PathBuf) = {
            if let Some(index) = arg.find('=') {
                (
                    arg[..index].to_string(),
                    PathBuf::from_str(&arg[index + 1..])?,
                )
            } else {
                let source = PathBuf::from_str(&arg.clone())?;
                let key = format!("/{}", source.file_name().unwrap().to_string_lossy());
                // or if we want to retain relative paths:
                // let key = if source.is_absolute() {
                //     format!("/{}", source.file_name().unwrap().to_string_lossy())
                // } else {
                //     format!("/{}", arg.clone())
                // };
                (
                    key,
                    source,
                )
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
                let p = p.path().to_path_buf();
                let relative = p.strip_prefix(&source).expect("cannot strip prefix");
                let mut key = key.clone();
                if !key.ends_with('/') {
                    key.push('/');
                }
                key.push_str(relative.to_string_lossy().as_ref());
                key_map.insert( key, p );
                //
                // AssetLocation { source, key }

                // let p: &Path = p.path();
                // let key = key.to_string() + "/" + &p.to_string_lossy();
                // let source = p.to_path_buf();
                // key_map.insert(key, source);
            }
        }
    }

    Ok(key_map)
}
