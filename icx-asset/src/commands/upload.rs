use crate::{support, UploadOpts};
use ic_utils::Canister;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use walkdir::WalkDir;

pub(crate) async fn upload(canister: &Canister<'_>, opts: &UploadOpts) -> support::Result {
    let key_map = get_key_map(&opts.files)?;
    for (k, v) in &key_map {
        eprintln!("k: {}  v: {}", k, v.to_string_lossy());
    }
    ic_asset::upload(canister, Duration::from_secs(500), key_map).await?;
    Ok(())
}

fn get_key_map(files: &[String]) -> anyhow::Result<HashMap<String, PathBuf>> {
    let mut key_map: HashMap<String, PathBuf> = HashMap::new();

    for arg in files {
        let (key, source): (String, PathBuf) = {
            if let Some(index) = arg.find('=') {
                (
                    arg[..index].to_string(),
                    PathBuf::from_str(&arg[index + 1..])?,
                )
            } else {
                (
                    format!("/{}", arg.clone()),
                    PathBuf::from_str(&arg.clone())?,
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
                let p: &Path = p.path();
                let key = key.to_string() + "/" + &p.to_string_lossy();
                let source = p.to_path_buf();
                key_map.insert(key, source);
            }
        }
    }

    Ok(key_map)
}
