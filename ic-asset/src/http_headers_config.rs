// FIXME: support a way to clear header key-value (currently not possible, once it's there, you can only overwrite it)

use globset::Glob;
use pathdiff::diff_paths;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

/// Filename for assets configuration JSON file.
pub const ASSETS_CONFIG_FILENAME: &str = ".ic-assets.json";

/// HTTP cache configuration.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct CacheConfig {
    pub(crate) max_age: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        // TODO: what defaults should be used
        Self { max_age: 0 }
    }
}

/// Map of custom HTTP headers defined by the end developer.
// TODO: instead of serde_json::Value, maybe consider this https://docs.rs/http-serde/1.1.0/http_serde/index.html
pub(crate) type HeadersConfig = HashMap<String, Value>;

/// The single map from array from deserialized .ic-assets.json file.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
struct AssetsHeadersConfiguration {
    /// Glob pattern
    r#match: String,
    /// HTTP cache config, if omitted, the default value will be used.
    cache: Option<CacheConfig>,
    /// HTTP Headers.
    headers: Option<HeadersConfig>,
}

/// Represents single .ic-assets.json file.
///
/// Expected JSON format;
/// ```json
/// [
///  {
///    "match": "*",
///    "cache": {
///      "max_age": 86400
///    },
///    "headers": {
///      "some-header-name": "some-header-value",
///      "permissions-policy": "add; delete"
///    }
///  },
///  {
///    "match": "**/*.js",
///    "cache": {
///      "max_age": 3600
///    }
///  }
/// ]
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
struct AssetsHeadersConfigFile {
    filepath: PathBuf,
    config_maps: Vec<AssetsHeadersConfiguration>,
}

impl AssetsHeadersConfigFile {
    /// Parse JSON config file
    // TODO: Error handling
    fn read(filepath: &Path) -> Result<Self, std::io::Error> {
        let mut file = File::open(filepath)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        match serde_json::from_str::<Vec<AssetsHeadersConfiguration>>(&contents) {
            Ok(mut config_maps) => {
                config_maps.iter_mut().for_each(|c| {
                    let glob_pattern = format!(
                        "{}/{}",
                        filepath.parent().unwrap().to_str().unwrap(),
                        &c.r#match
                    );
                    c.r#match = glob_pattern;
                });
                Ok(Self {
                    config_maps,
                    filepath: filepath.to_path_buf(),
                })
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Configuration assigned to single asset
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub(crate) struct AssetConfig {
    /// asset' full path
    pub(crate) filepath: PathBuf,
    /// asset' relative path - used only for pretty printing
    pub(crate) relative_filepath: PathBuf,
    /// HTTP cache config, if omitted, the default value will be used.
    // TODO: discuss: perhaps this shouldnt be an option
    pub(crate) cache: Option<CacheConfig>,
    /// HTTP Headers.
    // TODO: discuss: perhaps this shouldnt be an option
    pub(crate) headers: Option<HeadersConfig>,
}

impl AssetConfig {
    pub(crate) fn with_path(self, filepath: &Path, relative_filepath: &Path) -> Self {
        Self {
            filepath: filepath.to_path_buf(),
            relative_filepath: relative_filepath.to_path_buf(),
            ..self
        }
    }

    /// Helper function, enables to easily `fold` the `Vec<AssetsHeadersConfig>`.
    /// Merges by overwritting left (self) with right (other).
    fn merge(mut self, other: Self) -> Self {
        if let Some(c) = other.cache {
            self.cache = Some(c);
        };
        match (self.headers.as_mut(), other.headers) {
            (Some(sh), Some(oh)) => sh.extend(oh),
            (None, Some(h)) => self.headers = Some(h),
            (_, None) => {}
        };
        self
    }
}

impl Default for AssetConfig {
    fn default() -> Self {
        Self {
            filepath: PathBuf::new(),
            relative_filepath: PathBuf::new(),
            // TODO: what defaults should be used
            cache: None,
            headers: None,
        }
    }
}

/// Single asset file.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
struct AssetFile {
    /// asset' full path
    filepath: PathBuf,
    /// asset' relative path - used only for pretty printing
    relative_filepath: PathBuf,
    matched_configurations: Vec<AssetConfig>,
}

impl AssetFile {
    fn from_path(assets_dir: &Path, asset_fullpath: &Path) -> Self {
        Self {
            filepath: asset_fullpath.to_path_buf(),
            relative_filepath: diff_paths(asset_fullpath, assets_dir).unwrap(),
            matched_configurations: vec![],
        }
    }
}

/// For given [`assets_dir`](AssetsConfigMatcher::new), it will walk trough the assets directory,
/// and find all [.ic-assets.json](ASSETS_CONFIG_FILENAME) config files in directories and
/// subdirectories, and finally assignes [AssetConfig] for each asset file matched.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub(crate) struct AssetsConfigMatcher {
    /// List of all .ic-assets.json config files.
    configs: Vec<AssetsHeadersConfigFile>,
    /// List of all assets.
    assets: Vec<AssetFile>,
    /// Assets root dir (usually defined in dfx.json canisters/<name>/source).
    assets_dir: PathBuf,
}

impl AssetsConfigMatcher {
    /// Walks `assets_dir` to find each .ic-assets.json file and all assets files.
    pub(crate) fn new(assets_dir: &Path) -> Self {
        let mut configs = vec![];
        let mut assets = vec![];

        for entry in WalkDir::new(assets_dir) {
            match entry {
                Ok(e) if e.file_type().is_file() && e.file_name() == ASSETS_CONFIG_FILENAME => {
                    match AssetsHeadersConfigFile::read(e.path()) {
                        Ok(config) => configs.push(config),
                        Err(e) => eprintln!("error reading {}: {}", 3, e),
                    }
                }
                Ok(e) if e.file_type().is_file() => {
                    assets.push(AssetFile::from_path(assets_dir, e.path()))
                }
                // TODO: error handling
                _ => continue,
            }
        }

        AssetsConfigMatcher {
            configs,
            assets,
            assets_dir: assets_dir.to_path_buf(),
        }
    }

    /// for each asset file:
    ///     1. search for config in its directory or parent directories
    ///     2. for each found config file, go trough all glob patterns and store all config maps which match asset' filepath
    ///     3. fold all matched config maps (which return a single, final config for the file)
    ///
    /// Oftentimes, multiple patterns will be matched, which requires confict resolution.
    /// The strategy for conflict resolution is simple: assets directory is being walk trought in DFS fashion
    /// which makes it easy to prioritize the most deeply nested .ic-assets.json config file.
    /// Afterwards, within each config file, the latter config maps take precedense over former ones.
    pub(crate) fn get_config(self) -> anyhow::Result<Vec<AssetConfig>> {
        let mut assets_config = vec![];

        for mut asset_file in self.assets {
            // TODO: naming?
            let mut configs_in_paths = vec![];
            for cfg_file in &self.configs {
                if asset_file
                    .filepath
                    .starts_with(cfg_file.filepath.parent().unwrap())
                {
                    configs_in_paths.push(cfg_file.clone());
                }
            }

            for cfg_file in configs_in_paths {
                // FIXME: n^3 time complexity
                for configuration in &cfg_file.config_maps {
                    if let Ok(glob) = Glob::new(&configuration.r#match) {
                        if glob.compile_matcher().is_match(&asset_file.filepath) {
                            asset_file.matched_configurations.push(AssetConfig {
                                filepath: asset_file.filepath.clone(),
                                relative_filepath: asset_file.relative_filepath.clone(),
                                cache: configuration.cache.clone(),
                                headers: configuration.headers.clone(),
                            })
                        }
                    } else {
                        eprintln!(
                            "malformed glob pattern '{}' in {:?}",
                            &configuration.r#match, cfg_file.filepath
                        );
                    }
                }
            }

            let default_asset_config = AssetConfig::default()
                .with_path(&asset_file.filepath, &asset_file.relative_filepath);
            let asset_config = asset_file
                .matched_configurations
                .into_iter()
                .fold(default_asset_config, |acc, x| acc.merge(x));
            assets_config.push(asset_config);
        }

        Ok(assets_config)
    }
}

#[cfg(test)]
mod with_tempdir {

    use super::*;
    use serde_json::json;
    use std::fs::File;
    use std::io::Write;
    use std::str::FromStr;
    use tempfile::{Builder, TempDir};

    fn create_temporary_assets_directory(
        config_files: Option<HashMap<String, String>>,
        assets_count: usize,
    ) -> Result<TempDir, std::io::Error> {
        let assets_dir = Builder::new().prefix("assets").rand_bytes(5).tempdir()?;

        let _subdirs = ["css", "js", "nested/deep"]
            .map(|d| assets_dir.as_ref().join(d))
            .map(std::fs::create_dir_all);

        let _asset_files = [
            "index.html",
            "js/index.js",
            "js/index.map.js",
            "css/main.css",
            "css/stylish.css",
            "nested/the-thing.txt",
            "nested/deep/the-next-thing.toml",
        ]
        .iter()
        .map(|path| assets_dir.path().join(path))
        .take(assets_count)
        .for_each(|path| {
            File::create(path).unwrap();
        });

        let new_empty_config = |directory: &str| (directory.to_string(), "[]".to_string());
        let mut h = HashMap::from([
            new_empty_config(""),
            new_empty_config("css"),
            new_empty_config("js"),
            new_empty_config("nested"),
            new_empty_config("nested/deep"),
        ]);
        if let Some(cf) = config_files {
            h.extend(cf);
        }
        h.into_iter().for_each(|(dir, content)| {
            let path = assets_dir.path().join(dir).join(ASSETS_CONFIG_FILENAME);
            let mut file = File::create(path).unwrap();
            write!(file, "{}", content).unwrap();
        });

        Ok(assets_dir)
    }

    impl AssetConfig {
        fn test_default_with_path(assets_path: &Path, relative_filepath: &str) -> Self {
            Self {
                filepath: assets_path.join(relative_filepath),
                relative_filepath: PathBuf::from_str(relative_filepath).unwrap(),
                ..Self::default()
            }
        }
    }

    // ---
    #[test]
    fn match_only_nested_files() -> anyhow::Result<()> {
        let cfg = HashMap::from([(
            "nested".to_string(),
            r#"[{"match": "*", "cache": {"max_age": 333}}]"#.to_string(),
        )]);
        let assets_temp_dir = create_temporary_assets_directory(Some(cfg), 7).unwrap();
        let assets_dir = assets_temp_dir.path();
        assert_eq!(
            AssetsConfigMatcher::new(&assets_dir).get_config()?,
            vec![
                AssetConfig::test_default_with_path(assets_dir, "index.html"),
                AssetConfig::test_default_with_path(assets_dir, "css/main.css"),
                AssetConfig::test_default_with_path(assets_dir, "css/stylish.css"),
                AssetConfig::test_default_with_path(assets_dir, "js/index.js"),
                AssetConfig::test_default_with_path(assets_dir, "js/index.map.js"),
                AssetConfig {
                    filepath: assets_dir.join("nested/the-thing.txt"),
                    relative_filepath: PathBuf::from_str("nested/the-thing.txt").unwrap(),
                    cache: Some(CacheConfig { max_age: 333 }),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_dir.join("nested/deep/the-next-thing.toml"),
                    relative_filepath: PathBuf::from_str("nested/deep/the-next-thing.toml")
                        .unwrap(),
                    cache: Some(CacheConfig { max_age: 333 }),
                    ..Default::default()
                },
            ]
        );
        assets_temp_dir.close().unwrap();
        Ok(())
    }

    #[test]
    fn overriding_cache_rules() -> anyhow::Result<()> {
        let cfg = Some(HashMap::from([
            (
                "nested".to_string(),
                r#"[{"match": "*", "cache": {"max_age": 111}}]"#.to_string(),
            ),
            (
                "".to_string(),
                r#"[{"match": "*", "cache": {"max_age": 333}}]"#.to_string(),
            ),
        ]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 7).unwrap();
        let assets_path = assets_temp_dir.path();
        assert_eq!(
            AssetsConfigMatcher::new(&assets_path).get_config()?,
            vec![
                AssetConfig {
                    filepath: assets_path.join("index.html"),
                    relative_filepath: PathBuf::from_str("index.html").unwrap(),
                    cache: Some(CacheConfig { max_age: 333 },),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_path.join("css/main.css"),
                    relative_filepath: PathBuf::from_str("css/main.css").unwrap(),
                    cache: Some(CacheConfig { max_age: 333 },),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_path.join("css/stylish.css"),
                    relative_filepath: PathBuf::from_str("css/stylish.css").unwrap(),
                    cache: Some(CacheConfig { max_age: 333 },),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_path.join("js/index.js"),
                    relative_filepath: PathBuf::from_str("js/index.js").unwrap(),
                    cache: Some(CacheConfig { max_age: 333 },),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_path.join("js/index.map.js"),
                    relative_filepath: PathBuf::from_str("js/index.map.js").unwrap(),
                    cache: Some(CacheConfig { max_age: 333 },),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_path.join("nested/the-thing.txt"),
                    relative_filepath: PathBuf::from_str("nested/the-thing.txt").unwrap(),
                    cache: Some(CacheConfig { max_age: 111 },),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_path.join("nested/deep/the-next-thing.toml"),
                    relative_filepath: PathBuf::from_str("nested/deep/the-next-thing.toml")
                        .unwrap(),
                    cache: Some(CacheConfig { max_age: 111 },),
                    ..Default::default()
                },
            ],
        );
        Ok(())
    }

    #[test]
    fn overriding_headers() -> anyhow::Result<()> {
        let cfg = Some(HashMap::from([(
            "".to_string(),
            r#"
    [
      {
        "match": "index.html",
        "cache": {
          "max_age": 22
        },
        "headers": {
          "Content-Security-Policy": "add",
          "x-frame-options": "ALLHELLBREAKSLOOSE",
          "x-content-type-options": "nosniff"
        }
      },
      {
        "match": "*",
        "headers": {
          "Content-Security-Policy": "delete"
        }
      },
      {
        "match": "*",
        "headers": {
          "Some-Other-Policy": "add"
        }
      },
      {
        "match": "*",
        "cache": {
          "max_age": 88
        },
        "headers": {
          "x-xss-protection": 1,
          "x-frame-options": "SAMEORIGIN"
        }
      }
    ]
    "#
            .to_string(),
        )]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 1).unwrap();
        let assets_path = assets_temp_dir.path();
        assert_eq!(
            AssetsConfigMatcher::new(&assets_path).get_config()?,
            vec![AssetConfig {
                filepath: assets_path.join("index.html"),
                relative_filepath: PathBuf::from_str("index.html").unwrap(),
                headers: Some(HashMap::from([
                    ("Content-Security-Policy".to_string(), json!("delete")),
                    ("Some-Other-Policy".to_string(), json!("add")),
                    ("x-xss-protection".to_string(), json!(1)),
                    ("x-frame-options".to_string(), json!("SAMEORIGIN")),
                    ("x-content-type-options".to_string(), json!("nosniff")),
                ])),
                cache: Some(CacheConfig { max_age: 88 })
            }]
        );
        Ok(())
    }

    #[test]
    fn stringify_headers() -> anyhow::Result<()> {
        let cfg = Some(HashMap::from([(
            "".to_string(),
            r#"
    [
      {
        "match": "*",
        "headers": {
          "array": [
            {"map": "https://internetcomputer.org"},
            {"null": null},
            {"number": 3.14},
            {"number-int": 888},
            {"string": "well"},
            {"bool": true}
          ]
        }
      }
    ]
    "#
            .to_string(),
        )]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 1).unwrap();
        let assets_path = assets_temp_dir.path();
        let x = AssetsConfigMatcher::new(&assets_path).get_config().unwrap();
        assert_eq!(
            serde_json::to_string_pretty(&x).unwrap(),
            r#"[
  {
    "filepath": "{{path}}/index.html",
    "relative_filepath": "index.html",
    "cache": null,
    "headers": {
      "array": [
        {
          "map": "https://internetcomputer.org"
        },
        {
          "null": null
        },
        {
          "number": 3.14
        },
        {
          "number-int": 888
        },
        {
          "string": "well"
        },
        {
          "bool": true
        }
      ]
    }
  }
]"#
            .to_string()
            .replace("{{path}}", assets_path.to_str().unwrap())
        );
        Ok(())
    }

    #[test]
    fn prioritization() -> anyhow::Result<()> {
        // 1. the most deeply nested config file takes precedens over the one in parent dir
        // 2. order of rules withing file matters - last rule in config file takes precedens over the first one
        let cfg = Some(HashMap::from([
            (
                "".to_string(),
                r#"[
        {"match": "nested/**/*", "cache": {"max_age": 900}},
        {"match": "nested/deep/*", "cache": {"max_age": 800}},
        {"match": "nested/**/*.toml","cache": {"max_age": 700}}
    ]"#
                .to_string(),
            ),
            (
                "nested".to_string(),
                r#"[
        {"match": "the-thing.txt", "cache": {"max_age": 600}},
        {"match": "*.txt", "cache": {"max_age": 500}},
        {"match": "*", "cache": {"max_age": 400}}
    ]"#
                .to_string(),
            ),
            (
                "nested/deep".to_string(),
                r#"[
        {"match": "**/*", "cache": {"max_age": 300}},
        {"match": "*", "cache": {"max_age": 200}},
        {"match": "*.toml", "cache": {"max_age": 100}}
    ]"#
                .to_string(),
            ),
        ]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 7).unwrap();
        let assets_path = assets_temp_dir.path();
        assert_eq!(
            AssetsConfigMatcher::new(&assets_path).get_config()?,
            vec![
                AssetConfig::test_default_with_path(assets_path, "index.html"),
                AssetConfig::test_default_with_path(assets_path, "css/main.css"),
                AssetConfig::test_default_with_path(assets_path, "css/stylish.css"),
                AssetConfig::test_default_with_path(assets_path, "js/index.js"),
                AssetConfig::test_default_with_path(assets_path, "js/index.map.js"),
                AssetConfig {
                    filepath: assets_path.join("nested/the-thing.txt"),
                    relative_filepath: PathBuf::from_str("nested/the-thing.txt").unwrap(),
                    cache: Some(CacheConfig { max_age: 400 }),
                    ..Default::default()
                },
                AssetConfig {
                    filepath: assets_path.join("nested/deep/the-next-thing.toml"),
                    relative_filepath: PathBuf::from_str("nested/deep/the-next-thing.toml")
                        .unwrap(),
                    cache: Some(CacheConfig { max_age: 100 }),
                    ..Default::default()
                },
            ]
        );
        assets_temp_dir.close().unwrap();
        Ok(())
    }

    #[test]
    fn no_content_config_file() -> anyhow::Result<()> {
        let cfg = Some(HashMap::from([
            ("".to_string(), "".to_string()),
            ("css".to_string(), "".to_string()),
            ("js".to_string(), "".to_string()),
            ("nested".to_string(), "".to_string()),
            ("nested/deep".to_string(), "".to_string()),
        ]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 7).unwrap();
        let assets_path = assets_temp_dir.path();
        assert_eq!(
            AssetsConfigMatcher::new(&assets_path).get_config()?,
            vec![
                AssetConfig::test_default_with_path(assets_path, "index.html"),
                AssetConfig::test_default_with_path(assets_path, "css/main.css"),
                AssetConfig::test_default_with_path(assets_path, "css/stylish.css"),
                AssetConfig::test_default_with_path(assets_path, "js/index.js"),
                AssetConfig::test_default_with_path(assets_path, "js/index.map.js"),
                AssetConfig::test_default_with_path(assets_path, "nested/the-thing.txt"),
                AssetConfig::test_default_with_path(assets_path, "nested/deep/the-next-thing.toml"),
            ]
        );
        assets_temp_dir.close().unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod config_generation {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn empty() -> anyhow::Result<()> {
        let c = AssetsConfigMatcher {
            assets: vec![],
            configs: vec![],
            assets_dir: PathBuf::from_str("").unwrap(),
        };
        assert_eq!(c.get_config()?, vec![]);
        Ok(())
    }

    #[test]
    fn no_assets() -> anyhow::Result<()> {
        let c = AssetsConfigMatcher {
            assets: vec![],
            assets_dir: PathBuf::from_str("").unwrap(),
            configs: vec![AssetsHeadersConfigFile {
                filepath: PathBuf::new(),
                config_maps: vec![AssetsHeadersConfiguration {
                    r#match: "*".to_string(),
                    cache: Some(CacheConfig { max_age: 11111 }),
                    headers: None,
                }],
            }],
        };
        assert_eq!(c.get_config()?, vec![]);
        Ok(())
    }

    #[test]
    fn no_config() -> anyhow::Result<()> {
        let assets_dir = Path::new("/something/");
        let asset = Path::new("index.js");
        let c = AssetsConfigMatcher {
            assets: vec![AssetFile {
                filepath: assets_dir.join(asset),
                relative_filepath: asset.to_path_buf(),
                matched_configurations: vec![],
            }],
            configs: vec![],
            assets_dir: assets_dir.to_path_buf(),
        };
        assert_eq!(
            c.get_config()?,
            vec![AssetConfig {
                filepath: assets_dir.join(asset),
                relative_filepath: asset.to_path_buf(),
                headers: None,
                cache: None
            }]
        );
        Ok(())
    }

    #[test]
    fn glob_match_everything() -> anyhow::Result<()> {
        let hm = HashMap::from([
            ("some-header-name".to_string(), json!("some-header-value")),
            ("permissions-policy".to_string(), json!("add")),
            ("funky-policy".to_string(), json!("roll")),
        ]);
        let assets_dir = Path::new("/something/");
        let asset = Path::new("index.js");
        let c = AssetsConfigMatcher {
            assets_dir: assets_dir.to_path_buf(),
            assets: vec![AssetFile {
                filepath: assets_dir.join(asset),
                relative_filepath: asset.to_path_buf(),
                matched_configurations: vec![],
            }],
            configs: vec![AssetsHeadersConfigFile {
                filepath: assets_dir.to_path_buf(),
                config_maps: vec![AssetsHeadersConfiguration {
                    r#match: "*".to_string(),
                    cache: Some(CacheConfig { max_age: 11111 }),
                    headers: Some(hm.clone()),
                }],
            }],
        };
        assert_eq!(
            c.get_config()?,
            vec![AssetConfig {
                filepath: assets_dir.join(asset).to_path_buf(),
                relative_filepath: asset.to_path_buf(),
                cache: Some(CacheConfig { max_age: 11111 }),
                headers: Some(hm)
            }]
        );
        Ok(())
    }

    #[test]
    fn bad_glob_pattern() -> anyhow::Result<()> {
        let hm = HashMap::new();
        let assets_dir = Path::new("/something/");
        let asset = Path::new("index.js");
        let c = AssetsConfigMatcher {
            assets_dir: assets_dir.to_path_buf(),
            assets: vec![AssetFile {
                filepath: assets_dir.join(asset),
                relative_filepath: asset.to_path_buf(),
                matched_configurations: vec![],
            }],
            configs: vec![AssetsHeadersConfigFile {
                filepath: assets_dir.to_path_buf(),
                config_maps: vec![
                    AssetsHeadersConfiguration {
                        r#match: "\\".to_string(),
                        cache: Some(CacheConfig { max_age: 11111 }),
                        headers: Some(hm.clone()),
                    },
                    AssetsHeadersConfiguration {
                        r#match: "[".to_string(),
                        cache: Some(CacheConfig { max_age: 11111 }),
                        headers: Some(hm.clone()),
                    },
                    AssetsHeadersConfiguration {
                        r#match: "{".to_string(),
                        cache: Some(CacheConfig { max_age: 11111 }),
                        headers: Some(hm.clone()),
                    },
                ],
            }],
        };
        assert_eq!(
            c.get_config()?,
            vec![AssetConfig {
                filepath: assets_dir.join(asset).to_path_buf(),
                relative_filepath: asset.to_path_buf(),
                ..Default::default()
            }]
        );
        Ok(())
    }
}
