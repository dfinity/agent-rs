use anyhow::{bail, Context};
use derivative::Derivative;
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cell::{RefCell, RefMut},
    collections::HashMap,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};

const ASSETS_CONFIG_FILENAME: &str = ".ic-assets.json";

thread_local! {
    // There is no simple way to pass state into serde deserializer. Using this as a walkaround.
    // https://stackoverflow.com/questions/54052495/mock-instance-inside-serde-implementation
    static CURRENTLY_PROCESSED_ASSETS_DIRECTORY: RefCell<PathBuf> = RefCell::new(PathBuf::new());
}

pub(crate) type HeadersConfig = HashMap<String, Value>;
type Map = HashMap<PathBuf, Arc<AssetConfigTreeNode>>;

#[derive(Deserialize, Serialize, Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CacheConfig {
    pub(crate) max_age: u64,
}

#[derive(Deserialize, Clone, Derivative)]
#[derivative(Debug)]
struct AssetConfigRule {
    #[serde(deserialize_with = "string_to_glob")]
    #[derivative(Debug(format_with = "fmt_glob_field"))]
    r#match: GlobMatcher,
    cache: Option<CacheConfig>,
    #[serde(default, deserialize_with = "deser_headers")]
    headers: Maybe<HeadersConfig>,
}

#[derive(Deserialize, Clone, Debug)]
enum Maybe<T> {
    Null,
    Absent,
    Value(T),
}

impl<T> Default for Maybe<T> {
    fn default() -> Self {
        Self::Absent
    }
}

impl Into<Option<HeadersConfig>> for Maybe<HeadersConfig> {
    fn into(self) -> Option<HeadersConfig> {
        match self {
            Maybe::Null => None,
            Maybe::Absent => Some(HashMap::new()),
            Maybe::Value(v) => Some(v),
        }
    }
}

fn deser_headers<'de, D>(deserializer: D) -> Result<Maybe<HeadersConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::value::Value::deserialize(deserializer)? {
        Value::Object(v) => Ok(Maybe::Value(
            v.into_iter().collect::<HashMap<String, Value>>(),
        )),
        Value::Null => Ok(Maybe::Null),
        _ => Err(serde::de::Error::custom(
            "wrong data format for field `headers` (only map or null are allowed)",
        )),
    }
}

fn fmt_glob_field(
    field: &GlobMatcher,
    formatter: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    formatter.write_str(field.glob().glob())?;
    Ok(())
}

fn string_to_glob<'de, D>(deserializer: D) -> Result<GlobMatcher, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let dir = CURRENTLY_PROCESSED_ASSETS_DIRECTORY.with(|book| book.borrow().clone());

    if let Value::String(glob) = serde_json::value::Value::deserialize(deserializer)? {
        if let Ok(glob) = Glob::new(&format!("{}/{}", dir.to_str().unwrap(), &glob)) {
            Ok(glob.compile_matcher())
        } else {
            Err(serde::de::Error::custom(
                "the value in `match` field is not a valid glob pattern",
            ))
        }
    } else {
        Err(serde::de::Error::custom(
            "the value in `match` field is not a string",
        ))
    }
}

impl AssetConfigRule {
    fn applies(&self, canonical_path: &Path) -> bool {
        self.r#match.is_match(canonical_path)
    }
}

impl AssetConfig {
    fn merge(mut self, other: Self) -> Self {
        if let Some(c) = other.cache {
            self.cache = Some(c);
        };
        match (self.headers.as_mut(), other.headers) {
            (Some(sh), Some(oh)) => sh.extend(oh),
            (_, oh) => self.headers = oh,
        };
        self
    }
}

#[derive(Debug)]
pub(crate) struct AssetSourceDirectoryConfiguration {
    config_map: Map,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct AssetConfig {
    pub(crate) cache: Option<CacheConfig>,
    pub(crate) headers: Option<HeadersConfig>,
}

impl Default for AssetConfig {
    fn default() -> Self {
        Self {
            headers: Some(HashMap::new()),
            cache: Some(CacheConfig::default()),
        }
    }
}

#[derive(Debug, Default)]
struct AssetConfigTreeNode {
    pub parent: Option<Arc<AssetConfigTreeNode>>,
    pub rules: Vec<AssetConfigRule>,
}

impl AssetSourceDirectoryConfiguration {
    pub(crate) fn load(root_dir: &Path) -> anyhow::Result<Self> {
        let mut config_map = HashMap::new();
        AssetConfigTreeNode::load(None, &root_dir, &mut config_map)?;
        Ok(Self { config_map })
    }

    pub(crate) fn get_asset_config(&self, canonical_path: &Path) -> anyhow::Result<AssetConfig> {
        let parent_dir = canonical_path.parent().context(format!(
            "unable to get the parent directory for asset path: {:?}",
            canonical_path
        ))?;
        Ok(self
            .config_map
            .get(parent_dir)
            .context(format!(
                "unable to find default config for following path: {:?}",
                parent_dir
            ))?
            .get_config(canonical_path))
    }
}

impl AssetConfigTreeNode {
    fn load(
        parent: Option<Arc<AssetConfigTreeNode>>,
        dir: &Path,
        configs: &mut HashMap<PathBuf, Arc<AssetConfigTreeNode>>,
    ) -> anyhow::Result<()> {
        let mut rules = vec![];
        let config_path = dir.join(ASSETS_CONFIG_FILENAME);
        if let Ok(file) = File::open(&config_path) {
            let reader = BufReader::new(file);
            CURRENTLY_PROCESSED_ASSETS_DIRECTORY.with(|book| {
                let x = book.borrow_mut();
                let mut path = RefMut::map(x, |p| p);
                *path = dir.to_path_buf();
            });

            match serde_json::from_reader(reader) {
                Ok(mut v) => rules.append(&mut v),
                Err(e) => bail!(
                    "ERR: {} - {}",
                    e.to_string(),
                    &config_path.to_str().unwrap()
                ),
            }
        }

        let config_tree = Self { parent, rules };
        let parent_ref = Arc::new(config_tree);
        configs.insert(dir.to_path_buf(), parent_ref.clone());
        for f in std::fs::read_dir(&dir)
            .with_context(|| format!("Unable to read directory {:?}", &dir))?
            .filter_map(|x| x.ok())
            .filter(|x| x.file_type().unwrap().is_dir())
        {
            Self::load(Some(parent_ref.clone()), &f.path(), configs)?;
        }
        Ok(())
    }

    fn get_config(&self, canonical_path: &Path) -> AssetConfig {
        let base_config = match &self.parent {
            Some(parent) => parent.get_config(&canonical_path),
            None => AssetConfig::default(),
        };
        self.rules
            .iter()
            .cloned()
            .filter(|rule| rule.applies(canonical_path))
            .fold(base_config, |acc, x| acc.merge(x.into()))
    }
}

impl From<AssetConfigRule> for AssetConfig {
    fn from(AssetConfigRule { cache, headers, .. }: AssetConfigRule) -> Self {
        Self {
            cache,
            headers: headers.into(),
        }
    }
}

#[cfg(test)]
mod with_tempdir {

    use super::*;
    use std::io::Write;
    use std::{collections::BTreeMap, fs::File};
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

    #[test]
    fn match_only_nested_files() -> anyhow::Result<()> {
        let cfg = HashMap::from([(
            "nested".to_string(),
            r#"[{"match": "*", "cache": {"max_age": 333}}]"#.to_string(),
        )]);
        let assets_temp_dir = create_temporary_assets_directory(Some(cfg), 7).unwrap();
        let assets_dir = assets_temp_dir.path();

        let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir)?;
        for f in ["nested/the-thing.txt", "nested/deep/the-next-thing.toml"] {
            assert_eq!(
                assets_config.get_asset_config(assets_dir.join(f).as_path())?,
                AssetConfig {
                    cache: Some(CacheConfig { max_age: 333 }),
                    headers: Some(HashMap::new()),
                }
            );
        }
        for f in [
            "index.html",
            "js/index.js",
            "js/index.map.js",
            "css/main.css",
            "css/stylish.css",
        ] {
            assert_eq!(
                assets_config.get_asset_config(assets_dir.join(f).as_path())?,
                AssetConfig::default()
            );
        }

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
        let assets_dir = assets_temp_dir.path();

        let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir)?;
        for f in ["nested/the-thing.txt", "nested/deep/the-next-thing.toml"] {
            assert_eq!(
                assets_config.get_asset_config(assets_dir.join(f).as_path())?,
                AssetConfig {
                    cache: Some(CacheConfig { max_age: 111 }),
                    headers: Some(HashMap::new()),
                }
            );
        }
        for f in [
            "index.html",
            "js/index.js",
            "js/index.map.js",
            "css/main.css",
            "css/stylish.css",
        ] {
            assert_eq!(
                assets_config.get_asset_config(assets_dir.join(f).as_path())?,
                AssetConfig {
                    cache: Some(CacheConfig { max_age: 333 }),
                    ..Default::default()
                }
            );
        }

        Ok(())
    }

    #[test]
    fn overriding_headers() -> anyhow::Result<()> {
        use serde_json::Value::*;
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
          "x-frame-options": "NONE",
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
        let assets_dir = assets_temp_dir.path();
        let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir)?;
        let parsed_asset_config =
            assets_config.get_asset_config(assets_dir.join("index.html").as_path())?;
        let expected_asset_config = AssetConfig {
            cache: Some(CacheConfig { max_age: 88 }),
            headers: Some(HashMap::from([
                (
                    "x-content-type-options".to_string(),
                    String("nosniff".to_string()),
                ),
                (
                    "x-frame-options".to_string(),
                    String("SAMEORIGIN".to_string()),
                ),
                ("Some-Other-Policy".to_string(), String("add".to_string())),
                (
                    "Content-Security-Policy".to_string(),
                    String("delete".to_string()),
                ),
                (
                    "x-xss-protection".to_string(),
                    Number(serde_json::Number::from(1).into()),
                ),
            ])),
        };

        assert_eq!(parsed_asset_config.cache, expected_asset_config.cache);
        assert_eq!(
            parsed_asset_config
                .headers
                .unwrap()
                .iter()
                // keys are sorted
                .collect::<BTreeMap<_, _>>(),
            expected_asset_config
                .headers
                .unwrap()
                .iter()
                .collect::<BTreeMap<_, _>>(),
        );

        Ok(())
    }

    //     #[test]
    //     fn stringify_different_json_types_in_headers() -> anyhow::Result<()> {
    //         let cfg = Some(HashMap::from([(
    //             "".to_string(),
    //             r#"
    //         [
    //           {
    //             "match": "*",
    //             "headers": {
    //                 "map": {"homepage": "https://internetcomputer.org"},
    //                 "null": null,
    //                 "number": 3.14,
    //                 "number-int": 888,
    //                 "string": "well",
    //                 "bool": true,
    //                 "array": ["a", "b", "c"]
    //             }
    //           }
    //         ]
    //         "#
    //             .to_string(),
    //         )]));
    //         let assets_temp_dir = create_temporary_assets_directory(cfg, 1).unwrap();
    //         let assets_dir = assets_temp_dir.path();
    //         let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir)?;
    //         let asset_config = assets_config.get_asset_config(assets_dir.join("index.html").as_path());

    //         assert_eq!(
    //             serde_json::to_string_pretty(&asset_config)?,
    //             String::from(
    //                 r#"{
    //   "cache": {
    //     "max_age": 0
    //   },
    //   "headers": {
    //     "null": null,
    //     "bool": true,
    //     "map": {
    //       "homepage": "https://internetcomputer.org"
    //     },
    //     "number": 3.14,
    //     "number-int": 888,
    //     "array": [
    //       "a",
    //       "b",
    //       "c"
    //     ],
    //     "string": "well"
    //   }
    // }"#
    //             )
    //         );
    //         Ok(())
    //     }

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
        let assets_dir = assets_temp_dir.path();

        println!("ff");
        let assets_config = dbg!(AssetSourceDirectoryConfiguration::load(assets_dir))?;
        for f in [
            "index.html",
            "js/index.js",
            "js/index.map.js",
            "css/main.css",
            "css/stylish.css",
        ] {
            assert_eq!(
                assets_config.get_asset_config(assets_dir.join(f).as_path())?,
                AssetConfig::default()
            );
        }

        assert_eq!(
            assets_config.get_asset_config(assets_dir.join("nested/the-thing.txt").as_path())?,
            AssetConfig {
                cache: Some(CacheConfig { max_age: 400 }),
                ..Default::default()
            },
        );
        assert_eq!(
            assets_config
                .get_asset_config(assets_dir.join("nested/deep/the-next-thing.toml").as_path())?,
            AssetConfig {
                cache: Some(CacheConfig { max_age: 100 }),
                ..Default::default()
            },
        );

        Ok(())
    }

    #[test]
    fn no_content_config_file() {
        let cfg = Some(HashMap::from([
            ("".to_string(), "".to_string()),
            ("css".to_string(), "".to_string()),
            ("js".to_string(), "".to_string()),
            ("nested".to_string(), "".to_string()),
            ("nested/deep".to_string(), "".to_string()),
        ]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 0).unwrap();
        let assets_dir = assets_temp_dir.path();
        let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir);
        assert_eq!(
            assets_config.err().unwrap().to_string(),
            format!(
                "ERR: EOF while parsing a value at line 1 column 0 - {}",
                assets_dir.join(ASSETS_CONFIG_FILENAME).to_str().unwrap()
            )
        );
    }

    #[test]
    fn invalid_json_config_file() {
        let cfg = Some(HashMap::from([("".to_string(), "[[[{{{".to_string())]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 0).unwrap();
        let assets_dir = assets_temp_dir.path();
        let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir);
        assert_eq!(
            assets_config.err().unwrap().to_string(),
            format!(
                "ERR: key must be a string at line 1 column 5 - {}",
                assets_dir.join(ASSETS_CONFIG_FILENAME).to_str().unwrap()
            )
        );
    }

    #[test]
    fn invalid_glob_pattern() {
        let cfg = Some(HashMap::from([(
            "".to_string(),
            r#"[
        {"match": "{{{\\\", "cache": {"max_age": 900}},
    ]"#
            .to_string(),
        )]));
        let assets_temp_dir = create_temporary_assets_directory(cfg, 0).unwrap();
        let assets_dir = assets_temp_dir.path();
        let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir);
        assert_eq!(
            assets_config.err().unwrap().to_string(),
            format!(
                "ERR: the value in `match` field is not a valid glob pattern at line 2 column 30 - {}",
                assets_dir.join(ASSETS_CONFIG_FILENAME).to_str().unwrap()
            )
        );
    }

    #[test]
    fn invalid_asset_path() -> anyhow::Result<()> {
        let cfg = Some(HashMap::new());
        let assets_temp_dir = create_temporary_assets_directory(cfg, 0).unwrap();
        let assets_dir = assets_temp_dir.path();
        let assets_config = AssetSourceDirectoryConfiguration::load(assets_dir)?;
        assert_eq!(
            assets_config.get_asset_config(assets_dir.join("doesnt.exists").as_path())?,
            AssetConfig::default()
        );
        Ok(())
    }
}
