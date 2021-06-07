use anyhow::{anyhow, Result};
use cargo_metadata::{Package, Version};
use clap::Clap;
use git2::{Commit, DescribeFormatOptions, Repository, RepositoryState};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml_parse::{walk, SyntaxNode, SyntaxToken, TomlKind};

#[derive(Clap, Debug)]
struct Options {
    /// If true, will print out what would be done, but not do it.
    #[clap(long = "dry-run")]
    dry_run: bool,

    /// Skip creating a git commit (will still output all messages and logs).
    #[clap(long = "skip-git")]
    skip_git: bool,

    /// If true, will ignore status and branch of the repo.
    #[clap(long = "force")]
    force: bool,

    /// The release tag, by default the most recent tag is used if it starts
    /// with `release-`.
    #[clap(long = "release")]
    tag: Option<String>,

    /// A list of forced patch or minor for packages. This will bypass automatic
    /// detection of changes. The format is `--package name=<1.2.3|minor|patch>`.
    #[clap(long = "package")]
    package: Vec<String>,
}

fn check_repo_status(repo: &Repository) -> Result<()> {
    if RepositoryState::Clean != repo.state() {
        return Err(anyhow!(
            "The repo is not in a clean state. State: {:?}",
            repo.state()
        ));
    }

    for s in repo.statuses(None)?.iter() {
        let status = s.status();

        if status.is_ignored() {
            continue;
        }
        if status.is_empty() {
            continue;
        }

        return Err(anyhow!("The repo has local changes. Cannot proceed."));
    }

    Ok(())
}

fn package_changed(
    repo: &Repository,
    workspace_root: &Path,
    package_root: &Path,
    commit: &Commit,
) -> Result<bool> {
    let commit_tree = commit.tree()?;
    let parent_tree = commit.parent(0)?.tree()?;

    let diff = repo.diff_tree_to_tree(Some(&parent_tree), Some(&commit_tree), None)?;

    for delta in diff.deltas() {
        let old_path = workspace_root.join(delta.old_file().path().unwrap());
        let new_path = workspace_root.join(delta.new_file().path().unwrap());

        if old_path.starts_with(package_root) || new_path.starts_with(package_root) {
            return Ok(true);
        }
    }

    Ok(false)
}

type ApplyChangeFn = dyn FnMut(bool) -> std::io::Result<()>;

type VersionMap = HashMap<String, (Package, Version)>;

#[derive(Debug)]
struct PackageDependency {
    pub name: String,
    pub version_node: SyntaxToken,
}

fn get_version_value_from_table(node: &SyntaxNode) -> Option<SyntaxToken> {
    walk(node)
        .filter_map(|el| {
            let n = el.as_node()?;
            if n.kind() == TomlKind::KeyValue
                && n.first_child()?.first_token()?.to_string() == "version"
            {
                // Get the ident.
                walk(&n.last_child()?)
                    .filter(|x| x.kind() == TomlKind::Ident)
                    .take(1)
                    .last()
                    .map(|x| x.into_token().unwrap())
            } else {
                None
            }
        })
        .take(1)
        .collect::<Vec<SyntaxToken>>()
        .pop()
}

fn package_dependencies_from_dependencies_section(
    node: &SyntaxNode,
) -> Result<Vec<PackageDependency>> {
    Ok(node
        .children()
        // Skip heading.
        .skip(1)
        .filter_map(|x| {
            if x.kind() != TomlKind::KeyValue {
                return None;
            }

            let key = x.first_token().unwrap();
            let value = x.children().last().unwrap().first_child().unwrap();

            let version_node: SyntaxToken = match value.kind() {
                TomlKind::InlineTable => get_version_node_from_table(&value)?,
                TomlKind::Str => {
                    // Get the ident
                    walk(&value)
                        .filter(|x| x.kind() == TomlKind::Ident)
                        .take(1)
                        .last()
                        .unwrap()
                        .into_token()
                        .unwrap()
                }
                _ => return None,
            };

            Some(PackageDependency {
                name: key.to_string(),
                version_node,
            })
        })
        .collect())
}

fn package_dependencies_from_dependency_dot(node: &SyntaxNode) -> Option<Vec<PackageDependency>> {
    let title = node.first_token()?.next_sibling_or_token()?.to_string();
    let name = title.split_at("dependencies.".len()).1.to_string();
    let version_node = get_version_value_from_table(node)?;
    Some(vec![PackageDependency { name, version_node }])
}

fn update_manifest(package_name: &str, version_map: &VersionMap) -> Result<Box<ApplyChangeFn>> {
    let (package, version) = &version_map.get(package_name).unwrap();
    eprintln!("   {:20} {} => {}", package_name, package.version, version);
    let cargo_path = package.manifest_path.as_path().as_os_str().to_os_string();
    let mut cargo_toml = std::fs::read_to_string(&cargo_path)?;

    let parsed = toml_parse::parse_it(&cargo_toml)?;
    let root = parsed.syntax();

    let mut changes: Vec<(usize, usize, String)> = Vec::new();

    // Find the `[package]` object and the key pair for version = ...,
    // then add a change to the vector above to update the value to the new version.
    walk(&root)
        .filter_map(|element| {
            if element.kind() != TomlKind::KeyValue || element.parent().is_none() {
                return None;
            }

            // Check that it's inside the package object.
            let parent = element.parent().unwrap();
            if parent.kind() != TomlKind::Table {
                return None;
            }

            if parent
                .first_token()
                .unwrap()
                .next_sibling_or_token()
                .unwrap()
                .to_string()
                != "package"
            {
                return None;
            }

            let node = element.as_node().unwrap();
            let key = node.first_token().unwrap();
            if key.text() != "version" {
                None
            } else {
                let value = node
                    .children()
                    .nth(1)
                    .unwrap()
                    .first_token()
                    .unwrap()
                    .next_sibling_or_token()
                    .unwrap();
                Some((key, value))
            }
        })
        .take(1)
        .for_each(|(_k, v)| {
            let range = v.text_range();
            let start: usize = range.start().into();
            let end: usize = range.end().into();
            changes.push((start, end, version.to_string()));
        });

    // Find the location of all version = ... of dependencies. This is a bit more touchy.
    // This strategy is O(n^m) where `m` is the number of elements we look for, basically
    // 4 right now, and `n` is the number of nodes in the graph. We don't actually care
    // about performance but keep in mind this might be very slow.
    walk(&root)
        .filter_map(|element| {
            // Find all tables that have name `dependencies` or `dev-dependencies`.
            if element.kind() == TomlKind::Table {
                let node = element.as_node()?;
                let title = node.first_token()?.next_sibling_or_token()?.to_string();

                if title.starts_with("dependencies.") {
                    package_dependencies_from_dependency_dot(node).map(Result::Ok)
                } else if title == "dependencies" {
                    Some(package_dependencies_from_dependencies_section(node))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .map(|x| Ok(x?))
        .collect::<Result<Vec<Vec<PackageDependency>>>>()?
        .into_iter()
        .flatten()
        .for_each(|pnv: PackageDependency| {
            if let Some((_pkg, version)) = version_map.get(&pnv.name) {
                // Add a change to the version number of this.
                // This might be a shorter version so we need to check for that.
                let short = format!("{}.{}", version.major, version.minor);
                let long = version.to_string();

                // Count number of dots... Easiest way to know.
                let new_version = match pnv
                    .version_node
                    .to_string()
                    .chars()
                    .filter(|x| *x == '.')
                    .count()
                {
                    0 | 1 => short,
                    _ => long,
                };

                let range = pnv.version_node.text_range();
                let start: usize = range.start().into();
                let end: usize = range.end().into();
                changes.push((start, end, new_version));
            }
        });

    // Sort and apply all changes and return the save function.
    changes.sort_by(|a, b| b.1.cmp(&a.1));
    for (start, end, str) in changes {
        cargo_toml.replace_range(start..end, &str);
    }

    let version = version.clone();
    let cargo_path = cargo_path;
    Ok(Box::new(move |dry_run| {
        if dry_run {
            println!(
                "  Would update manifest '{}' to version {} (but dry-run is on)",
                cargo_path.to_string_lossy(),
                version
            );
            Ok(())
        } else {
            // Update the cargo file.
            std::fs::write(&cargo_path, &cargo_toml)
        }
    }))
}

fn main() -> Result<()> {
    let opts: Options = Options::parse();
    eprintln!("{:#?}\n", opts);

    let repo = Repository::open(std::env::current_dir()?)?;

    if !opts.force {
        check_repo_status(&repo)?;
    }

    eprintln!("Finding the last release tag...");
    let tag = if let Some(tag) = opts.tag {
        tag
    } else {
        let d = repo.describe(&git2::DescribeOptions::new().describe_tags())?;
        let tag = d.format(Some(&DescribeFormatOptions::new().abbreviated_size(0)))?;
        if !tag.starts_with("release-") {
            return Err(anyhow!("Invalid release tag name: {}", tag));
        }
        tag
    };
    eprintln!("Found '{}'...", tag);

    eprintln!("Checking all packages...");
    let metadata = cargo_metadata::MetadataCommand::new()
        .features(cargo_metadata::CargoOpt::AllFeatures)
        .exec()?;

    eprintln!(
        "  Found {} packages ({} workspace member)...",
        metadata.packages.len(),
        metadata.workspace_members.len()
    );

    eprintln!("Checking git history to see the changes...");
    let mut revwalk = repo.revwalk()?;
    let revspec = repo.revparse(&tag)?;
    revwalk.push_head()?;
    revwalk.hide(revspec.from().unwrap().id())?;

    let mut packages: HashMap<PathBuf, Package> = HashMap::new();
    let mut packages_minor: HashMap<String, Package> = HashMap::new();
    let mut packages_patch: HashMap<String, Package> = HashMap::new();

    for package in metadata.packages {
        if !metadata.workspace_members.contains(&package.id) {
            continue;
        }

        if package.version.eq(&Version::from_str("0.0.0")?) {
            eprintln!("Skipping '{}' because it's version 0.0.0...", package.name);
            continue;
        }

        let cargo_toml: PathBuf = package.manifest_path.to_path_buf().into();
        packages.insert(cargo_toml.parent().unwrap().to_path_buf(), package);
    }

    let workspace_root: PathBuf = metadata.workspace_root.into();

    for rev in revwalk {
        let oid = rev?;
        let commit = repo.find_commit(oid)?;
        if oid == revspec.from().unwrap().id() {
            break;
        }

        let message = commit.message().unwrap_or("");
        if message.starts_with("feat") {
            for (root, package) in &packages {
                if package_changed(&repo, &workspace_root, root, &commit)? {
                    packages_minor.insert(package.name.clone(), package.clone());
                }
            }
        } else if message.starts_with("feat") {
            for (root, package) in &packages {
                if package_changed(&repo, &workspace_root, root, &commit)? {
                    packages_patch.insert(package.name.clone(), package.clone());
                }
            }
        }
    }

    // Increment the patch of all packages that depend on a package that's going to be updated.
    let mut changed = true;
    while changed {
        changed = false;

        for (_root, package) in packages.iter() {
            for d in &package.dependencies {
                if packages_minor.values().any(|p| p.name == d.name) {
                    if packages_patch
                        .insert(package.name.clone(), package.clone())
                        .is_none()
                    {
                        changed = true;
                    }
                } else if packages_patch.values().any(|p| p.name == d.name)
                    && packages_patch
                        .insert(package.name.clone(), package.clone())
                        .is_none()
                {
                    changed = true;
                }
            }
        }
    }

    for k in packages_minor.keys() {
        packages_patch.remove(k);
    }

    let mut version_map = VersionMap::new();
    for (name, package) in packages_minor.iter() {
        let mut v = package.version.clone();
        v.increment_minor();
        version_map.insert(name.clone(), (package.clone(), v));
    }
    for (name, package) in packages_patch.iter() {
        let mut v = package.version.clone();
        v.increment_patch();
        version_map.insert(name.clone(), (package.clone(), v));
    }

    for patch in opts.package {
        // Split using `=`.
        let c: Vec<_> = patch.split('=').take(2).collect();
        let name = c[0].to_string();
        let version = Version::from_str(c[1])?;

        version_map
            .entry(name.to_string())
            .and_modify(|e| e.1 = version);
    }

    eprintln!("\nVersions will be updated to:");

    // Find all update functions and if any of them failed, bail out without doing any changes.
    let changes: Result<Vec<Box<ApplyChangeFn>>> = packages_minor
        .iter()
        .chain(packages_patch.iter())
        .map(|(name, _package)| update_manifest(name, &version_map))
        .collect();

    eprintln!("\nApplying changes...");
    for mut ch in changes? {
        ch(opts.dry_run)?;
    }

    eprintln!("");

    let commit_message = format!(
        "chore: release of ic-agent\n\n{}",
        version_map
            .iter()
            .map(|(name, (pkg, v))| {
                format!("{}: {} => {}", name, pkg.version.to_string(), v.to_string())
            })
            .collect::<Vec<String>>()
            .join("\n")
    );
    eprintln!(
        "Will create a commit with message:\n===\n{}\n===\n",
        commit_message
    );

    if opts.skip_git || opts.dry_run {
        eprintln!("Skipping creating a git commit...");
    } else {
        let mut index = repo.index()?;
        index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
        index.write()?;
        repo.commit(
            Some("HEAD"),
            &repo.signature()?,
            &repo.signature()?,
            &commit_message,
            &repo.find_tree(index.write_tree()?)?,
            &[&repo.find_commit(repo.head()?.target().unwrap())?],
        )?;
        eprintln!("Commit made. All you need to do is `git push` now.");
    }

    // Figure out the dependency order. Using bubble sort because it's simple, it saves us
    // time trying to figure out transitive dependencies.
    // Basically if we were to use, say, merge sort, comparing two packages would mean
    // comparing all the transitive dependencies of both to know if one is directly or
    // indirectly depending on the other (if so, greater or less than depending on sort
    // order, and if not, equals). That's too complicated. Proper solution is to use
    // petgraph and topological sort, but I'm lazy. Bubblesort works already, with just
    // comparing intransitively if two dependencies are directly related.
    let mut cargo_update_order: Vec<&Package> = version_map.values().map(|x| &x.0).collect();

    let mut changed = cargo_update_order.len() > 1; // Nothing to sort if there's only 1.
    while changed {
        changed = false;
        for i in 0..(cargo_update_order.len() - 1) {
            for j in (i + 1)..cargo_update_order.len() {
                let (a, b) = (cargo_update_order[i], cargo_update_order[j]);

                if a.dependencies.iter().any(|dep| dep.name == b.name) {
                    cargo_update_order.swap(i, j);
                    changed = true;
                };
            }
        }
    }

    eprintln!("\nOnce the PR is approved, run `cargo publish` commands in the following order:");
    for p in cargo_update_order {
        eprintln!("  {}", p.name);
    }
    eprintln!("\n");

    Ok(())
}
