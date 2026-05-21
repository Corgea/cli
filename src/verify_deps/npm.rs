//! Discover installed npm dependencies from a project directory.
//!
//! Supported, in order of preference:
//!  1. `package-lock.json` / `npm-shrinkwrap.json` (lockfile v1, v2, v3)
//!  2. `pnpm-lock.yaml` (pnpm v5, v6, v7, v9)
//!  3. `yarn.lock` (Yarn classic, v1 syntax)
//!
//! These produce *resolved* (pinned) versions so the registry lookup is
//! exact. We deliberately do not parse `package.json` directly — its
//! version specifiers are ranges, which would require resolution we
//! don't want to redo.

use std::path::Path;

use serde::Deserialize;

use super::{Dependency, DependencyEcosystem, DiscoverResult};

const SUPPORTED_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

pub fn discover(project_dir: &Path, include_dev: bool) -> Result<DiscoverResult, String> {
    let candidates: Vec<_> = SUPPORTED_FILES
        .iter()
        .map(|f| project_dir.join(f))
        .filter(|p| p.exists())
        .collect();

    if candidates.is_empty() {
        return Err(format!(
            "no npm lockfile found in {}. Looked for: {}",
            project_dir.display(),
            SUPPORTED_FILES.join(", ")
        ));
    }

    let chosen = &candidates[0];
    let file_name = chosen
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    let content = super::read_to_string(chosen)?;

    let deps = match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => parse_npm_lock(&content, include_dev)?,
        "pnpm-lock.yaml" => parse_pnpm_lock(&content, include_dev)?,
        "yarn.lock" => parse_yarn_lock(&content)?,
        _ => unreachable!(),
    };

    Ok(DiscoverResult {
        deps,
        source: chosen.display().to_string(),
    })
}

#[derive(Debug, Deserialize)]
struct NpmLockRoot {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u32>,
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, NpmLockV1Entry>,
    #[serde(default)]
    packages: std::collections::BTreeMap<String, NpmLockV2Entry>,
}

#[derive(Debug, Deserialize)]
struct NpmLockV1Entry {
    version: Option<String>,
    #[serde(default)]
    dev: bool,
    #[serde(rename = "optional", default)]
    _optional: bool,
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, NpmLockV1Entry>,
}

#[derive(Debug, Deserialize)]
struct NpmLockV2Entry {
    version: Option<String>,
    name: Option<String>,
    #[serde(default)]
    dev: bool,
    #[serde(rename = "devOptional", default)]
    dev_optional: bool,
    #[serde(default)]
    link: bool,
}

pub(crate) fn parse_npm_lock(
    content: &str,
    include_dev: bool,
) -> Result<Vec<Dependency>, String> {
    let root: NpmLockRoot = serde_json::from_str(content)
        .map_err(|e| format!("failed to parse npm lockfile: {}", e))?;

    let mut deps: Vec<Dependency> = Vec::new();
    let version = root.lockfile_version.unwrap_or(1);

    if version >= 2 && !root.packages.is_empty() {
        for (key, entry) in &root.packages {
            if key.is_empty() {
                continue;
            }
            if entry.link {
                continue;
            }
            let dev = entry.dev || entry.dev_optional;
            if !include_dev && dev {
                continue;
            }
            let name = entry
                .name
                .clone()
                .or_else(|| extract_name_from_packages_key(key))
                .unwrap_or_default();
            let ver = match &entry.version {
                Some(v) if !v.is_empty() => v.clone(),
                _ => continue,
            };
            if name.is_empty() {
                continue;
            }
            if !is_registry_version(&ver) {
                continue;
            }
            deps.push(Dependency {
                name,
                version: ver,
                ecosystem: DependencyEcosystem::Npm,
                source: "package-lock.json".to_string(),
                dev,
            });
        }
    } else {
        collect_v1(&root.dependencies, include_dev, &mut deps);
    }

    Ok(deps)
}

fn collect_v1(
    map: &std::collections::BTreeMap<String, NpmLockV1Entry>,
    include_dev: bool,
    out: &mut Vec<Dependency>,
) {
    for (name, entry) in map {
        let dev = entry.dev;
        if include_dev || !dev {
            if let Some(version) = entry.version.as_ref() {
                if !version.is_empty() && is_registry_version(version) {
                    out.push(Dependency {
                        name: name.clone(),
                        version: version.clone(),
                        ecosystem: DependencyEcosystem::Npm,
                        source: "package-lock.json".to_string(),
                        dev,
                    });
                }
            }
        }
        if !entry.dependencies.is_empty() {
            collect_v1(&entry.dependencies, include_dev, out);
        }
    }
}

/// Extract a package name from a v2/v3 lockfile `packages` key like
/// `node_modules/foo` or `node_modules/@scope/bar/node_modules/baz`.
fn extract_name_from_packages_key(key: &str) -> Option<String> {
    let last_nm = key.rfind("node_modules/")?;
    let rest = &key[last_nm + "node_modules/".len()..];
    if rest.is_empty() {
        return None;
    }
    if rest.starts_with('@') {
        let mut parts = rest.splitn(3, '/');
        let scope = parts.next()?;
        let pkg = parts.next()?;
        Some(format!("{}/{}", scope, pkg))
    } else {
        let first = rest.split('/').next()?;
        Some(first.to_string())
    }
}

/// Filter out non-registry version specifiers (git URLs, file refs, links).
fn is_registry_version(version: &str) -> bool {
    let v = version.trim();
    if v.is_empty() {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    let bad_prefixes = [
        "git+", "git:", "git://", "ssh://", "http://", "https://", "file:", "link:", "workspace:", "npm:",
    ];
    if bad_prefixes.iter().any(|p| lower.starts_with(p)) {
        return false;
    }
    let first = v.chars().next().unwrap_or(' ');
    if !(first.is_ascii_digit() || first == 'v') {
        return false;
    }
    true
}

/// Parse a Yarn classic (v1) lockfile.
///
/// Yarn classic format (simplified, the bits we need):
///
/// ```text
/// "left-pad@^1.3.0":
///   version "1.3.0"
///   resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"
///
/// "@scope/pkg@^1.0.0", "@scope/pkg@^1.0.1":
///   version "1.0.5"
/// ```
pub(crate) fn parse_yarn_lock(content: &str) -> Result<Vec<Dependency>, String> {
    let mut deps: Vec<Dependency> = Vec::new();
    let mut current_keys: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;

    let flush =
        |keys: &mut Vec<String>,
         version: &mut Option<String>,
         out: &mut Vec<Dependency>| {
            if let (Some(name), Some(ver)) = (
                keys.first().and_then(|k| yarn_key_name(k)),
                version.clone(),
            ) {
                if is_registry_version(&ver) {
                    out.push(Dependency {
                        name,
                        version: ver,
                        ecosystem: DependencyEcosystem::Npm,
                        source: "yarn.lock".to_string(),
                        dev: false,
                    });
                }
            }
            keys.clear();
            *version = None;
        };

    for raw_line in content.lines() {
        let line = raw_line;
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
            if !current_keys.is_empty() && current_version.is_some() {
                flush(&mut current_keys, &mut current_version, &mut deps);
            }
            continue;
        }
        let leading_ws = line.len() - line.trim_start().len();
        if leading_ws == 0 {
            if !current_keys.is_empty() && current_version.is_some() {
                flush(&mut current_keys, &mut current_version, &mut deps);
            } else {
                current_keys.clear();
                current_version = None;
            }
            let header = trimmed.trim_end_matches(':').trim();
            current_keys = split_yarn_header(header);
        } else if let Some(rest) = trimmed.trim_start().strip_prefix("version ") {
            let v = rest.trim().trim_matches('"').to_string();
            current_version = Some(v);
        }
    }
    if !current_keys.is_empty() && current_version.is_some() {
        flush(&mut current_keys, &mut current_version, &mut deps);
    }
    Ok(deps)
}

/// Split a yarn lock header line of comma-separated quoted specs into
/// the individual specs. Handles e.g.
/// `"@scope/pkg@^1.0.0", "@scope/pkg@^1.0.1"`.
fn split_yarn_header(header: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    for c in header.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let s = buf.trim().trim_matches('"').to_string();
                if !s.is_empty() {
                    out.push(s);
                }
                buf.clear();
            }
            _ => buf.push(c),
        }
    }
    let s = buf.trim().trim_matches('"').to_string();
    if !s.is_empty() {
        out.push(s);
    }
    out
}

/// Extract the package name from a yarn key like `left-pad@^1.3.0` or
/// `@scope/name@^1.0.0`.
fn yarn_key_name(key: &str) -> Option<String> {
    let key = key.trim().trim_matches('"');
    if key.is_empty() {
        return None;
    }
    let (name_part, _) = if key.starts_with('@') {
        let after_scope = key[1..].find('@')?;
        let split_at = after_scope + 1;
        (&key[..split_at], &key[split_at + 1..])
    } else {
        let at = key.find('@')?;
        (&key[..at], &key[at + 1..])
    };
    Some(name_part.to_string())
}

/// Parse a pnpm-lock.yaml file. Supports lockfile versions 5.x, 6.x,
/// 7.x and 9.x — the format and key conventions vary across versions:
///
/// * v5/v6 keys in `packages:` use `/` separators:
///     `/lodash/4.17.21:` or `/@types/node/20.10.5:`
/// * v6+ keys may use `@` for the version separator:
///     `/lodash@4.17.21:` or `/@types/node@20.10.5:`
/// * v9 keys drop the leading `/` entirely:
///     `lodash@4.17.21:` or `'@types/node@20.10.5':`
///
/// Versions can carry a peer-deps suffix that is *not* part of the
/// resolved version — `(react@18.0.0)` in v9, `_react@18.0.0` in v6.
/// Both must be stripped before lookup, since the registry only knows
/// the bare semver version.
///
/// Dev/prod classification:
/// * v6 packages have a `dev: true|false` field per entry — we use it.
/// * v9 packages don't carry `dev:`. We instead consult the
///   `importers:` section: a (name, version) that appears *only* in
///   `devDependencies` of all importers (and never in `dependencies`)
///   is treated as dev. This is best-effort: transitive deps that are
///   only reached through a dev top-level package are still treated as
///   non-dev, because resolving the full graph from a lockfile is out
///   of scope here. Including those in production scans is the safer
///   default for a supply-chain tripwire.
pub(crate) fn parse_pnpm_lock(
    content: &str,
    include_dev: bool,
) -> Result<Vec<Dependency>, String> {
    let importers = parse_pnpm_importers(content);
    let entries = parse_pnpm_packages(content)?;

    let mut deps = Vec::new();
    for entry in entries {
        let key = (entry.name.clone(), entry.version.clone());
        let dev = match entry.dev_field {
            Some(d) => d,
            None => {
                let in_prod = importers.prod.contains(&key);
                let in_dev = importers.dev.contains(&key);
                in_dev && !in_prod
            }
        };
        if !include_dev && dev {
            continue;
        }
        if !is_registry_version(&entry.version) {
            continue;
        }
        deps.push(Dependency {
            name: entry.name,
            version: entry.version,
            ecosystem: DependencyEcosystem::Npm,
            source: "pnpm-lock.yaml".to_string(),
            dev,
        });
    }
    Ok(deps)
}

#[derive(Debug, Default)]
struct PnpmImporters {
    prod: std::collections::BTreeSet<(String, String)>,
    dev: std::collections::BTreeSet<(String, String)>,
}

#[derive(Debug)]
struct PnpmPackageEntry {
    name: String,
    version: String,
    dev_field: Option<bool>,
}

fn parse_pnpm_packages(content: &str) -> Result<Vec<PnpmPackageEntry>, String> {
    let mut out = Vec::new();
    let mut state = PackagesState::Outside;

    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_dev: Option<bool> = None;
    let mut entry_indent: usize = 0;

    for raw_line in content.lines() {
        if raw_line.trim().is_empty() || raw_line.trim_start().starts_with('#') {
            continue;
        }
        let indent = leading_spaces(raw_line);
        let body = &raw_line[indent..];

        if indent == 0 {
            commit_pnpm_entry(&mut out, &mut current_name, &mut current_version, &mut current_dev);
            state = if body.trim_end_matches(' ') == "packages:" {
                PackagesState::Inside
            } else {
                PackagesState::Outside
            };
            continue;
        }

        if !matches!(state, PackagesState::Inside) {
            continue;
        }

        if current_name.is_none() {
            entry_indent = indent;
        }

        if indent == entry_indent && body.ends_with(':') {
            commit_pnpm_entry(&mut out, &mut current_name, &mut current_version, &mut current_dev);

            let key = body.trim_end_matches(':').trim();
            if let Some((name, version)) = extract_pnpm_pkg_key(key) {
                current_name = Some(name);
                current_version = Some(version);
                current_dev = None;
            } else {
                current_name = None;
                current_version = None;
                current_dev = None;
            }
        } else if indent > entry_indent {
            if let Some(rest) = body.strip_prefix("dev:") {
                let v = rest.trim();
                if v == "true" {
                    current_dev = Some(true);
                } else if v == "false" {
                    current_dev = Some(false);
                }
            }
        }
    }
    commit_pnpm_entry(&mut out, &mut current_name, &mut current_version, &mut current_dev);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackagesState {
    Outside,
    Inside,
}

fn commit_pnpm_entry(
    out: &mut Vec<PnpmPackageEntry>,
    name: &mut Option<String>,
    version: &mut Option<String>,
    dev: &mut Option<bool>,
) {
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        out.push(PnpmPackageEntry {
            name: n,
            version: v,
            dev_field: dev.take(),
        });
    } else {
        *name = None;
        *version = None;
        *dev = None;
    }
}

fn parse_pnpm_importers(content: &str) -> PnpmImporters {
    let mut importers = PnpmImporters::default();

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Bucket {
        Prod,
        Dev,
        None,
    }

    let mut active_bucket = Bucket::None;
    let mut bucket_indent: usize = usize::MAX;
    let mut in_importers_section = false;
    let mut pending_name: Option<(String, usize)> = None;

    for raw_line in content.lines() {
        if raw_line.trim().is_empty() || raw_line.trim_start().starts_with('#') {
            continue;
        }
        let indent = leading_spaces(raw_line);
        let body = &raw_line[indent..];

        if indent == 0 {
            in_importers_section = body.trim_end_matches(' ') == "importers:";
            if !in_importers_section {
                if body.trim_end_matches(' ') == "dependencies:" {
                    active_bucket = Bucket::Prod;
                    bucket_indent = 0;
                    pending_name = None;
                    continue;
                }
                if body.trim_end_matches(' ') == "devDependencies:" {
                    active_bucket = Bucket::Dev;
                    bucket_indent = 0;
                    pending_name = None;
                    continue;
                }
                active_bucket = Bucket::None;
                bucket_indent = usize::MAX;
                pending_name = None;
            } else {
                active_bucket = Bucket::None;
                bucket_indent = usize::MAX;
                pending_name = None;
            }
            continue;
        }

        if in_importers_section {
            let trimmed = body.trim_end();
            if trimmed == "dependencies:" {
                active_bucket = Bucket::Prod;
                bucket_indent = indent;
                pending_name = None;
                continue;
            }
            if trimmed == "devDependencies:" {
                active_bucket = Bucket::Dev;
                bucket_indent = indent;
                pending_name = None;
                continue;
            }
        }

        if active_bucket == Bucket::None || indent <= bucket_indent {
            if indent <= bucket_indent {
                active_bucket = Bucket::None;
                bucket_indent = usize::MAX;
                pending_name = None;
            }
            continue;
        }

        let (key_part, value_part) = match body.split_once(':') {
            Some(x) => x,
            None => continue,
        };
        let key = key_part.trim().trim_matches('\'').trim_matches('"');
        let value = value_part.trim();

        let expected_entry_indent = bucket_indent + 2;
        if indent != expected_entry_indent {
            if let Some((ref pkg, _)) = pending_name {
                if key == "version" && !value.is_empty() {
                    let version = strip_pnpm_peer_suffix(value.trim_matches('\'').trim_matches('"'));
                    let pair = (pkg.clone(), version);
                    match active_bucket {
                        Bucket::Prod => {
                            importers.prod.insert(pair);
                        }
                        Bucket::Dev => {
                            importers.dev.insert(pair);
                        }
                        Bucket::None => {}
                    }
                    pending_name = None;
                }
            }
            continue;
        }

        if value.is_empty() {
            pending_name = Some((key.to_string(), indent));
        } else {
            let version = strip_pnpm_peer_suffix(value.trim_matches('\'').trim_matches('"'));
            let pair = (key.to_string(), version);
            match active_bucket {
                Bucket::Prod => {
                    importers.prod.insert(pair);
                }
                Bucket::Dev => {
                    importers.dev.insert(pair);
                }
                Bucket::None => {}
            }
            pending_name = None;
        }
    }

    importers
}

fn leading_spaces(line: &str) -> usize {
    line.bytes().take_while(|b| *b == b' ').count()
}

fn extract_pnpm_pkg_key(raw_key: &str) -> Option<(String, String)> {
    // Order of trims matters: pnpm v9 quotes the *whole* scoped key
    // including the version (`'@types/node@20.10.5'`), and v5/v6 wrap
    // the same shape with a leading `/`. Strip both, in either order,
    // until the key stabilises.
    let mut key = raw_key.trim().to_string();
    for _ in 0..3 {
        let trimmed = key
            .trim_matches('\'')
            .trim_matches('"')
            .trim_start_matches('/')
            .to_string();
        if trimmed == key {
            break;
        }
        key = trimmed;
    }
    let key_owned = strip_pnpm_peer_suffix(&key);
    let key: &str = &key_owned;

    if let Some(rest) = key.strip_prefix('@') {
        let after_scope_idx = rest.find('/')?;
        let post = &rest[after_scope_idx + 1..];
        let sep_offset_at = post.find('@');
        let sep_offset_slash = post.find('/');
        let sep_offset = match (sep_offset_at, sep_offset_slash) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }?;
        let name_end = 1 + after_scope_idx + 1 + sep_offset;
        let name = &key[..name_end];
        let version = &key[name_end + 1..];
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_string(), version.to_string()))
    } else {
        let sep_at = key.find('@');
        let sep_slash = key.find('/');
        let sep = match (sep_at, sep_slash) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }?;
        let name = &key[..sep];
        let version = &key[sep + 1..];
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_string(), version.to_string()))
    }
}

fn strip_pnpm_peer_suffix(version: &str) -> String {
    let v = version.trim();
    let v = match v.find('(') {
        Some(idx) => &v[..idx],
        None => v,
    };
    let v = match v.find('_') {
        Some(idx) => &v[..idx],
        None => v,
    };
    v.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_lock_v1() {
        let lock = r#"{
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "left-pad": { "version": "1.3.0" },
                "is-odd": { "version": "3.0.1", "dev": true,
                    "dependencies": {
                        "is-number": { "version": "6.0.0", "dev": true }
                    }
                }
            }
        }"#;
        let prod = parse_npm_lock(lock, false).unwrap();
        let names: Vec<_> = prod.iter().map(|d| (d.name.as_str(), d.version.as_str())).collect();
        assert_eq!(names, vec![("left-pad", "1.3.0")]);

        let all = parse_npm_lock(lock, true).unwrap();
        let names: Vec<_> = all.iter().map(|d| d.name.clone()).collect();
        assert!(names.contains(&"left-pad".to_string()));
        assert!(names.contains(&"is-odd".to_string()));
        assert!(names.contains(&"is-number".to_string()));
    }

    #[test]
    fn parses_npm_lock_v3() {
        let lock = r#"{
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "demo",
                    "version": "1.0.0"
                },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                },
                "node_modules/@types/node": {
                    "version": "20.10.5",
                    "dev": true
                },
                "node_modules/local-link": {
                    "link": true,
                    "resolved": "../local-link"
                }
            }
        }"#;

        let prod = parse_npm_lock(lock, false).unwrap();
        let names: Vec<_> = prod.iter().map(|d| (d.name.as_str(), d.version.as_str())).collect();
        assert_eq!(names, vec![("left-pad", "1.3.0")]);

        let all = parse_npm_lock(lock, true).unwrap();
        let mut got: Vec<_> = all.iter().map(|d| (d.name.clone(), d.version.clone())).collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("@types/node".to_string(), "20.10.5".to_string()),
                ("left-pad".to_string(), "1.3.0".to_string()),
            ]
        );
    }

    #[test]
    fn parses_yarn_lock() {
        let lock = r#"# THIS IS AN AUTOGENERATED FILE.
# yarn lockfile v1

"left-pad@^1.3.0":
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"

"@types/node@^20.10.0", "@types/node@^20.10.5":
  version "20.10.5"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.10.5.tgz"
"#;
        let deps = parse_yarn_lock(lock).unwrap();
        assert_eq!(deps.len(), 2);
        let names: Vec<_> = deps.iter().map(|d| (d.name.clone(), d.version.clone())).collect();
        assert!(names.contains(&("left-pad".to_string(), "1.3.0".to_string())));
        assert!(names.contains(&("@types/node".to_string(), "20.10.5".to_string())));
    }

    #[test]
    fn ignores_non_registry_versions() {
        assert!(!is_registry_version("git+https://github.com/x/y.git#abc"));
        assert!(!is_registry_version("file:../pkg"));
        assert!(!is_registry_version("link:../pkg"));
        assert!(!is_registry_version("workspace:*"));
        assert!(!is_registry_version("npm:other@1.0.0"));
        assert!(is_registry_version("1.2.3"));
        assert!(is_registry_version("v1.2.3"));
    }

    #[test]
    fn extracts_packages_key_name() {
        assert_eq!(extract_name_from_packages_key("node_modules/foo").as_deref(), Some("foo"));
        assert_eq!(
            extract_name_from_packages_key("node_modules/@scope/bar").as_deref(),
            Some("@scope/bar")
        );
        assert_eq!(
            extract_name_from_packages_key("node_modules/a/node_modules/@s/b").as_deref(),
            Some("@s/b")
        );
        assert_eq!(extract_name_from_packages_key("").as_deref(), None);
    }

    #[test]
    fn pnpm_pkg_key_v5() {
        // v5: leading slash + slash version separator
        assert_eq!(
            extract_pnpm_pkg_key("/lodash/4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
        assert_eq!(
            extract_pnpm_pkg_key("/@types/node/20.10.5"),
            Some(("@types/node".to_string(), "20.10.5".to_string()))
        );
    }

    #[test]
    fn pnpm_pkg_key_v6() {
        // v6: leading slash + at-sign version separator
        assert_eq!(
            extract_pnpm_pkg_key("/lodash@4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
        assert_eq!(
            extract_pnpm_pkg_key("/@types/node@20.10.5"),
            Some(("@types/node".to_string(), "20.10.5".to_string()))
        );
    }

    #[test]
    fn pnpm_pkg_key_v9() {
        // v9: no leading slash; quoted scoped names
        assert_eq!(
            extract_pnpm_pkg_key("lodash@4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
        assert_eq!(
            extract_pnpm_pkg_key("'@types/node@20.10.5'"),
            Some(("@types/node".to_string(), "20.10.5".to_string()))
        );
        assert_eq!(
            extract_pnpm_pkg_key("\"@types/node@20.10.5\""),
            Some(("@types/node".to_string(), "20.10.5".to_string()))
        );
    }

    #[test]
    fn pnpm_pkg_key_strips_peer_suffix() {
        // v9 paren style:
        assert_eq!(
            extract_pnpm_pkg_key("/foo@1.0.0(react@18.0.0)"),
            Some(("foo".to_string(), "1.0.0".to_string()))
        );
        assert_eq!(
            extract_pnpm_pkg_key("foo@1.0.0(react@18.0.0)(typescript@5.0.0)"),
            Some(("foo".to_string(), "1.0.0".to_string()))
        );
        // v6 underscore style:
        assert_eq!(
            extract_pnpm_pkg_key("/foo/1.0.0_react@18.0.0"),
            Some(("foo".to_string(), "1.0.0".to_string()))
        );
        assert_eq!(
            extract_pnpm_pkg_key("/foo@1.0.0_react@18.0.0"),
            Some(("foo".to_string(), "1.0.0".to_string()))
        );
    }

    #[test]
    fn pnpm_pkg_key_rejects_garbage() {
        assert_eq!(extract_pnpm_pkg_key(""), None);
        assert_eq!(extract_pnpm_pkg_key("/"), None);
        assert_eq!(extract_pnpm_pkg_key("/lodash"), None);
        assert_eq!(extract_pnpm_pkg_key("/@scope/no-version"), None);
    }

    #[test]
    fn parses_pnpm_lock_v9() {
        // Realistic pnpm v9 lockfile.
        let lock = r#"lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
      '@scope/lib':
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      typescript:
        specifier: ^5.0.0
        version: 5.4.5

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
    engines: {node: '>=12'}

  '@scope/lib@1.0.0':
    resolution: {integrity: sha512-y}

  typescript@5.4.5:
    resolution: {integrity: sha512-z}
    engines: {node: '>=14.17'}

  some-transitive@2.0.0:
    resolution: {integrity: sha512-w}
"#;

        let prod = parse_pnpm_lock(lock, false).unwrap();
        let pairs: Vec<_> = prod
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
        // typescript is dev-only top-level, should be excluded.
        // some-transitive is unclassified — kept as prod (best-effort).
        assert!(pairs.contains(&("lodash".to_string(), "4.17.21".to_string())));
        assert!(pairs.contains(&("@scope/lib".to_string(), "1.0.0".to_string())));
        assert!(pairs.contains(&("some-transitive".to_string(), "2.0.0".to_string())));
        assert!(!pairs.contains(&("typescript".to_string(), "5.4.5".to_string())));

        let all = parse_pnpm_lock(lock, true).unwrap();
        let names: Vec<_> = all.iter().map(|d| d.name.clone()).collect();
        assert!(names.contains(&"typescript".to_string()));
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn parses_pnpm_lock_v6() {
        // v6 layout: per-package `dev:` flag drives classification.
        let lock = r#"lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21

devDependencies:
  typescript:
    specifier: ^5.0.0
    version: 5.4.5

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-x}
    dev: false

  /typescript@5.4.5:
    resolution: {integrity: sha512-z}
    dev: true

  /'@types/node@20.10.5':
    resolution: {integrity: sha512-y}
    dev: true
"#;

        let prod = parse_pnpm_lock(lock, false).unwrap();
        let pairs: Vec<_> = prod
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
        assert_eq!(
            pairs,
            vec![("lodash".to_string(), "4.17.21".to_string())]
        );

        let all = parse_pnpm_lock(lock, true).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn parses_pnpm_lock_v5_flat() {
        let lock = r#"lockfileVersion: 5.4

dependencies:
  lodash: 4.17.21

devDependencies:
  typescript: 5.4.5

packages:

  /lodash/4.17.21:
    resolution: {integrity: sha512-x}
    dev: false

  /typescript/5.4.5:
    resolution: {integrity: sha512-z}
    dev: true
"#;
        let prod = parse_pnpm_lock(lock, false).unwrap();
        let pairs: Vec<_> = prod
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
        assert_eq!(
            pairs,
            vec![("lodash".to_string(), "4.17.21".to_string())]
        );
    }

    #[test]
    fn pnpm_lock_strips_peer_suffix_in_packages_section() {
        let lock = r#"lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      consumer:
        specifier: ^1.0.0
        version: 1.0.0(react@18.2.0)

packages:
  consumer@1.0.0(react@18.2.0):
    resolution: {integrity: sha512-x}
  react@18.2.0:
    resolution: {integrity: sha512-y}
"#;
        let deps = parse_pnpm_lock(lock, true).unwrap();
        let pairs: Vec<_> = deps
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
        assert!(pairs.contains(&("consumer".to_string(), "1.0.0".to_string())));
        assert!(pairs.contains(&("react".to_string(), "18.2.0".to_string())));
    }
}
