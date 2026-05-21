//! Discover installed npm dependencies from a project directory.
//!
//! Supported, in order of preference:
//!  1. `package-lock.json` / `npm-shrinkwrap.json` (lockfile v1, v2, v3)
//!  2. `yarn.lock` (Yarn classic, v1 syntax)
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
}
