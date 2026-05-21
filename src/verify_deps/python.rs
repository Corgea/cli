//! Discover installed Python dependencies from a project directory.
//!
//! Supported, in order of preference:
//!  1. `poetry.lock` (TOML)
//!  2. `Pipfile.lock` (JSON)
//!  3. `uv.lock` (TOML)
//!  4. `requirements.txt` — only `==`-pinned lines (we can't verify a
//!     range against a registry without resolving, which is out of scope).
//!
//! All resolved dependencies are pinned to exact versions.

use std::path::Path;

use serde::Deserialize;

use super::{Dependency, DependencyEcosystem, DiscoverResult};

const SUPPORTED_FILES: &[&str] = &[
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "requirements.txt",
];

pub fn discover(project_dir: &Path, include_dev: bool) -> Result<DiscoverResult, String> {
    let candidates: Vec<_> = SUPPORTED_FILES
        .iter()
        .map(|f| project_dir.join(f))
        .filter(|p| p.exists())
        .collect();

    if candidates.is_empty() {
        return Err(format!(
            "no Python lockfile found in {}. Looked for: {}",
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
        "poetry.lock" => parse_poetry_lock(&content, include_dev)?,
        "Pipfile.lock" => parse_pipfile_lock(&content, include_dev)?,
        "uv.lock" => parse_uv_lock(&content)?,
        "requirements.txt" => parse_requirements(&content),
        _ => unreachable!(),
    };

    Ok(DiscoverResult {
        deps,
        source: chosen.display().to_string(),
    })
}

#[derive(Debug, Deserialize)]
struct PoetryLockRoot {
    #[serde(default)]
    package: Vec<PoetryPackage>,
}

#[derive(Debug, Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    source: Option<PoetrySource>,
    #[serde(default)]
    groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PoetrySource {
    #[serde(rename = "type")]
    source_type: Option<String>,
}

pub(crate) fn parse_poetry_lock(content: &str, include_dev: bool) -> Result<Vec<Dependency>, String> {
    let root: PoetryLockRoot =
        toml::from_str(content).map_err(|e| format!("failed to parse poetry.lock: {}", e))?;

    let mut out = Vec::new();
    for pkg in root.package {
        if let Some(src) = &pkg.source {
            if let Some(t) = &src.source_type {
                let t = t.to_ascii_lowercase();
                if t == "git" || t == "directory" || t == "file" || t == "url" {
                    continue;
                }
            }
        }

        let is_dev = is_poetry_dev(&pkg);
        if !include_dev && is_dev {
            continue;
        }

        out.push(Dependency {
            name: normalize_python_name(&pkg.name),
            version: pkg.version,
            ecosystem: DependencyEcosystem::Python,
            source: "poetry.lock".to_string(),
            dev: is_dev,
        });
    }
    Ok(out)
}

fn is_poetry_dev(pkg: &PoetryPackage) -> bool {
    if let Some(cat) = &pkg.category {
        if !cat.is_empty() && cat.to_ascii_lowercase() != "main" {
            return true;
        }
    }
    if let Some(groups) = &pkg.groups {
        if !groups.is_empty()
            && !groups.iter().any(|g| g.eq_ignore_ascii_case("main"))
        {
            return true;
        }
    }
    false
}

#[derive(Debug, Deserialize)]
struct PipfileLockRoot {
    #[serde(default)]
    default: std::collections::BTreeMap<String, PipfileLockEntry>,
    #[serde(default)]
    develop: std::collections::BTreeMap<String, PipfileLockEntry>,
}

#[derive(Debug, Deserialize)]
struct PipfileLockEntry {
    version: Option<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default)]
    path: Option<String>,
}

pub(crate) fn parse_pipfile_lock(content: &str, include_dev: bool) -> Result<Vec<Dependency>, String> {
    let root: PipfileLockRoot =
        serde_json::from_str(content).map_err(|e| format!("failed to parse Pipfile.lock: {}", e))?;
    let mut out = Vec::new();
    extend_pipfile(&root.default, false, &mut out);
    if include_dev {
        extend_pipfile(&root.develop, true, &mut out);
    }
    Ok(out)
}

fn extend_pipfile(
    map: &std::collections::BTreeMap<String, PipfileLockEntry>,
    dev: bool,
    out: &mut Vec<Dependency>,
) {
    for (name, entry) in map {
        if entry.git.is_some() || entry.path.is_some() {
            continue;
        }
        let version = match entry.version.as_ref() {
            Some(v) => v,
            None => continue,
        };
        // Pipfile pins look like "==1.2.3" — strip the leading "==".
        let version = version.trim_start_matches("==").trim();
        if version.is_empty() {
            continue;
        }
        out.push(Dependency {
            name: normalize_python_name(name),
            version: version.to_string(),
            ecosystem: DependencyEcosystem::Python,
            source: "Pipfile.lock".to_string(),
            dev,
        });
    }
}

#[derive(Debug, Deserialize)]
struct UvLockRoot {
    #[serde(default)]
    package: Vec<UvPackage>,
}

#[derive(Debug, Deserialize)]
struct UvPackage {
    name: String,
    version: Option<String>,
    #[serde(default)]
    source: Option<UvSource>,
}

#[derive(Debug, Deserialize)]
struct UvSource {
    #[serde(default)]
    registry: Option<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    editable: Option<String>,
    #[serde(default)]
    virtual_: Option<String>,
}

pub(crate) fn parse_uv_lock(content: &str) -> Result<Vec<Dependency>, String> {
    let root: UvLockRoot =
        toml::from_str(content).map_err(|e| format!("failed to parse uv.lock: {}", e))?;

    let mut out = Vec::new();
    for pkg in root.package {
        let version = match pkg.version {
            Some(v) if !v.is_empty() => v,
            _ => continue,
        };
        if let Some(src) = pkg.source {
            // Skip non-registry sources.
            if src.git.is_some()
                || src.url.is_some()
                || src.path.is_some()
                || src.editable.is_some()
                || src.virtual_.is_some()
            {
                continue;
            }
            if src.registry.is_none() {
                continue;
            }
        } else {
            continue;
        }
        out.push(Dependency {
            name: normalize_python_name(&pkg.name),
            version,
            ecosystem: DependencyEcosystem::Python,
            source: "uv.lock".to_string(),
            dev: false,
        });
    }
    Ok(out)
}

/// Parse a `requirements.txt` file. We only emit deps that are
/// `==`-pinned. Everything else (ranges, git URLs, editables) is
/// skipped silently — those can't be checked against a registry
/// without resolution.
pub(crate) fn parse_requirements(content: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut continued = String::new();
    for raw_line in content.lines() {
        let mut line = raw_line.to_string();
        if let Some(idx) = line.find('#') {
            line.truncate(idx);
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line = if line.ends_with('\\') {
            continued.push_str(line.trim_end_matches('\\').trim());
            continued.push(' ');
            continue;
        } else if !continued.is_empty() {
            let mut full = std::mem::take(&mut continued);
            full.push_str(line);
            full
        } else {
            line.to_string()
        };

        if line.starts_with('-') {
            continue;
        }

        let no_extras = match line.find(';') {
            Some(i) => line[..i].trim().to_string(),
            None => line.clone(),
        };

        let no_extras = no_extras.split_whitespace().next().unwrap_or("").to_string();
        if no_extras.is_empty() {
            continue;
        }

        if let Some(idx) = no_extras.find("==") {
            let name_part = &no_extras[..idx];
            let version_part = &no_extras[idx + 2..];
            let name = name_part.split('[').next().unwrap_or("").trim();
            let version = version_part.trim().trim_matches(|c: char| c == '\'' || c == '"');
            if name.is_empty() || version.is_empty() {
                continue;
            }
            out.push(Dependency {
                name: normalize_python_name(name),
                version: version.to_string(),
                ecosystem: DependencyEcosystem::Python,
                source: "requirements.txt".to_string(),
                dev: false,
            });
        }
    }
    out
}

/// Normalize a Python distribution name per PEP 503 (lowercase,
/// runs of `_-.` collapsed to single `-`).
pub(crate) fn normalize_python_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_dash = false;
    for c in lower.chars() {
        if c == '_' || c == '.' || c == '-' {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(c);
            prev_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_names() {
        assert_eq!(normalize_python_name("Flask"), "flask");
        assert_eq!(normalize_python_name("pytest_mock"), "pytest-mock");
        assert_eq!(normalize_python_name("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(normalize_python_name("Some__Weird--Name.."), "some-weird-name");
    }

    #[test]
    fn parses_requirements_txt() {
        let req = r#"
# A comment
requests==2.31.0
flask==2.3.2 ; python_version >= "3.7"
numpy>=1.20  # not pinned, ignored
-r other.txt
git+https://github.com/x/y.git
django[bcrypt]==4.2.0
        "#;
        let deps = parse_requirements(req);
        let pairs: Vec<_> = deps.iter().map(|d| (d.name.clone(), d.version.clone())).collect();
        assert!(pairs.contains(&("requests".to_string(), "2.31.0".to_string())));
        assert!(pairs.contains(&("flask".to_string(), "2.3.2".to_string())));
        assert!(pairs.contains(&("django".to_string(), "4.2.0".to_string())));
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn parses_poetry_lock() {
        let lock = r#"
[[package]]
name = "Requests"
version = "2.31.0"
description = "x"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
description = "x"
category = "dev"

[[package]]
name = "local-pkg"
version = "1.0.0"
description = "x"
category = "main"

[package.source]
type = "directory"
url = "../local"
"#;
        let prod = parse_poetry_lock(lock, false).unwrap();
        let pairs: Vec<_> = prod.iter().map(|d| (d.name.clone(), d.version.clone())).collect();
        assert_eq!(pairs, vec![("requests".to_string(), "2.31.0".to_string())]);

        let all = parse_poetry_lock(lock, true).unwrap();
        let names: Vec<_> = all.iter().map(|d| d.name.clone()).collect();
        assert!(names.contains(&"pytest".to_string()));
        assert!(!names.contains(&"local-pkg".to_string()));
    }

    #[test]
    fn parses_pipfile_lock() {
        let lock = r#"{
            "_meta": {},
            "default": {
                "requests": { "version": "==2.31.0" },
                "private": { "git": "https://example.com/x.git" }
            },
            "develop": {
                "pytest": { "version": "==7.4.0" }
            }
        }"#;
        let prod = parse_pipfile_lock(lock, false).unwrap();
        let names: Vec<_> = prod.iter().map(|d| d.name.clone()).collect();
        assert_eq!(names, vec!["requests".to_string()]);

        let all = parse_pipfile_lock(lock, true).unwrap();
        let names: Vec<_> = all.iter().map(|d| d.name.clone()).collect();
        assert!(names.contains(&"pytest".to_string()));
    }

    #[test]
    fn parses_uv_lock() {
        let lock = r#"
[[package]]
name = "requests"
version = "2.31.0"

[package.source]
registry = "https://pypi.org/simple"

[[package]]
name = "myproj"
version = "0.1.0"

[package.source]
virtual = "."

[[package]]
name = "gitdep"
version = "0.0.0"

[package.source]
git = "https://example.com/x.git"
"#;
        let deps = parse_uv_lock(lock).unwrap();
        let pairs: Vec<_> = deps.iter().map(|d| (d.name.clone(), d.version.clone())).collect();
        assert_eq!(pairs, vec![("requests".to_string(), "2.31.0".to_string())]);
    }
}
