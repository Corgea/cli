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

const SUPPORTED_FILES: &[&str] = &["poetry.lock", "Pipfile.lock", "uv.lock", "requirements.txt"];

pub fn discover(project_dir: &Path, include_dev: bool) -> Result<DiscoverResult, String> {
    let candidates: Vec<_> = SUPPORTED_FILES
        .iter()
        .map(|f| project_dir.join(f))
        .filter(|p| p.exists())
        .collect();

    let mut warnings: Vec<super::UnpinnedWarning> = Vec::new();

    // Always look for sibling manifests that imply the project has
    // dependencies, even when a lockfile is present. We surface these
    // as warnings only when the corresponding lockfile is missing.
    let pyproject = project_dir.join("pyproject.toml");
    let pipfile = project_dir.join("Pipfile");
    let pipfile_lock = project_dir.join("Pipfile.lock");
    let poetry_lock = project_dir.join("poetry.lock");
    let uv_lock = project_dir.join("uv.lock");
    let requirements_in = project_dir.join("requirements.in");

    if pipfile.exists() && !pipfile_lock.exists() {
        warnings.push(super::UnpinnedWarning {
            ecosystem: DependencyEcosystem::Python,
            manifest: pipfile.display().to_string(),
            reason: "Pipfile is present but Pipfile.lock is missing. Run `pipenv lock` to generate one before verifying."
                .to_string(),
        });
    }

    if requirements_in.exists() && !project_dir.join("requirements.txt").exists() {
        warnings.push(super::UnpinnedWarning {
            ecosystem: DependencyEcosystem::Python,
            manifest: requirements_in.display().to_string(),
            reason: "requirements.in is present but no compiled requirements.txt was found. Run `pip-compile` (or `uv pip compile`) to produce a pinned requirements file before verifying."
                .to_string(),
        });
    }

    if pyproject.exists()
        && !poetry_lock.exists()
        && !uv_lock.exists()
        && !pipfile_lock.exists()
        && pyproject_has_deps(&pyproject).unwrap_or(false)
    {
        warnings.push(super::UnpinnedWarning {
                ecosystem: DependencyEcosystem::Python,
                manifest: pyproject.display().to_string(),
                reason: "pyproject.toml declares dependencies but no lockfile was found (looked for poetry.lock, uv.lock, Pipfile.lock). Run `poetry lock`, `uv lock`, or generate a pinned requirements.txt before verifying."
                    .to_string(),
            });
    }

    if candidates.is_empty() {
        // Without a lockfile or pinned requirements.txt we have nothing
        // to verify. If we already emitted a warning above, return it
        // (and let the caller decide if it's fatal). Otherwise fall
        // back to the previous "nothing to do" error.
        if !warnings.is_empty() {
            return Ok(DiscoverResult {
                deps: Vec::new(),
                source: String::new(),
                warnings,
            });
        }
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
        "requirements.txt" => {
            let (pinned, unpinned) = parse_requirements_with_warnings(&content);
            for line in unpinned {
                warnings.push(super::UnpinnedWarning {
                    ecosystem: DependencyEcosystem::Python,
                    manifest: chosen.display().to_string(),
                    reason: format!("requirements.txt line is not `==`-pinned: `{}`", line),
                });
            }
            pinned
        }
        _ => unreachable!(),
    };

    Ok(DiscoverResult {
        deps,
        source: chosen.display().to_string(),
        warnings,
    })
}

/// Lightweight check: does this `pyproject.toml` declare any project
/// dependencies? We look at PEP 621 `[project].dependencies` and
/// `[project].optional-dependencies`, plus the legacy
/// `[tool.poetry.dependencies]` and `[tool.poetry.group.*.dependencies]`
/// tables. Tolerates parse errors.
fn pyproject_has_deps(path: &Path) -> Result<bool, ()> {
    let content = std::fs::read_to_string(path).map_err(|_| ())?;
    let parsed: toml::Value = toml::from_str(&content).map_err(|_| ())?;

    let project_deps = parsed
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let project_opt = parsed
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|v| v.as_table())
        .map(|t| {
            t.values()
                .any(|v| v.as_array().map(|a| !a.is_empty()).unwrap_or(false))
        })
        .unwrap_or(false);
    let poetry_main = parsed
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|v| v.as_table())
        // Poetry seeds `python = "^3.10"` here; ignore that one entry.
        .map(|t| t.iter().any(|(k, _)| k != "python"))
        .unwrap_or(false);
    let poetry_groups = parsed
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("group"))
        .and_then(|v| v.as_table())
        .map(|groups| {
            groups.values().any(|g| {
                g.get("dependencies")
                    .and_then(|d| d.as_table())
                    .map(|t| !t.is_empty())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    Ok(project_deps || project_opt || poetry_main || poetry_groups)
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

pub(crate) fn parse_poetry_lock(
    content: &str,
    include_dev: bool,
) -> Result<Vec<Dependency>, String> {
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
        if !cat.is_empty() && !cat.eq_ignore_ascii_case("main") {
            return true;
        }
    }
    if let Some(groups) = &pkg.groups {
        if !groups.is_empty() && !groups.iter().any(|g| g.eq_ignore_ascii_case("main")) {
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

pub(crate) fn parse_pipfile_lock(
    content: &str,
    include_dev: bool,
) -> Result<Vec<Dependency>, String> {
    let root: PipfileLockRoot = serde_json::from_str(content)
        .map_err(|e| format!("failed to parse Pipfile.lock: {}", e))?;
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

/// Parse a `requirements.txt` file. Returns `(pinned_deps, unpinned_lines)`:
///
/// * `pinned_deps`: deps with an exact `==` pin, ready for registry
///   lookup.
/// * `unpinned_lines`: each non-empty, non-comment, non-flag line that
///   we *could not* resolve to a pinned version (range specifiers,
///   bare names, git URLs, editables, etc.). Surfaced as warnings so
///   `--fail-unpinned` can fail on them.
pub(crate) fn parse_requirements_with_warnings(content: &str) -> (Vec<Dependency>, Vec<String>) {
    let mut deps = Vec::new();
    let mut unpinned = Vec::new();
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

        // `-r other.txt`, `-c constraints.txt`, `--index-url`, etc.
        // These are pip configuration directives, not deps.
        if line.starts_with('-') {
            continue;
        }

        let no_extras = match line.find(';') {
            Some(i) => line[..i].trim().to_string(),
            None => line.clone(),
        };

        let first_token = no_extras
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if first_token.is_empty() {
            continue;
        }

        // VCS / local path / archive URL specifiers — explicit and
        // unverifiable against a registry. Don't classify these as
        // unpinned warnings; they're an intentional escape hatch.
        let lowered = first_token.to_ascii_lowercase();
        let unverifiable_prefixes = [
            "git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:",
        ];
        if unverifiable_prefixes.iter().any(|p| lowered.starts_with(p)) {
            continue;
        }

        if let Some(idx) = first_token.find("==") {
            let name_part = &first_token[..idx];
            let version_part = &first_token[idx + 2..];
            let name = name_part.split('[').next().unwrap_or("").trim();
            let version = version_part
                .trim()
                .trim_matches(|c: char| c == '\'' || c == '"');
            if name.is_empty() || version.is_empty() {
                unpinned.push(line.clone());
                continue;
            }
            deps.push(Dependency {
                name: normalize_python_name(name),
                version: version.to_string(),
                ecosystem: DependencyEcosystem::Python,
                source: "requirements.txt".to_string(),
                dev: false,
            });
        } else {
            unpinned.push(line.clone());
        }
    }
    (deps, unpinned)
}

/// Backwards-compatible wrapper that drops the unpinned-line list.
/// Used by tests; the binary build path doesn't call it directly any
/// more, so the dead-code lint needs silencing.
#[allow(dead_code)]
pub(crate) fn parse_requirements(content: &str) -> Vec<Dependency> {
    parse_requirements_with_warnings(content).0
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
        assert_eq!(
            normalize_python_name("Some__Weird--Name.."),
            "some-weird-name"
        );
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
        let pairs: Vec<_> = deps
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
        assert!(pairs.contains(&("requests".to_string(), "2.31.0".to_string())));
        assert!(pairs.contains(&("flask".to_string(), "2.3.2".to_string())));
        assert!(pairs.contains(&("django".to_string(), "4.2.0".to_string())));
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn requirements_warnings_capture_unpinned_lines() {
        let req = r#"
# pinned, no warning
requests==2.31.0

# unpinned — should produce warnings
numpy>=1.20
flask
sqlalchemy~=2.0

# pip directives — ignored, not warnings
-r other.txt
--index-url https://example.com/simple

# VCS / URL deps — explicit escape hatch, no warning
git+https://github.com/x/y.git
https://example.com/pkg.tar.gz
"#;
        let (deps, unpinned) = parse_requirements_with_warnings(req);
        assert_eq!(
            deps.iter().map(|d| d.name.clone()).collect::<Vec<_>>(),
            vec!["requests".to_string()]
        );
        assert_eq!(unpinned.len(), 3);
        assert!(unpinned.iter().any(|l| l.contains("numpy>=1.20")));
        assert!(unpinned.iter().any(|l| l == "flask"));
        assert!(unpinned.iter().any(|l| l.contains("sqlalchemy~=2.0")));
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
        let pairs: Vec<_> = prod
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
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
        let pairs: Vec<_> = deps
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
        assert_eq!(pairs, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    #[test]
    fn discover_warns_on_pyproject_without_lockfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests>=2.0", "flask"]
"#,
        )
        .unwrap();

        let result = discover(dir.path(), false).expect("discover");
        assert!(result.deps.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].reason.contains("pyproject.toml"));
        assert!(result.warnings[0].reason.contains("lockfile"));
    }

    #[test]
    fn discover_no_warning_for_empty_pyproject() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"[project]
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap();

        let err = discover(dir.path(), false).err().expect("expected error");
        assert!(err.contains("no Python lockfile found"));
    }

    #[test]
    fn discover_warns_on_pipfile_without_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("Pipfile"), "[packages]\nrequests = \"*\"\n").unwrap();

        let result = discover(dir.path(), false).expect("discover");
        assert!(result.deps.is_empty());
        assert!(result.warnings.iter().any(|w| w.reason.contains("Pipfile")));
    }

    #[test]
    fn discover_emits_unpinned_warnings_from_requirements_txt() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("requirements.txt"),
            "requests==2.31.0
flask>=2.0
numpy
",
        )
        .unwrap();

        let result = discover(dir.path(), false).expect("discover");
        let names: Vec<_> = result.deps.iter().map(|d| d.name.clone()).collect();
        assert_eq!(names, vec!["requests".to_string()]);
        // Two unpinned lines: `flask>=2.0` and `numpy`.
        assert_eq!(result.warnings.len(), 2);
        for w in &result.warnings {
            assert!(w.reason.contains("not `==`-pinned"));
        }
    }

    #[test]
    fn discover_warns_for_requirements_in_without_compiled_txt() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("requirements.in"),
            "requests
flask
",
        )
        .unwrap();

        let err = discover(dir.path(), false).err();
        // requirements.in alone is not enough to find a lockfile, but
        // we should have surfaced the in-without-compiled-txt warning
        // before getting to the "no lockfile" error.
        match err {
            Some(e) => assert!(e.contains("no Python lockfile")),
            None => {}
        }

        // When requirements.in is paired with a pyproject.toml that
        // *does* declare deps, we end up returning a warning.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("requirements.in"),
            "requests
",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]
"#,
        )
        .unwrap();
        let result = discover(dir.path(), false).expect("discover");
        assert!(result
            .warnings
            .iter()
            .any(|w| w.manifest.ends_with("requirements.in")));
        assert!(result
            .warnings
            .iter()
            .any(|w| w.manifest.ends_with("pyproject.toml")));
    }
}
