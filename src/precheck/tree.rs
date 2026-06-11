//! Full would-install-set resolution (the "tree pass").
//!
//! Safety invariant: resolution must never execute package code.
//! pip: `--only-binary :all:` prevents sdist builds (pypa/pip#13091).
//! npm: `--ignore-scripts` guards npm/cli#2787.

use std::process::Command;

use super::PackageManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreePackage {
    pub name: String,
    pub version: String,
}

/// Whether this manager's resolver has anything to resolve for the parsed
/// install. pip's dry-run also reads `-r` requirements files, so those make
/// a pip install eligible even with no named targets. npm's lockfile
/// resolution reads `package.json`, so a bare `npm install` is eligible
/// whenever the working directory has one.
pub fn covers_input(manager: PackageManager, parsed: &super::parse::ParsedInstall) -> bool {
    !parsed.targets.is_empty()
        || (manager == PackageManager::Pip && !parsed.requirements_files.is_empty())
        || (manager == PackageManager::Npm && std::path::Path::new("package.json").exists())
}

/// `Ok(None)`: manager has no safe dry-run — named-only with warning.
/// `Err(reason)`: dry-run attempted and failed — named-only, warning carries reason.
pub fn resolve_tree(
    manager: PackageManager,
    install_args: &[String],
) -> Result<Option<Vec<TreePackage>>, String> {
    match manager {
        PackageManager::Pip => resolve_pip_tree(manager.binary_name(), install_args).map(Some),
        PackageManager::Npm => resolve_npm_tree(manager.binary_name(), install_args).map(Some),
        // yarn/pnpm/uv have no safe dry-run for installs.
        _ => Ok(None),
    }
}

/// Last stderr line of a failed subprocess, for one-line error messages.
fn stderr_tail(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .trim()
        .lines()
        .last()
        .unwrap_or("unknown error")
        .to_string()
}

fn resolve_pip_tree(binary: &str, install_args: &[String]) -> Result<Vec<TreePackage>, String> {
    let resolved = which::which(binary).map_err(|e| format!("{binary} not found on PATH: {e}"))?;
    let output = Command::new(resolved)
        .arg("install")
        .args([
            "--dry-run",
            "--quiet",
            "--report",
            "-",
            "--only-binary",
            ":all:",
        ])
        .args(install_args)
        .output()
        .map_err(|e| format!("run pip dry-run: {e}"))?;
    if !output.status.success() {
        return Err(format!("pip dry-run failed: {}", stderr_tail(&output)));
    }
    parse_pip_report(&String::from_utf8_lossy(&output.stdout))
}

fn parse_pip_report(json: &str) -> Result<Vec<TreePackage>, String> {
    let report: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("parse pip report: {e}"))?;
    let install = report
        .get("install")
        .and_then(|v| v.as_array())
        .ok_or("pip report has no install[] array")?;
    install
        .iter()
        .map(|item| {
            let metadata = item.get("metadata").ok_or("report item missing metadata")?;
            let field = |k: &str| {
                metadata
                    .get(k)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| format!("report item missing metadata.{k}"))
            };
            Ok(TreePackage {
                name: field("name")?,
                version: field("version")?,
            })
        })
        .collect()
}

/// Resolve npm's full would-install set by generating a lockfile in a
/// throwaway dir so the user's own lockfile is never touched. npm's
/// `--dry-run --json` only emits counts (npm/cli#6558), so we read the
/// generated `package-lock.json` instead.
///
/// `--ignore-scripts` because npm has run lifecycle scripts under
/// `--package-lock-only` before (npm/cli#2787).
fn resolve_npm_tree(binary: &str, install_args: &[String]) -> Result<Vec<TreePackage>, String> {
    let resolved = which::which(binary).map_err(|e| format!("{binary} not found on PATH: {e}"))?;
    let work = tempfile::tempdir().map_err(|e| format!("create temp dir: {e}"))?;
    for manifest in [
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        ".npmrc",
    ] {
        if std::path::Path::new(manifest).exists() {
            std::fs::copy(manifest, work.path().join(manifest))
                .map_err(|e| format!("copy {manifest}: {e}"))?;
        }
    }
    let output = Command::new(resolved)
        .arg("install")
        .args(install_args)
        .args([
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ])
        .current_dir(work.path())
        .output()
        .map_err(|e| format!("run npm lockfile resolution: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "npm lockfile resolution failed: {}",
            stderr_tail(&output)
        ));
    }
    let lock = std::fs::read_to_string(work.path().join("package-lock.json"))
        .map_err(|e| format!("read generated package-lock.json: {e}"))?;
    parse_npm_lockfile(&lock)
}

fn parse_npm_lockfile(json: &str) -> Result<Vec<TreePackage>, String> {
    let lock: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("parse package-lock.json: {e}"))?;
    let packages = lock
        .get("packages")
        .and_then(|v| v.as_object())
        .ok_or("package-lock.json has no packages map (npm < 7?)")?;
    let mut out = Vec::new();
    for (path, entry) in packages {
        if path.is_empty() {
            continue; // root project entry
        }
        if entry.get("link").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| name_from_lock_path(path));
        let (Some(name), Some(version)) = (name, entry.get("version").and_then(|v| v.as_str()))
        else {
            continue;
        };
        out.push(TreePackage {
            name,
            version: version.to_string(),
        });
    }
    Ok(out)
}

/// Derive a package name from a lockfile path key like
/// `node_modules/a/node_modules/@scope/pkg` → `@scope/pkg`.
fn name_from_lock_path(path: &str) -> Option<String> {
    let idx = path.rfind("node_modules/")?;
    let name = &path[idx + "node_modules/".len()..];
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK_REPORT: &str = r#"{"version":"1","pip_version":"24.0","install":[
        {"metadata":{"name":"oldpkg","version":"1.0.0"},"requested":true},
        {"metadata":{"name":"evildep","version":"0.4.2"},"requested":false}]}"#;

    #[test]
    fn parse_pip_report_ok() {
        let pkgs = parse_pip_report(OK_REPORT).expect("parse ok report");
        assert_eq!(
            pkgs,
            vec![
                TreePackage {
                    name: "oldpkg".to_string(),
                    version: "1.0.0".to_string()
                },
                TreePackage {
                    name: "evildep".to_string(),
                    version: "0.4.2".to_string()
                },
            ]
        );
    }

    #[test]
    fn parse_pip_report_missing_install() {
        let err = parse_pip_report(r#"{"version":"1"}"#).expect_err("no install[]");
        assert!(err.contains("no install[]"), "got: {err}");
    }

    #[test]
    fn parse_pip_report_missing_version() {
        let json = r#"{"install":[{"metadata":{"name":"x"}}]}"#;
        let err = parse_pip_report(json).expect_err("missing version");
        assert!(err.contains("metadata.version"), "got: {err}");
    }

    #[test]
    fn parse_pip_report_non_json() {
        let err = parse_pip_report("not json").expect_err("non-json");
        assert!(err.contains("parse pip report"), "got: {err}");
    }

    // lockfile-v3 with: root entry (skipped), a plain dep, a nested dep,
    // a scoped dep, and a workspace `link: true` entry (skipped).
    const NPM_LOCK: &str = r#"{
        "name": "proj", "lockfileVersion": 3,
        "packages": {
            "": {"name": "proj", "version": "1.0.0"},
            "node_modules/oldpkg": {"version": "1.0.0"},
            "node_modules/evildep": {"version": "0.4.2"},
            "node_modules/a/node_modules/b": {"version": "2.3.4"},
            "node_modules/@scope/pkg": {"version": "9.0.1"},
            "node_modules/localdep": {"resolved": "../local", "link": true},
            "packages/localdep": {"name": "localdep", "version": "0.0.1"}
        }
    }"#;

    #[test]
    fn parse_npm_lockfile_ok() {
        let mut pkgs = parse_npm_lockfile(NPM_LOCK).expect("parse npm lock");
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            pkgs,
            vec![
                TreePackage {
                    name: "@scope/pkg".to_string(),
                    version: "9.0.1".to_string()
                },
                TreePackage {
                    name: "b".to_string(),
                    version: "2.3.4".to_string()
                },
                TreePackage {
                    name: "evildep".to_string(),
                    version: "0.4.2".to_string()
                },
                TreePackage {
                    name: "localdep".to_string(),
                    version: "0.0.1".to_string()
                },
                TreePackage {
                    name: "oldpkg".to_string(),
                    version: "1.0.0".to_string()
                },
            ]
        );
    }

    #[test]
    fn parse_npm_lockfile_missing_packages() {
        let err = parse_npm_lockfile(r#"{"lockfileVersion":1}"#).expect_err("no packages map");
        assert!(err.contains("no packages map"), "got: {err}");
    }

    #[test]
    fn name_from_lock_path_handles_nested_and_scoped() {
        assert_eq!(
            name_from_lock_path("node_modules/oldpkg").as_deref(),
            Some("oldpkg")
        );
        assert_eq!(
            name_from_lock_path("node_modules/a/node_modules/b").as_deref(),
            Some("b")
        );
        assert_eq!(
            name_from_lock_path("node_modules/a/node_modules/@scope/pkg").as_deref(),
            Some("@scope/pkg")
        );
        assert_eq!(name_from_lock_path("packages/foo"), None);
    }
}
