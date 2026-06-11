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
    /// pip report `"requested"`: the user named this package (CLI arg or
    /// requirements file). Always false for npm — its lockfile has no
    /// equivalent flag.
    pub requested: bool,
}

/// Whether this manager's resolver has anything to resolve for the parsed
/// install. pip's dry-run and uv's compile also read `-r` requirements
/// files, so those make an install eligible even with no named targets.
/// npm's lockfile resolution reads `package.json`, so a bare `npm install`
/// is eligible whenever the working directory has one.
pub fn covers_input(manager: PackageManager, parsed: &super::parse::ParsedInstall) -> bool {
    !parsed.targets.is_empty()
        || (matches!(manager, PackageManager::Pip | PackageManager::Uv)
            && !parsed.requirements_files.is_empty())
        || (manager == PackageManager::Npm && std::path::Path::new("package.json").exists())
}

/// `Ok(None)`: manager has no safe dry-run — named-only with warning.
/// `Err(reason)`: dry-run attempted and failed — named-only, warning carries reason.
pub fn resolve_tree(
    manager: PackageManager,
    install_args: &[String],
    parsed: &super::parse::ParsedInstall,
) -> Result<Option<Vec<TreePackage>>, String> {
    match manager {
        PackageManager::Pip => resolve_pip_tree(manager.binary_name(), install_args).map(Some),
        PackageManager::Npm => resolve_npm_tree(manager.binary_name(), install_args).map(Some),
        PackageManager::Uv => resolve_uv_tree(parsed).map(Some),
        // yarn/pnpm have no safe dry-run for installs.
        PackageManager::Yarn | PackageManager::Pnpm => Ok(None),
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
    // Same binary resolution as the exec path (pip → pip3 fallback) — the
    // tree pass must not silently degrade on pip3-only systems.
    let resolved = super::resolve_binary(binary)?;
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
                requested: item
                    .get("requested")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            })
        })
        .collect()
}

/// Resolve uv's would-install set with `uv pip compile` — uv's own
/// resolver, run without executing package code (`--only-binary :all:`
/// blocks sdist builds, mirroring the pip dry-run guard). Compile takes
/// requirements files rather than bare specs, so named registry specs and
/// absolutized `-r` includes are written to a temp `.in` file.
/// Unverifiable targets (URL / git / editable / path) are excluded — they
/// are already surfaced as skipped warnings. Index selection comes from
/// uv's env/config; index flags on the wrapped command don't carry over.
fn resolve_uv_tree(parsed: &super::parse::ParsedInstall) -> Result<Vec<TreePackage>, String> {
    let uv = super::resolve_binary("uv")?;
    let mut input = String::new();
    for t in &parsed.targets {
        if !matches!(t.kind, super::TargetKind::Unverifiable { .. }) {
            input.push_str(&t.display);
            input.push('\n');
        }
    }
    for f in &parsed.requirements_files {
        let abs = std::fs::canonicalize(f).map_err(|e| format!("read {}: {e}", f.display()))?;
        input.push_str(&format!("-r {}\n", abs.display()));
    }
    if input.is_empty() {
        return Err("nothing uv pip compile can resolve (all targets are URL/path refs)".into());
    }

    let work = tempfile::tempdir().map_err(|e| format!("create temp dir: {e}"))?;
    let in_file = work.path().join("corgea-gate.in");
    std::fs::write(&in_file, &input).map_err(|e| format!("write compile input: {e}"))?;
    let output = Command::new(&uv)
        .args([
            "pip",
            "compile",
            "--only-binary",
            ":all:",
            "--no-header",
            "--no-annotate",
            "--quiet",
        ])
        .arg(&in_file)
        .output()
        .map_err(|e| format!("run uv pip compile: {e}"))?;
    if !output.status.success() {
        return Err(format!("uv pip compile failed: {}", stderr_tail(&output)));
    }
    parse_compiled_requirements(
        &String::from_utf8_lossy(&output.stdout),
        &requested_names(parsed),
    )
}

/// Normalized names the user asked for — named CLI targets plus entries of
/// `-r` files — so tree findings label "(from requirements)" like pip's
/// `requested` report flag. Best-effort line parse; anything unparsed just
/// labels "(transitive)".
fn requested_names(parsed: &super::parse::ParsedInstall) -> std::collections::HashSet<String> {
    let norm = |n: &str| PackageManager::Uv.normalize_name(n);
    let mut out: std::collections::HashSet<String> = parsed
        .targets
        .iter()
        .filter(|t| !matches!(t.kind, super::TargetKind::Unverifiable { .. }))
        .map(|t| norm(&t.name))
        .collect();
    for f in &parsed.requirements_files {
        let Ok(content) = std::fs::read_to_string(f) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', '-']) || line.contains("://") {
                continue;
            }
            let name: String = line
                .chars()
                .take_while(|c| !matches!(c, '[' | '<' | '>' | '=' | '!' | '~' | ';' | ' '))
                .collect();
            if !name.is_empty() {
                out.insert(norm(&name));
            }
        }
    }
    out
}

/// Parse `uv pip compile` stdout (requirements.txt-format `name==version`
/// pins) into the would-install set. Any line that isn't a pin is an error —
/// silently skipping could hide part of the tree.
fn parse_compiled_requirements(
    out: &str,
    requested: &std::collections::HashSet<String>,
) -> Result<Vec<TreePackage>, String> {
    let mut pkgs = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', '-']) {
            continue;
        }
        // Strip env markers and trailing comments: `pkg==1.0 ; marker  # via`.
        let line = line.split(';').next().unwrap_or(line).trim();
        let line = line.split(" #").next().unwrap_or(line).trim();
        let Some((name, version)) = line.split_once("==") else {
            return Err(format!(
                "unexpected line in uv pip compile output: '{line}'"
            ));
        };
        // Strip extras: `celery[redis]==5.3.4`.
        let name = name.split('[').next().unwrap_or(name).trim().to_string();
        pkgs.push(TreePackage {
            requested: requested.contains(&PackageManager::Uv.normalize_name(&name)),
            name,
            version: version.trim().to_string(),
        });
    }
    if pkgs.is_empty() {
        return Err("uv pip compile produced no packages".to_string());
    }
    Ok(pkgs)
}

/// Direct dependency names declared by the project's `package.json` in the
/// current directory (the manifest `resolve_npm_tree` copies). Empty when
/// the manifest is absent or unparsable — origin labeling then degrades to
/// `(transitive)`.
pub fn project_direct_deps() -> std::collections::HashSet<String> {
    std::fs::read_to_string("package.json")
        .map(|s| direct_deps_from_manifest(&s))
        .unwrap_or_default()
}

fn direct_deps_from_manifest(json: &str) -> std::collections::HashSet<String> {
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(json) else {
        return Default::default();
    };
    let groups = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    groups
        .iter()
        .filter_map(|g| manifest.get(g)?.as_object())
        .flat_map(|deps| deps.keys().cloned())
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
    let resolved = super::resolve_binary(binary)?;
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
    let output = Command::new(&resolved)
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
    Ok(packages
        .iter()
        // Skip the root project entry ("") and symlinked (workspace) entries.
        .filter(|(path, entry)| {
            !path.is_empty() && entry.get("link").and_then(|v| v.as_bool()) != Some(true)
        })
        .filter_map(|(path, entry)| {
            let name = entry
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| name_from_lock_path(path))?;
            let version = entry.get("version").and_then(|v| v.as_str())?;
            Some(TreePackage {
                name,
                version: version.to_string(),
                requested: false,
            })
        })
        .collect())
}

/// Derive a package name from a lockfile path key like
/// `node_modules/a/node_modules/@scope/pkg` → `@scope/pkg`. `None` for keys
/// outside `node_modules/` (workspace stanzas carry an explicit `name`).
fn name_from_lock_path(path: &str) -> Option<String> {
    if !path.contains("node_modules/") {
        return None;
    }
    let name = crate::deps::ecosystems::npm::package_name_from_lock_key(path);
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
                    version: "1.0.0".to_string(),
                    requested: true,
                },
                TreePackage {
                    name: "evildep".to_string(),
                    version: "0.4.2".to_string(),
                    requested: false,
                },
            ]
        );
    }

    #[test]
    fn parse_pip_report_missing_requested_defaults_false() {
        let json = r#"{"install":[{"metadata":{"name":"x","version":"1.0.0"}}]}"#;
        let pkgs = parse_pip_report(json).expect("parse report without requested");
        assert!(!pkgs[0].requested);
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

    #[test]
    fn parse_compiled_requirements_pins_extras_and_markers() {
        let requested = std::collections::HashSet::from(["flask-cors".to_string()]);
        let out = "Flask_Cors==4.0.0\ncelery[redis]==5.3.4\nwerkzeug==3.1.8 ; python_version >= \"3.9\"\n\n# comment\n--index-url https://example.com\n";
        let pkgs = parse_compiled_requirements(out, &requested).expect("parse pins");
        assert_eq!(
            pkgs,
            vec![
                TreePackage {
                    name: "Flask_Cors".to_string(),
                    version: "4.0.0".to_string(),
                    requested: true,
                },
                TreePackage {
                    name: "celery".to_string(),
                    version: "5.3.4".to_string(),
                    requested: false,
                },
                TreePackage {
                    name: "werkzeug".to_string(),
                    version: "3.1.8".to_string(),
                    requested: false,
                },
            ]
        );
    }

    #[test]
    fn parse_compiled_requirements_rejects_non_pins() {
        let none = std::collections::HashSet::new();
        let err = parse_compiled_requirements("flask>=2.0\n", &none).expect_err("not a pin");
        assert!(err.contains("unexpected line"), "got: {err}");
        let err = parse_compiled_requirements("", &none).expect_err("empty");
        assert!(err.contains("no packages"), "got: {err}");
    }

    #[test]
    fn requested_names_unions_targets_and_requirements_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let req = dir.path().join("requirements.txt");
        std::fs::write(
            &req,
            "# comment\nFlask_Cors==4.0.0\nrequests[security]>=2.0 ; python_version >= \"3.9\"\n-r other.txt\nhttps://example.com/pkg.whl\n",
        )
        .expect("write requirements");
        let parsed = super::super::parse::ParsedInstall {
            targets: vec![super::super::InstallTarget {
                name: "celery".to_string(),
                display: "celery==5.3.4".to_string(),
                kind: super::super::TargetKind::Pypi(
                    crate::verify_deps::registry::PypiSpec::Exact("5.3.4".to_string()),
                ),
            }],
            requirements_files: vec![req],
        };
        let names = requested_names(&parsed);
        for name in ["celery", "flask-cors", "requests"] {
            assert!(names.contains(name), "missing {name}: {names:?}");
        }
        assert_eq!(names.len(), 3);
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
        let pkg = |name: &str, version: &str| TreePackage {
            name: name.to_string(),
            version: version.to_string(),
            requested: false,
        };
        assert_eq!(
            pkgs,
            vec![
                pkg("@scope/pkg", "9.0.1"),
                pkg("b", "2.3.4"),
                pkg("evildep", "0.4.2"),
                pkg("localdep", "0.0.1"),
                pkg("oldpkg", "1.0.0"),
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

    #[test]
    fn direct_deps_from_manifest_unions_all_groups() {
        let manifest = r#"{
            "name": "proj",
            "dependencies": {"a": "^1.0.0", "@scope/b": "2.x"},
            "devDependencies": {"c": "*"},
            "optionalDependencies": {"d": "1.2.3"},
            "peerDependencies": {"e": ">=1"}
        }"#;
        let deps = direct_deps_from_manifest(manifest);
        for name in ["a", "@scope/b", "c", "d", "e"] {
            assert!(deps.contains(name), "missing {name}");
        }
        assert_eq!(deps.len(), 5);
    }

    #[test]
    fn direct_deps_from_manifest_degrades_to_empty() {
        assert!(direct_deps_from_manifest("not json").is_empty());
        assert!(direct_deps_from_manifest(r#"{"name":"proj"}"#).is_empty());
        assert!(direct_deps_from_manifest(r#"{"dependencies":[]}"#).is_empty());
    }
}
