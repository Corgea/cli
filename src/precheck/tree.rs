//! Full would-install-set resolution (the "tree pass").
//!
//! Safety invariant: resolution must never execute package code.
//! pip: `--only-binary :all:` (appended last, so it wins over CLI
//! format-control flags) prevents sdist builds (pypa/pip#13091) — BUT pip
//! applies format-control directives found *inside* `-r` files after CLI
//! parsing, so requirements files are pre-scanned and any `--no-binary` /
//! `--only-binary` line refuses the dry-run (named-only fallback) instead.
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
/// install. pip's dry-run also reads `-r` requirements files, so those make
/// an install eligible even with no named targets. npm's lockfile resolution
/// reads `package.json`, so a bare `npm install` is eligible whenever the
/// project (found like npm finds it — nearest ancestor manifest) has one.
pub fn covers_input(manager: PackageManager, parsed: &super::parse::ParsedInstall) -> bool {
    !parsed.targets.is_empty()
        || (manager == PackageManager::Pip && !parsed.requirements_files.is_empty())
        || (manager == PackageManager::Npm && npm_project_root().is_some())
}

/// Nearest ancestor file named `name`, starting at the CWD.
pub(super) fn find_up(name: &str) -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    cwd.ancestors()
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// The project directory npm itself would operate on: the nearest ancestor
/// holding `package.json`. A bare `npm install` from a subdirectory
/// installs THAT project's tree, so the gate must look there too.
pub(super) fn npm_project_root() -> Option<std::path::PathBuf> {
    Some(find_up("package.json")?.parent()?.to_path_buf())
}

/// The npm flag that redirects the project root (`--prefix`, `-C`, `-g`,
/// `--global`, `--location`), if present. The gate can't safely resolve or
/// verify the redirected project from a throwaway copy of the CWD, so the
/// callers fail closed (bare install / `npm ci`) or degrade to named-only.
pub(super) fn npm_root_redirect_flag(args: &[String]) -> Option<String> {
    const ROOT_REDIRECT_FLAGS: [&str; 5] = ["--prefix", "-C", "--global", "-g", "--location"];
    args.iter()
        .find(|a| {
            ROOT_REDIRECT_FLAGS
                .iter()
                .any(|f| a.as_str() == *f || a.starts_with(&format!("{f}=")))
        })
        .cloned()
}

/// `Err(reason)`: the dry-run failed — the caller falls back to named-only
/// and its warning carries `reason`.
pub fn resolve_tree(
    manager: PackageManager,
    install_args: &[String],
    parsed: &super::parse::ParsedInstall,
) -> Result<Vec<TreePackage>, String> {
    match manager {
        PackageManager::Pip => resolve_pip_tree(manager.binary_name(), install_args, parsed),
        PackageManager::Npm => resolve_npm_tree(manager.binary_name(), install_args),
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

fn resolve_pip_tree(
    binary: &str,
    install_args: &[String],
    parsed: &super::parse::ParsedInstall,
) -> Result<Vec<TreePackage>, String> {
    // pip applies format-control directives found INSIDE a requirements
    // file AFTER command-line parsing (acknowledged pip behavior — the file
    // parser mutates the shared FormatControl object), so a `--no-binary
    // :all:` line in a `-r` file would override the trailing CLI guard
    // below and build sdists during the dry-run. Refuse to dry-run such
    // files; the caller degrades to the named-only fallback, whose
    // requirements parser skips option lines entirely.
    if let Some((file, directive)) =
        super::parse::requirements_format_control_directive(&parsed.requirements_files)
    {
        return Err(format!(
            "{} sets {} (file-level format-control overrides the sdist guard; not dry-running)",
            file.display(),
            directive
        ));
    }
    // Same binary resolution as the exec path (pip → pip3 fallback) — the
    // tree pass must not silently degrade on pip3-only systems.
    let resolved = super::exec::resolve_binary(binary)?;
    // The non-execution guard `--only-binary :all:` is appended AFTER the
    // user's args: pip's format-control flags are last-wins per package, so a
    // user `--no-binary :all:` / `--only-binary :none:` placed in install_args
    // must not re-enable sdist builds (which would run package code during the
    // report step, violating this file's safety invariant).
    let output = Command::new(resolved)
        .arg("install")
        .args(["--dry-run", "--quiet", "--report", "-"])
        .args(install_args)
        .args(["--only-binary", ":all:"])
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

/// Direct dependency names declared by the project's `package.json` (the
/// manifest `resolve_npm_tree` copies — nearest ancestor, like npm).
/// Empty when the manifest is absent or unparsable — origin labeling then
/// degrades to `(transitive)`.
pub fn project_direct_deps() -> std::collections::HashSet<String> {
    npm_project_root()
        .and_then(|root| std::fs::read_to_string(root.join("package.json")).ok())
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
    // Flags that redirect npm's project root would defeat the throwaway-dir
    // isolation below (`--prefix` overrides `current_dir`, so the dry run
    // would write the USER'S package-lock.json) — degrade to named-only.
    if let Some(flag) = npm_root_redirect_flag(install_args) {
        return Err(format!(
            "'{flag}' redirects npm's project root; lockfile resolution skipped"
        ));
    }

    let resolved = super::exec::resolve_binary(binary)?;
    let work = tempfile::tempdir().map_err(|e| format!("create temp dir: {e}"))?;
    // Copy the manifests from the project npm would operate on (nearest
    // ancestor package.json), not just the CWD. The `.npmrc` copy is
    // config-only (registry/auth/save prefs) so resolution matches a real
    // install; CLI flags below still win over it (`--ignore-scripts` can't
    // be undone by an `ignore-scripts=false` line). A `package-lock=false`
    // `.npmrc` makes the resolution emit no lockfile → named-only fallback
    // by design, not a hole: nothing executes either way.
    let root = npm_project_root();
    for manifest in [
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        ".npmrc",
    ] {
        let src = match &root {
            Some(root) => root.join(manifest),
            None => std::path::PathBuf::from(manifest),
        };
        if src.exists() {
            std::fs::copy(&src, work.path().join(manifest))
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
    // npm gives `npm-shrinkwrap.json` precedence over `package-lock.json`,
    // so read whichever it actually produced/used, preferring the shrinkwrap.
    let lock_path = ["npm-shrinkwrap.json", "package-lock.json"]
        .iter()
        .map(|n| work.path().join(n))
        .find(|p| p.is_file())
        .ok_or("npm produced no lockfile to verify")?;
    let lock = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("read generated {}: {e}", lock_path.display()))?;
    parse_npm_lockfile(&lock)
}

pub(super) fn parse_npm_lockfile(json: &str) -> Result<Vec<TreePackage>, String> {
    let lock: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("parse package-lock.json: {e}"))?;
    // lockfileVersion 2/3 carries the `packages` map; v1 only has the
    // `dependencies` tree, which npm still understands — support both so a
    // v1 project isn't forced to bypass the gate with `--force`.
    if let Some(packages) = lock.get("packages").and_then(|v| v.as_object()) {
        Ok(packages
            .iter()
            // Only `node_modules/...` entries are registry-installed deps.
            // Skip the root project (""), symlinked workspaces (`link: true`),
            // and workspace SOURCE stanzas (`packages/foo`, `apps/bar`) — those
            // are local packages with no registry identity, so sending them to
            // the public vuln-api would falsely block a monorepo install when a
            // public package shares the name@version.
            .filter(|(path, entry)| {
                path.contains("node_modules/")
                    && entry.get("link").and_then(|v| v.as_bool()) != Some(true)
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
    } else if let Some(deps) = lock.get("dependencies").and_then(|v| v.as_object()) {
        let mut out = Vec::new();
        collect_v1_dependencies(deps, &mut out, 0)?;
        Ok(out)
    } else {
        Err("package-lock.json has neither a packages map nor a dependencies tree".to_string())
    }
}

/// npm-written v1 trees are finite (no cycles by construction), but
/// `npm ci` feeds this parser an attacker-supplied file — cap the depth so
/// a crafted deep nest can't overflow the stack. In practice serde_json's
/// own 128-level recursion limit rejects such files at parse time (each v1
/// level is two JSON levels); this cap is defense-in-depth should that
/// limit ever change. Real trees are a handful of levels deep.
const V1_MAX_DEPTH: usize = 64;

/// Recursively collect `name@version` from a lockfileVersion 1
/// `dependencies` tree. Nested `dependencies` are deduped by the caller's
/// pool; local/link entries (`"link": true`) carry no registry identity and
/// are skipped. Fails loudly past `V1_MAX_DEPTH` (callers refuse or fall
/// back — never silently truncate the verdict set).
fn collect_v1_dependencies(
    deps: &serde_json::Map<String, serde_json::Value>,
    out: &mut Vec<TreePackage>,
    depth: usize,
) -> Result<(), String> {
    if depth > V1_MAX_DEPTH {
        return Err(format!(
            "package-lock.json dependencies nest deeper than {V1_MAX_DEPTH} levels; refusing to parse"
        ));
    }
    for (name, entry) in deps {
        if entry.get("link").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }
        if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
            out.push(TreePackage {
                name: name.clone(),
                version: version.to_string(),
                requested: false,
            });
        }
        if let Some(nested) = entry.get("dependencies").and_then(|v| v.as_object()) {
            collect_v1_dependencies(nested, out, depth + 1)?;
        }
    }
    Ok(())
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

    fn pkg(name: &str, version: &str) -> TreePackage {
        TreePackage {
            name: name.to_string(),
            version: version.to_string(),
            requested: false,
        }
    }

    #[test]
    fn parse_npm_lockfile_ok() {
        let mut pkgs = parse_npm_lockfile(NPM_LOCK).expect("parse npm lock");
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        // The workspace SOURCE stanza `packages/localdep` is a local package,
        // not a registry dep — it must NOT be verdicted, only the four
        // node_modules/ entries are.
        assert_eq!(
            pkgs,
            vec![
                pkg("@scope/pkg", "9.0.1"),
                pkg("b", "2.3.4"),
                pkg("evildep", "0.4.2"),
                pkg("oldpkg", "1.0.0"),
            ]
        );
    }

    #[test]
    fn parse_npm_lockfile_v1_dependencies_tree() {
        // lockfileVersion 1 has no `packages` map — npm still understands it,
        // so the gate must too (recursing into nested `dependencies`), and
        // skip `link` entries.
        const V1: &str = r#"{
            "name": "proj", "lockfileVersion": 1,
            "dependencies": {
                "oldpkg": {"version": "1.0.0"},
                "evildep": {"version": "0.4.2", "dependencies": {
                    "deepdep": {"version": "3.2.1"}
                }},
                "locallink": {"version": "file:../local", "link": true}
            }
        }"#;
        let mut pkgs = parse_npm_lockfile(V1).expect("parse v1 lock");
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            pkgs,
            vec![
                pkg("deepdep", "3.2.1"),
                pkg("evildep", "0.4.2"),
                pkg("oldpkg", "1.0.0"),
            ]
        );
    }

    #[test]
    fn parse_npm_lockfile_neither_schema_is_error() {
        let err = parse_npm_lockfile(r#"{"lockfileVersion":1}"#).expect_err("no deps");
        assert!(err.contains("neither a packages map"), "got: {err}");
    }

    #[test]
    fn parse_npm_lockfile_v1_depth_bomb_errors_instead_of_overflowing() {
        // `npm ci` parses attacker-supplied lockfiles; a crafted deep nest
        // must hit the depth cap (loud error → refuse/fallback), not
        // overflow the stack.
        let mut inner = r#"{"version":"1.0.0"}"#.to_string();
        for _ in 0..(V1_MAX_DEPTH + 2) {
            inner = format!(r#"{{"version":"1.0.0","dependencies":{{"d":{inner}}}}}"#);
        }
        let lock = format!(r#"{{"lockfileVersion":1,"dependencies":{{"a":{inner}}}}}"#);
        let err = parse_npm_lockfile(&lock).expect_err("depth bomb must error");
        // serde_json's recursion limit fires first today; the explicit
        // V1_MAX_DEPTH cap is the backstop. Either way: loud error.
        assert!(
            err.contains("deeper than") || err.contains("recursion limit"),
            "got: {err}"
        );
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
