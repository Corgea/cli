//! Full would-install-set resolution (the "tree pass").
//!
//! Safety invariant: resolution must never execute package code.
//! pip: `--only-binary :all:` prevents sdist builds (pypa/pip#13091).
//! npm: `--ignore-scripts` guards npm/cli#2787.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

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

/// Warn-only `npm audit` second opinion: counts from
/// `metadata.vulnerabilities` plus the worst few advisories. Never blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSummary {
    pub total: u64,
    pub critical: u64,
    pub high: u64,
    pub moderate: u64,
    pub low: u64,
    pub info: u64,
    /// Worst advisories as `(package name, severity)`, capped at
    /// `AUDIT_TOP_LIMIT`, severest first.
    pub top: Vec<(String, String)>,
}

/// What `resolve_tree` hands back: the would-install set, plus (npm only)
/// a handle to the concurrent `npm audit` second opinion.
pub struct TreeResolution {
    pub packages: Vec<TreePackage>,
    pub audit: Option<AuditHandle>,
}

/// The in-flight `npm audit` second opinion: a receiver for the summary plus
/// deterministic cleanup. The CLI exits the process as soon as the gate
/// returns, which would strand the audit thread mid-poll and orphan the
/// `npm audit` child — so `collect` owns reaping both before the gate moves
/// on.
pub struct AuditHandle {
    rx: mpsc::Receiver<AuditSummary>,
    /// The audit subprocess, shared with the polling thread. Emptied by
    /// whichever side reaps it first.
    child: Arc<Mutex<Option<std::process::Child>>>,
    thread: std::thread::JoinHandle<()>,
}

impl AuditHandle {
    /// Wait up to `window` for the summary, then kill whatever is left of
    /// the subprocess and join the thread. On the happy path the child has
    /// already exited and the join is instant; a hung audit is killed now
    /// rather than left running past the CLI's exit.
    pub fn collect(self, window: Duration) -> Option<AuditSummary> {
        let summary = self.rx.recv_timeout(window).ok();
        if let Ok(mut slot) = self.child.lock() {
            if let Some(mut child) = slot.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        let _ = self.thread.join();
        summary
    }
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
    run_audit: bool,
) -> Result<Option<TreeResolution>, String> {
    match manager {
        PackageManager::Pip => {
            resolve_pip_tree(manager.binary_name(), install_args).map(|packages| {
                Some(TreeResolution {
                    packages,
                    audit: None,
                })
            })
        }
        PackageManager::Npm => {
            resolve_npm_tree(manager.binary_name(), install_args, run_audit).map(Some)
        }
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
                requested: item
                    .get("requested")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            })
        })
        .collect()
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
fn resolve_npm_tree(
    binary: &str,
    install_args: &[String],
    run_audit: bool,
) -> Result<TreeResolution, String> {
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
    let packages = parse_npm_lockfile(&lock)?;
    let audit = run_audit.then(|| spawn_audit(work, resolved));
    Ok(TreeResolution { packages, audit })
}

/// Kill the audit subprocess if it hasn't finished by then.
const AUDIT_DEADLINE: Duration = Duration::from_secs(5);

/// Cap on `AuditSummary::top` advisory entries.
const AUDIT_TOP_LIMIT: usize = 5;

/// Run `npm audit --json` in the dry-run temp dir, concurrent with the
/// verdict pool. The thread owns `work` so the dir outlives the resolver and
/// is cleaned up when the audit finishes. Any failure (spawn error, timeout,
/// unparsable output) drops the sender — the receiver sees a disconnect and
/// the gate silently skips the second opinion.
fn spawn_audit(work: tempfile::TempDir, npm: PathBuf) -> AuditHandle {
    let (tx, rx) = mpsc::channel();
    let child = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&child);
    let thread = std::thread::spawn(move || {
        if let Some(summary) = run_audit(work.path(), &npm, &slot) {
            let _ = tx.send(summary);
        }
        drop(work);
    });
    AuditHandle { rx, child, thread }
}

/// `npm audit` exits 1 when it finds advisories — that's the success case,
/// so stdout is parsed regardless of exit code. Stdout goes through a file
/// (not a pipe) so the deadline poll can't deadlock on a full pipe buffer.
/// `--package-lock-only` because the work dir holds only manifests and the
/// generated lockfile — never a `node_modules`.
///
/// The subprocess lives in `slot`, shared with `AuditHandle::collect`: the
/// poll relocks each iteration, and an empty slot means the collector
/// already reaped the child — stop quietly.
fn run_audit(
    work: &std::path::Path,
    npm: &std::path::Path,
    slot: &Mutex<Option<std::process::Child>>,
) -> Option<AuditSummary> {
    let stdout_path = work.join("corgea-npm-audit.json");
    let stdout_file = std::fs::File::create(&stdout_path).ok()?;
    let child = Command::new(npm)
        .args(["audit", "--json", "--package-lock-only"])
        .current_dir(work)
        .stdin(Stdio::null())
        .stdout(stdout_file)
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    *slot.lock().ok()? = Some(child);
    let deadline = Instant::now() + AUDIT_DEADLINE;
    loop {
        let mut guard = slot.lock().ok()?;
        let Some(child) = guard.as_mut() else {
            return None; // collector reaped the child first
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                // Exited on its own: clear the slot so the collector has
                // nothing left to kill.
                guard.take();
                break;
            }
            Ok(None) if Instant::now() < deadline => {
                drop(guard);
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let mut child = guard.take().expect("checked above");
                drop(guard);
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    parse_npm_audit(&std::fs::read_to_string(&stdout_path).ok()?)
}

/// Parse npm audit report v2 (npm 7+): counts from `metadata.vulnerabilities`,
/// `top` from the `vulnerabilities` map, severest first.
fn parse_npm_audit(json: &str) -> Option<AuditSummary> {
    let report: serde_json::Value = serde_json::from_str(json).ok()?;
    let counts = report.get("metadata")?.get("vulnerabilities")?;
    let count = |k: &str| counts.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    let (critical, high, moderate, low, info) = (
        count("critical"),
        count("high"),
        count("moderate"),
        count("low"),
        count("info"),
    );
    let total = counts
        .get("total")
        .and_then(|v| v.as_u64())
        .unwrap_or(critical + high + moderate + low + info);
    let mut top: Vec<(String, String)> = report
        .get("vulnerabilities")
        .and_then(|v| v.as_object())
        .map(|vulns| {
            vulns
                .values()
                .filter_map(|entry| {
                    Some((
                        entry.get("name")?.as_str()?.to_string(),
                        entry.get("severity")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    top.sort_by(|a, b| (severity_rank(&a.1), &a.0).cmp(&(severity_rank(&b.1), &b.0)));
    top.truncate(AUDIT_TOP_LIMIT);
    Some(AuditSummary {
        total,
        critical,
        high,
        moderate,
        low,
        info,
        top,
    })
}

/// Sort key for npm audit severities, severest first.
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "moderate" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
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
            requested: false,
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

    // npm audit report v2 shape: per-package `vulnerabilities` map plus
    // `metadata.vulnerabilities` counts.
    const AUDIT_REPORT: &str = r#"{
        "auditReportVersion": 2,
        "vulnerabilities": {
            "minimist": {"name": "minimist", "severity": "critical", "via": []},
            "lodash": {"name": "lodash", "severity": "high", "via": []},
            "ms": {"name": "ms", "severity": "moderate", "via": []}
        },
        "metadata": {"vulnerabilities":
            {"info": 0, "low": 0, "moderate": 1, "high": 1, "critical": 1, "total": 3}}
    }"#;

    #[test]
    fn parse_npm_audit_counts_and_top() {
        let summary = parse_npm_audit(AUDIT_REPORT).expect("parse audit report");
        assert_eq!(summary.total, 3);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.moderate, 1);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.info, 0);
        // Severest first: critical, high, moderate.
        assert_eq!(
            summary.top,
            vec![
                ("minimist".to_string(), "critical".to_string()),
                ("lodash".to_string(), "high".to_string()),
                ("ms".to_string(), "moderate".to_string()),
            ]
        );
    }

    #[test]
    fn parse_npm_audit_caps_top_entries() {
        let entries: Vec<String> = (0..8)
            .map(|i| format!(r#""p{i}": {{"name": "p{i}", "severity": "low"}}"#))
            .collect();
        let json = format!(
            r#"{{"vulnerabilities": {{{}}},
                "metadata": {{"vulnerabilities": {{"low": 8, "total": 8}}}}}}"#,
            entries.join(",")
        );
        let summary = parse_npm_audit(&json).expect("parse audit report");
        assert_eq!(summary.total, 8);
        assert_eq!(summary.top.len(), AUDIT_TOP_LIMIT);
    }

    #[test]
    fn parse_npm_audit_missing_total_sums_levels() {
        let json = r#"{"vulnerabilities": {},
            "metadata": {"vulnerabilities": {"high": 2, "low": 1}}}"#;
        let summary = parse_npm_audit(json).expect("parse audit report");
        assert_eq!(summary.total, 3);
    }

    #[test]
    fn parse_npm_audit_rejects_garbage() {
        assert_eq!(parse_npm_audit("not json"), None);
        assert_eq!(parse_npm_audit("{}"), None);
        assert_eq!(parse_npm_audit(r#"{"metadata": {}}"#), None);
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
