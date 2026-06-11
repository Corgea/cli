//! Hermetic e2e tests for the full-tree resolution pass
//! (`corgea pip install …` with a token + `CORGEA_VULN_API_URL` stub).
//!
//! Composes the `cli_verdict.rs` harness pattern (fake pip on a private PATH +
//! local pypi registry stub + in-crate vuln-api stub) with a dry-run-aware
//! fake pip: a `--dry-run` invocation answers with a canned pip report on
//! stdout, every other invocation records its argv to a marker and exits.
//! `oldpkg==1.0.0` is published in 2020 so recency never blocks here — every
//! block is the verdict's doing.

#![cfg(unix)]

mod common;

use common::{
    corgea_isolated, spawn_http_stub, write_fake_tree_pm, NOT_FOUND_JSON, OLDPKG_NPM_PACKUMENT,
    OLDPKG_PYPI_JSON, RESOLUTION_FAILS,
};
use corgea::vuln_api_stub::{self, PackageKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn key(eco: &str, name: &str, ver: &str) -> PackageKey {
    (eco.to_string(), name.to_string(), ver.to_string())
}

/// Pip `--report -` payload: `oldpkg` (named) + `evildep` (transitive).
const TREE_REPORT: &str = r#"{"version":"1","pip_version":"24.0","install":[
  {"metadata":{"name":"oldpkg","version":"1.0.0"},"requested":true},
  {"metadata":{"name":"evildep","version":"0.4.2"},"requested":false}]}"#;

fn vulnerable_evildep_body(ecosystem: &str) -> String {
    format!(
        r#"{{"ecosystem":"{ecosystem}","package_name":"evildep","version":"0.4.2","is_vulnerable":true,
        "matches":[{{"advisory_id":"MAL-2024-0002","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":null}}]}}"#
    )
}

/// Registry stub serving `/pypi/oldpkg/json` (pypi) and `/oldpkg` (npm
/// packument), both published 2020 → never recent. Everything else 404s.
fn spawn_pypi_stub() -> String {
    spawn_http_stub(|path| match path {
        "/pypi/oldpkg/json" => ("200 OK", OLDPKG_PYPI_JSON.to_string()),
        "/oldpkg" => ("200 OK", OLDPKG_NPM_PACKUMENT.to_string()),
        _ => ("404 Not Found", NOT_FOUND_JSON.to_string()),
    })
}

/// npm lockfile-v3 fixture: named `oldpkg` 1.0.0 + transitive `evildep` 0.4.2.
const NPM_LOCK: &str = r#"{"name":"proj","lockfileVersion":3,"packages":{
  "":{"name":"proj","version":"1.0.0"},
  "node_modules/oldpkg":{"version":"1.0.0"},
  "node_modules/evildep":{"version":"0.4.2"}}}"#;

/// `corgea` wired to the registry stub, a tree-aware fake pip, and a vuln-api
/// stub.
struct TreeHarness {
    cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

impl TreeHarness {
    /// Wires the registry + vuln-api stubs, token, and a fake `binary`
    /// (`"pip"` or `"npm"`) into a private PATH dir. `payload` is the canned
    /// tree-resolution output (pip report / npm lockfile), or
    /// `RESOLUTION_FAILS` to simulate a failed resolution.
    fn new(
        binary: &str,
        checks: HashMap<PackageKey, String>,
        statuses: HashMap<PackageKey, u16>,
        payload: &str,
        exit_code: i32,
    ) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_tree_pm(bin.path(), binary, &marker, payload, exit_code);
        let registry = spawn_pypi_stub();
        let vuln_stub = vuln_api_stub::spawn_with_statuses(checks, statuses);
        cmd.env("PATH", bin.path())
            .env("CORGEA_PYPI_REGISTRY", &registry)
            .env("CORGEA_NPM_REGISTRY", &registry)
            .env("CORGEA_VULN_API_URL", &vuln_stub.base_url)
            .env("CORGEA_TOKEN", "test-token");
        Self {
            cmd,
            marker,
            _home: home,
            _bin: bin,
        }
    }

    fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

#[test]
fn pip_transitive_vulnerable_blocks_install() {
    // Only the transitive `evildep` is flagged; the named `oldpkg` is clean.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_evildep_body("pypi"),
    );
    let mut h = TreeHarness::new("pip", checks, HashMap::new(), TREE_REPORT, 0);
    let out = h
        .cmd
        .args(["pip", "--concurrency", "2", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");
    assert_eq!(
        h.recorded_argv(),
        None,
        "pip must not run on a transitive vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evildep"), "stdout: {stdout}");
    assert!(stdout.contains("MAL-2024-0002"), "stdout: {stdout}");
    assert!(stdout.contains("(transitive)"), "stdout: {stdout}");
}

#[test]
fn pip_dry_run_failure_falls_back_with_loud_warning() {
    // Fake pip exits 2 on `--dry-run` (simulates old pip with no `--report`).
    // Stub is all-clean, so the named-only fallback proceeds.
    let mut h = TreeHarness::new("pip", HashMap::new(), HashMap::new(), RESOLUTION_FAILS, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean named-only must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("transitive dependencies not checked"),
        "stderr must carry the fallback warning: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn pip_json_carries_tree_object() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_evildep_body("pypi"),
    );
    let mut h = TreeHarness::new("pip", checks, HashMap::new(), TREE_REPORT, 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["tree"]["mode"], "full");
    assert_eq!(parsed["tree"]["transitive"][0]["name"], "evildep");
    assert_eq!(
        parsed["tree"]["transitive"][0]["verdict"]["status"],
        "vulnerable"
    );
    assert_eq!(parsed["summary"]["vulnerable"], 1);
}

#[test]
fn pip_clean_tree_proceeds() {
    // Stub default-clean (no overrides), so every resolved package is clean.
    let mut h = TreeHarness::new("pip", HashMap::new(), HashMap::new(), TREE_REPORT, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean tree must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tree: 2 packages resolved"),
        "stdout: {stdout}"
    );
}

#[test]
fn npm_transitive_vulnerable_blocks_install() {
    // The generated lockfile carries a transitive `evildep` 0.4.2 that the
    // vuln stub flags; the named `oldpkg` is clean.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_evildep_body("npm"),
    );
    let mut h = TreeHarness::new("npm", checks, HashMap::new(), NPM_LOCK, 0);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a transitive vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evildep"), "stdout: {stdout}");
    assert!(stdout.contains("MAL-2024-0002"), "stdout: {stdout}");
    assert!(stdout.contains("(transitive)"), "stdout: {stdout}");
}

#[test]
fn npm_resolution_failure_falls_back_with_warning() {
    // Fake npm exits 1 on `--package-lock-only`. Stub is all-clean, so the
    // named-only fallback proceeds with a loud warning.
    let mut h = TreeHarness::new("npm", HashMap::new(), HashMap::new(), RESOLUTION_FAILS, 0);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean named-only must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("transitive dependencies not checked"),
        "stderr must carry the fallback warning: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn npm_does_not_touch_project_lockfile() {
    // Run from a project dir holding sentinel manifests; the resolver works in
    // a throwaway copy, so after a gated run both files are byte-identical.
    let project = TempDir::new().expect("project dir");
    let pkg_json = project.path().join("package.json");
    let lock_json = project.path().join("package-lock.json");
    let pkg_sentinel = r#"{"name":"sentinel","version":"0.0.0"}"#;
    let lock_sentinel = r#"{"name":"sentinel","lockfileVersion":3,"packages":{}}"#;
    std::fs::write(&pkg_json, pkg_sentinel).expect("write package.json");
    std::fs::write(&lock_json, lock_sentinel).expect("write package-lock.json");

    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_evildep_body("npm"),
    );
    let mut h = TreeHarness::new("npm", checks, HashMap::new(), NPM_LOCK, 0);
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");

    assert_eq!(
        std::fs::read_to_string(&pkg_json).unwrap(),
        pkg_sentinel,
        "package.json must be untouched"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_json).unwrap(),
        lock_sentinel,
        "package-lock.json must be untouched"
    );
}
