//! Hermetic e2e tests for zero-spec ("bare") installs.
//!
//! With a `package.json`, bare `npm install` is gated like any other
//! install: the tree pass resolves the full lockfile set and verdicts
//! every package, so a vulnerable lockfile blocks (exit 1, `--force`
//! escape).
//!
//! Harness mirrors `cli_tree.rs`: tree-aware fake npm on a private PATH +
//! local registry stub + in-crate vuln-api stub. `oldpkg` is published in
//! 2020 so recency never blocks here.

#![cfg(unix)]

mod common;

use common::{key, vulnerable_body, GateHarness, NPM_LOCK, RESOLUTION_FAILS};
use std::collections::HashMap;

const PACKAGE_JSON: &str = r#"{"name":"proj","version":"1.0.0","dependencies":{"oldpkg":"1.0.0"}}"#;

#[test]
fn bare_npm_install_vulnerable_lockfile_blocks() {
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "vulnerable lockfile must block");
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evildep"), "stdout: {stdout}");
    assert!(stdout.contains("MAL-2024-0002"), "stdout: {stdout}");
    assert!(stdout.contains("(transitive)"), "stdout: {stdout}");
    // A bare install names no targets, so everything resolved is the
    // existing tree's — the refusal must say so.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("your existing dependency tree has known-vulnerable packages"),
        "bare install blames the existing tree: {stderr}"
    );
}

#[test]
fn bare_npm_install_clean_lockfile_proceeds() {
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean tree must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tree: 2 packages resolved"),
        "stdout: {stdout}"
    );
}

#[test]
fn bare_npm_install_force_overrides_block() {
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h
        .cmd
        .args(["npm", "--force", "install"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "--force must run the install");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("evildep"),
        "findings still printed under --force"
    );
}

#[test]
fn bare_npm_resolution_failure_falls_back_with_warning() {
    // Fake npm exits 1 on `--package-lock-only`. Nothing named remains to
    // verify, so the install proceeds behind the loud fallback warning.
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", RESOLUTION_FAILS, 0)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .with_project_file("package.json", PACKAGE_JSON)
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "fallback must proceed");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("transitive dependencies not checked"),
        "stderr must carry the fallback warning: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bare_npm_without_package_json_passes_through() {
    // No package.json in cwd → nothing to resolve → straight exec, no gate.
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 3)
        .oldpkg_registry()
        .vuln_checks(HashMap::new())
        .in_project_dir()
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(3), "npm's own exit code propagates");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("Pre-checking"), "stdout: {stdout}");
}

#[test]
fn bare_npm_install_from_subdirectory_is_gated() {
    // npm walks ancestors to find the project; the gate must too, or a
    // bare install from <project>/src would install the whole (vulnerable)
    // tree silently unchecked.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    let mut h = GateHarness::new()
        .fake_tree_pm("npm", NPM_LOCK, 0)
        .oldpkg_registry()
        .vuln_checks(checks)
        .with_project_file("package.json", PACKAGE_JSON)
        .in_subdir("src")
        .build();
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "vulnerable lockfile must block from a subdirectory too"
    );
    assert_eq!(
        h.recorded_argv(),
        None,
        "npm must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evildep"), "stdout: {stdout}");
}
