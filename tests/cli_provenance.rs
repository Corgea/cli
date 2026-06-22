//! Hermetic e2e tests for provenance labels on tree-pass findings:
//! `(from requirements)` for pip-requested packages, `(already in
//! package.json)` for npm direct deps the project already declares (plus the
//! `fix with:` advertised-fix hint), `(transitive)` otherwise.
//!
//! Same harness pattern as `cli_tree.rs`: fake package manager on a private
//! PATH (answers the tree-resolution invocation with a canned payload),
//! a local registry stub, and the in-crate vuln-api stub. `oldpkg` is
//! published in 2020 so recency never blocks — every block is the verdict's.

#![cfg(unix)]

mod common;

use common::{key, tree_harness, GateHarness, NPM_LOCK};
use std::collections::HashMap;

/// Vulnerable verdict body; `fixed: None` renders `"fixed_version":null`.
fn vulnerable_body(ecosystem: &str, name: &str, version: &str, fixed: Option<&str>) -> String {
    common::vulnerable_body(ecosystem, name, version, "MAL-2024-0002", fixed)
}

/// Pip report: only `reqpkg`, requested (as if it came from a `-r` file).
const PIP_REQ_REPORT: &str = r#"{"version":"1","pip_version":"24.0","install":[
  {"metadata":{"name":"reqpkg","version":"6.0.0"},"requested":true}]}"#;

/// Project manifest that already declares `evildep` as a direct dep.
const PROJECT_MANIFEST: &str =
    r#"{"name":"proj","version":"1.0.0","dependencies":{"evildep":"^0.4.0"}}"#;

/// npm tree harness whose project dir holds a `package.json` that already
/// declares `evildep` as a direct dep.
fn npm_project_harness(
    checks: HashMap<corgea::vuln_api_stub::PackageKey, String>,
    payload: &str,
) -> GateHarness {
    tree_harness("npm", checks, HashMap::new(), payload)
        .with_project_file("package.json", PROJECT_MANIFEST)
}

#[test]
fn pip_requirements_finding_labeled_from_requirements() {
    // The flagged package comes from a `-r` file (pip marks it `requested`),
    // so it must not be mislabeled "(transitive)".
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "reqpkg", "6.0.0"),
        vulnerable_body("pypi", "reqpkg", "6.0.0", None),
    );
    let mut h = tree_harness("pip", checks, HashMap::new(), PIP_REQ_REPORT);
    let out = h
        .cmd
        .args(["pip", "install", "-r", "reqs.txt"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "requested vuln must block");
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("reqpkg@6.0.0 (from requirements)"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("(transitive)"), "stdout: {stdout}");
}

#[test]
fn npm_preexisting_direct_dep_labeled_with_fix_hint() {
    // `evildep` is already a direct dep in the project's package.json; the
    // finding gets the pre-existing label plus the fix-command hint. The
    // fix 1.2.2 covers every advisory (`safe_version` is Some), so the hint
    // drops the "(advertised fix)" hedge.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", Some("1.2.2")),
    );
    let mut h = npm_project_harness(checks, NPM_LOCK);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "pre-existing vuln must block");
    assert_eq!(h.recorded_argv(), None, "npm must not run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("evildep@0.4.2 (already in package.json)"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("fix with: corgea npm install evildep@1.2.2\n"),
        "verified fix hint must print without the advertised-fix hedge: {stdout}"
    );
}

#[test]
fn npm_preexisting_fix_hint_keeps_hedge_when_fix_is_partial() {
    // One advisory advertises fix 1.2.2, the other has no fix: bumping is
    // still the best move but doesn't clear everything, so the steer line
    // stays quiet and the fix-command hint keeps its "(advertised fix)"
    // hedge.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        r#"{"ecosystem":"npm","package_name":"evildep","version":"0.4.2","is_vulnerable":true,
        "matches":[{"advisory_id":"MAL-2024-0002","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":"1.2.2"},
                   {"advisory_id":"MAL-2024-0003","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":null}]}"#
            .to_string(),
    );
    let mut h = npm_project_harness(checks, NPM_LOCK);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "pre-existing vuln must block");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("fix with: corgea npm install evildep@1.2.2 (advertised fix)"),
        "partial fix hint must keep the hedge: {stdout}"
    );
    assert!(
        !stdout.contains("→ safe version"),
        "a partial fix must not print the steer: {stdout}"
    );
}

#[test]
fn npm_preexisting_without_fix_has_no_hint() {
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", None),
    );
    let mut h = npm_project_harness(checks, NPM_LOCK);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("evildep@0.4.2 (already in package.json)"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("fix with:"),
        "no advertised fix → no hint; stdout: {stdout}"
    );
}

#[test]
fn named_install_with_transitive_vulnerable_keeps_generic_refusal() {
    // A named install pulling in a vulnerable transitive is the command's
    // doing — the refusal must NOT blame the existing tree.
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", None),
    );
    let mut h = tree_harness("npm", checks, HashMap::new(), NPM_LOCK);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Refusing to run install. Pass --force to proceed despite findings."),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("your existing dependency tree"),
        "a command-added transitive must not blame the existing tree: {stderr}"
    );
}
