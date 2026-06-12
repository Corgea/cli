//! Hermetic e2e tests for refusal-message context: the refusal blames the
//! existing tree only when every vulnerable finding predates the command
//! (bare installs, or manifest-declared pre-existing deps — see
//! `cli_bare_install.rs` for the positive case). A finding on a named
//! target, or a transitive finding the named targets pull in, keeps the
//! generic refusal.
//!
//! Same harness as `cli_tree.rs`, pip-only: a fake pip on a private PATH
//! answers the `--dry-run --report -` tree pass with a canned report, a local
//! pypi registry stub publishes `oldpkg` in 2020 (recency never blocks), and
//! the in-crate vuln-api stub supplies verdicts. Every block here is the
//! verdict's doing.

#![cfg(unix)]

mod common;

use common::{key, TreeHarness, TREE_REPORT};
use corgea::vuln_api_stub::PackageKey;
use std::collections::HashMap;
use tempfile::TempDir;

/// Refusal when the existing tree alone caused the block.
const TREE_REFUSAL: &str = "Refusing to run install: your existing dependency tree has known-vulnerable packages (none were added by this command). Fix them or pass --force.";
/// Refusal when a named target carries a blocking verdict.
const GENERIC_REFUSAL: &str = "Refusing to run install. Pass --force to proceed despite findings.";

fn vulnerable_body(name: &str, version: &str) -> String {
    common::vulnerable_body("pypi", name, version, "MAL-2024-0002", None)
}

fn harness(checks: HashMap<PackageKey, String>, statuses: HashMap<PackageKey, u16>) -> TreeHarness {
    TreeHarness::new("pip", checks, statuses, TREE_REPORT)
}

fn run_install(h: &mut TreeHarness) -> std::process::Output {
    h.cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea")
}

#[test]
fn named_install_with_transitive_vulnerable_keeps_generic_refusal() {
    // Only the transitive `evildep` is flagged; the named `oldpkg` is clean.
    // `evildep` is being pulled in *by this command*, so the existing-tree
    // refusal ("none were added by this command") would lie.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_body("evildep", "0.4.2"),
    );
    let mut h = harness(checks, HashMap::new());
    let out = run_install(&mut h);

    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");
    assert!(
        h.recorded_argv().is_none(),
        "pip must not run on a blocked install"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(GENERIC_REFUSAL),
        "a transitive dep of a named target keeps the generic refusal: {stderr}"
    );
    assert!(
        !stderr.contains(TREE_REFUSAL),
        "existing-tree refusal must not fire for command-added transitives: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 vulnerable (1 from resolved tree)"),
        "summary must attribute the finding to the tree: {stdout}"
    );
}

/// PR #108 review regression: a requirements-only install has no named
/// outcomes — exactly like a bare install — but its resolved set is added
/// by this command. A vulnerable transitive of a clean requirements entry
/// must keep the generic refusal.
#[test]
fn requirements_only_install_with_vulnerable_transitive_keeps_generic_refusal() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_body("evildep", "0.4.2"),
    );
    let mut h = harness(checks, HashMap::new());
    // `pip install -r reqs.txt` with no named targets — the canned tree
    // report still resolves oldpkg (requested) + evildep (transitive).
    let reqs_dir = TempDir::new().expect("reqs dir");
    let reqs = reqs_dir.path().join("reqs.txt");
    std::fs::write(&reqs, "oldpkg==1.0.0\n").expect("write reqs.txt");
    let out = h
        .cmd
        .args(["pip", "install", "-r"])
        .arg(&reqs)
        .output()
        .expect("run corgea");

    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");
    assert!(
        h.recorded_argv().is_none(),
        "pip must not run on a blocked install"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(GENERIC_REFUSAL),
        "requirements-driven transitives keep the generic refusal: {stderr}"
    );
    assert!(
        !stderr.contains(TREE_REFUSAL),
        "existing-tree refusal must not fire for a requirements-only install: {stderr}"
    );
}

#[test]
fn named_vulnerable_keeps_generic_refusal() {
    // The named `oldpkg` itself is flagged; `evildep` is clean.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("oldpkg", "1.0.0"),
    );
    let mut h = harness(checks, HashMap::new());
    let out = run_install(&mut h);

    assert_eq!(out.status.code(), Some(1), "named vuln must block");
    assert!(
        h.recorded_argv().is_none(),
        "pip must not run on a blocked install"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(GENERIC_REFUSAL),
        "named finding keeps the generic refusal: {stderr}"
    );
    assert!(
        !stderr.contains(TREE_REFUSAL),
        "existing-tree refusal must not fire on a named finding: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("from resolved tree"),
        "summary must not attribute a named finding to the tree: {stdout}"
    );
}

#[test]
fn named_unverifiable_with_transitive_vulnerable_keeps_generic_refusal() {
    // The named `oldpkg` verdict 503s (unverifiable, fail-closed) while the
    // transitive `evildep` is vulnerable. The command's own target is part of
    // the block, so the existing-tree refusal would mislead.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_body("evildep", "0.4.2"),
    );
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    let mut h = harness(checks, statuses);
    let out = run_install(&mut h);

    assert_eq!(out.status.code(), Some(1), "must block");
    assert!(
        h.recorded_argv().is_none(),
        "pip must not run on a blocked install"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(GENERIC_REFUSAL),
        "named unverifiable keeps the generic refusal: {stderr}"
    );
    assert!(
        !stderr.contains(TREE_REFUSAL),
        "existing-tree refusal must not fire while a named target blocks: {stderr}"
    );
}
