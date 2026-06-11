//! Hermetic e2e tests for the `corgea uv sync` gate.
//!
//! `uv sync` is gated from the project's `uv.lock`: every
//! index-sourced pin is verdicted against the vuln-api stub before uv runs.
//! Without a lockfile it execs behind an honest note.
//! Harness: fake `uv` argv recorder on a private PATH + in-crate vuln-api
//! stub + throwaway project dir as cwd. No registry stub — the sync gate
//! does no recency resolution.

#![cfg(unix)]

mod common;

use common::{key, vulnerable_body, GateHarness};
use corgea::vuln_api_stub::PackageKey;
use std::collections::HashMap;

/// `proj` is the project itself (editable — skipped); `evildep` is the one
/// index-sourced pin the gate must verdict.
const UV_LOCK: &str = r#"
version = 1

[[package]]
name = "proj"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "evildep"
version = "0.4.2"
source = { registry = "https://pypi.org/simple" }
"#;

fn vulnerable_evildep_checks() -> HashMap<PackageKey, String> {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_body("pypi", "evildep", "0.4.2", "MAL-2024-0002", None),
    );
    checks
}

#[test]
fn uv_sync_vulnerable_lockfile_blocks() {
    let mut h = GateHarness::new()
        .fake_recorder("uv", 0)
        .vuln_checks(vulnerable_evildep_checks())
        .token("test-token")
        .with_project_file("uv.lock", UV_LOCK)
        .build();
    let out = h.cmd.args(["uv", "sync"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "vulnerable lock must block");
    assert_eq!(
        h.recorded_argv(),
        None,
        "uv must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in ["evildep", "MAL-2024-0002", "(locked)"] {
        assert!(stdout.contains(needle), "stdout: {stdout}");
    }
    // Nothing was named by this command — the refusal blames the lock, not
    // the user's input.
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("your existing dependency tree has known-vulnerable packages"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn uv_sync_clean_lockfile_proceeds() {
    let mut h = GateHarness::new()
        .fake_recorder("uv", 0)
        .vuln_checks(HashMap::new())
        .token("test-token")
        .with_project_file("uv.lock", UV_LOCK)
        .build();
    let out = h
        .cmd
        .args(["uv", "sync", "--frozen"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean lock must proceed");
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("sync --frozen"),
        "uv's own args must be forwarded untouched"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tree: 1 packages resolved"),
        "the project's own editable stanza must be skipped: {stdout}"
    );
}

#[test]
fn uv_sync_force_overrides_block() {
    let mut h = GateHarness::new()
        .fake_recorder("uv", 0)
        .vuln_checks(vulnerable_evildep_checks())
        .token("test-token")
        .with_project_file("uv.lock", UV_LOCK)
        .build();
    let out = h
        .cmd
        .args(["uv", "--force", "sync"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "--force must run the sync");
    assert_eq!(h.recorded_argv().as_deref(), Some("sync"));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("evildep"),
        "findings still printed under --force"
    );
}

#[test]
fn uv_sync_without_lockfile_execs_with_note() {
    let mut h = GateHarness::new()
        .fake_recorder("uv", 0)
        .vuln_checks(HashMap::new())
        .token("test-token")
        .in_project_dir()
        .build();
    let out = h.cmd.args(["uv", "sync"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("sync"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("'uv sync' is not gated"),
        "stderr must carry the explicit ungated note: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn uv_sync_malformed_lockfile_fails_closed() {
    let mut h = GateHarness::new()
        .fake_recorder("uv", 0)
        .vuln_checks(HashMap::new())
        .token("test-token")
        .with_project_file("uv.lock", "not = [valid")
        .build();
    let out = h.cmd.args(["uv", "sync"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "unparseable lock must block");
    assert_eq!(h.recorded_argv(), None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot verify 'uv sync'"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("--force"), "stderr: {stderr}");
}

#[test]
fn uv_sync_tokenless_runs_public_lock_check() {
    let mut h = GateHarness::new()
        .fake_recorder("uv", 0)
        .vuln_checks(HashMap::new())
        .with_project_file("uv.lock", UV_LOCK)
        .build();
    let out = h.cmd.args(["uv", "sync"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("sync"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Pre-checking"), "stdout: {stdout}");
    assert!(
        stdout.contains("tree: 1 packages resolved"),
        "stdout: {stdout}"
    );
}

#[test]
fn uv_lock_stays_passthrough() {
    // `uv lock` installs nothing; the gate applies to the sync that follows.
    let mut h = GateHarness::new()
        .fake_recorder("uv", 0)
        .vuln_checks(vulnerable_evildep_checks())
        .token("test-token")
        .with_project_file("uv.lock", UV_LOCK)
        .build();
    let out = h.cmd.args(["uv", "lock"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("lock"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Pre-checking"));
}
