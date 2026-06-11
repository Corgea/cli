//! Hermetic e2e tests for the `corgea uv sync` gate.
//!
//! With a token, `uv sync` is gated from the project's `uv.lock`: every
//! index-sourced pin is verdicted against the vuln-api stub before uv runs.
//! Without a lockfile (or without a token) it execs behind an honest note.
//! Harness: fake `uv` argv recorder on a private PATH + in-crate vuln-api
//! stub + throwaway project dir as cwd. No registry stub — the sync gate
//! does no recency resolution.

#![cfg(unix)]

mod common;

use common::{corgea_isolated, key, vulnerable_body, write_fake_recorder};
use corgea::vuln_api_stub::{self, PackageKey};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

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

struct SyncHarness {
    cmd: Command,
    marker: PathBuf,
    project: TempDir,
    _home: TempDir,
    _bin: TempDir,
}

impl SyncHarness {
    fn new(checks: HashMap<PackageKey, String>) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let project = TempDir::new().expect("project dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_recorder(bin.path(), "uv", &marker, 0);
        let vuln_stub = vuln_api_stub::spawn_with_statuses(checks, HashMap::new());
        cmd.env("PATH", bin.path())
            .env("CORGEA_VULN_API_URL", &vuln_stub.base_url)
            .env("CORGEA_TOKEN", "test-token")
            .current_dir(project.path());
        Self {
            cmd,
            marker,
            project,
            _home: home,
            _bin: bin,
        }
    }

    fn with_uv_lock(self, content: &str) -> Self {
        std::fs::write(self.project.path().join("uv.lock"), content).expect("write uv.lock");
        self
    }

    fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

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
    let mut h = SyncHarness::new(vulnerable_evildep_checks()).with_uv_lock(UV_LOCK);
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
    let mut h = SyncHarness::new(HashMap::new()).with_uv_lock(UV_LOCK);
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
    let mut h = SyncHarness::new(vulnerable_evildep_checks()).with_uv_lock(UV_LOCK);
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
    let mut h = SyncHarness::new(HashMap::new());
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
    let mut h = SyncHarness::new(HashMap::new()).with_uv_lock("not = [valid");
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
fn uv_sync_tokenless_passes_through() {
    let mut h = SyncHarness::new(HashMap::new()).with_uv_lock(UV_LOCK);
    h.cmd.env_remove("CORGEA_TOKEN");
    let out = h.cmd.args(["uv", "sync"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("sync"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Pre-checking"));
}

#[test]
fn uv_lock_stays_passthrough() {
    // `uv lock` installs nothing; the gate applies to the sync that follows.
    let mut h = SyncHarness::new(vulnerable_evildep_checks()).with_uv_lock(UV_LOCK);
    let out = h.cmd.args(["uv", "lock"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("lock"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Pre-checking"));
}
