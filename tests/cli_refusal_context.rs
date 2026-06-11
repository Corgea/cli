//! Hermetic e2e tests for refusal-message context: when every vulnerable
//! finding sits in the resolved tree beyond the named targets, the refusal
//! must say the existing tree is the problem; a finding on a named target
//! keeps the generic refusal.
//!
//! Same harness as `cli_tree.rs`, pip-only: a fake pip on a private PATH
//! answers the `--dry-run --report -` tree pass with a canned report, a local
//! pypi registry stub publishes `oldpkg` in 2020 (recency never blocks), and
//! the in-crate vuln-api stub supplies verdicts. Every block here is the
//! verdict's doing.

#![cfg(unix)]

mod common;

use common::corgea_isolated;
use corgea::vuln_api_stub::{self, PackageKey};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use tempfile::TempDir;

/// Refusal when the existing tree alone caused the block.
const TREE_REFUSAL: &str = "Refusing to run install: your existing dependency tree has known-vulnerable packages (none were added by this command). Fix them or pass --force.";
/// Refusal when a named target carries a blocking verdict.
const GENERIC_REFUSAL: &str = "Refusing to run install. Pass --force to proceed despite findings.";

fn key(eco: &str, name: &str, ver: &str) -> PackageKey {
    (eco.to_string(), name.to_string(), ver.to_string())
}

/// Pip `--report -` payload: `oldpkg` (named) + `evildep` (transitive).
const TREE_REPORT: &str = r#"{"version":"1","pip_version":"24.0","install":[
  {"metadata":{"name":"oldpkg","version":"1.0.0"},"requested":true},
  {"metadata":{"name":"evildep","version":"0.4.2"},"requested":false}]}"#;

fn vulnerable_body(name: &str, version: &str) -> String {
    format!(
        r#"{{"ecosystem":"pypi","package_name":"{name}","version":"{version}","is_vulnerable":true,
        "matches":[{{"advisory_id":"MAL-2024-0002","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":null}}]}}"#
    )
}

/// Registry stub serving `/pypi/oldpkg/json`, published 2020 → never recent.
/// Everything else 404s.
fn spawn_pypi_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 1024];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");

            let (status, body) = match path {
                "/pypi/oldpkg/json" => (
                    "200 OK",
                    r#"{"info":{"name":"oldpkg"},"releases":{"1.0.0":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z"}]}}"#,
                ),
                _ => ("404 Not Found", r#"{"message":"not found"}"#),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    base_url
}

/// Write an executable fake pip into `dir`. A `--dry-run` invocation emits
/// the canned tree report on stdout and exits 0; any other invocation records
/// its argv to `marker` and exits 0. The payload is read via shell builtins
/// because the test's locked-down `PATH` has no `cat`; the `|| [ -n "$line" ]`
/// guard keeps the final line when the payload file has no trailing newline.
fn write_fake_pip(dir: &Path, marker: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let payload_path = dir.join("pip-tree-payload.json");
    std::fs::write(&payload_path, TREE_REPORT).expect("write fake pip payload");
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) while IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < '{payload}'; exit 0;; esac\nprintf '%s' \"$*\" > '{marker}'\nexit 0\n",
        payload = payload_path.display(),
        marker = marker.display(),
    );
    let path = dir.join("pip");
    std::fs::write(&path, script).expect("write fake pip");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake pip");
}

/// `corgea` wired to the registry stub, a tree-aware fake pip, and a vuln-api
/// stub.
struct Harness {
    cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

impl Harness {
    fn new(checks: HashMap<PackageKey, String>, statuses: HashMap<PackageKey, u16>) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_pip(bin.path(), &marker);
        let registry = spawn_pypi_stub();
        let vuln_stub = vuln_api_stub::spawn_with_statuses(checks, statuses);
        cmd.env("PATH", bin.path())
            .env("CORGEA_PYPI_REGISTRY", &registry)
            .env("CORGEA_VULN_API_URL", &vuln_stub.base_url)
            .env("CORGEA_TOKEN", "test-token");
        Self {
            cmd,
            marker,
            _home: home,
            _bin: bin,
        }
    }

    fn run_install(&mut self) -> std::process::Output {
        self.cmd
            .args(["pip", "install", "oldpkg==1.0.0"])
            .output()
            .expect("run corgea")
    }

    fn pip_ran(&self) -> bool {
        self.marker.exists()
    }
}

#[test]
fn transitive_only_vulnerable_gets_existing_tree_refusal() {
    // Only the transitive `evildep` is flagged; the named `oldpkg` is clean.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evildep", "0.4.2"),
        vulnerable_body("evildep", "0.4.2"),
    );
    let mut h = Harness::new(checks, HashMap::new());
    let out = h.run_install();

    assert_eq!(out.status.code(), Some(1), "transitive vuln must block");
    assert!(!h.pip_ran(), "pip must not run on a blocked install");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(TREE_REFUSAL),
        "stderr must carry the existing-tree refusal: {stderr}"
    );
    assert!(
        !stderr.contains(GENERIC_REFUSAL),
        "generic refusal must be replaced, not appended: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 vulnerable (1 from existing tree)"),
        "summary must attribute the finding to the tree: {stdout}"
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
    let mut h = Harness::new(checks, HashMap::new());
    let out = h.run_install();

    assert_eq!(out.status.code(), Some(1), "named vuln must block");
    assert!(!h.pip_ran(), "pip must not run on a blocked install");
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
        !stdout.contains("from existing tree"),
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
    let mut h = Harness::new(checks, statuses);
    let out = h.run_install();

    assert_eq!(out.status.code(), Some(1), "must block");
    assert!(!h.pip_ran(), "pip must not run on a blocked install");
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
