//! Hermetic e2e tests for the install-gate vuln-api verdict
//! (`corgea pip install …` with a token + `CORGEA_VULN_API_URL` stub).
//!
//! Composes the `cli_install.rs` harness pattern (fake package manager on a
//! private PATH + local pypi registry stub) with the in-crate vuln-api stub.
//! `oldpkg==1.0.0` is published in 2020, so recency never blocks here —
//! every block in this file is the verdict's doing.

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

fn key(eco: &str, name: &str, ver: &str) -> PackageKey {
    (eco.to_string(), name.to_string(), ver.to_string())
}

fn vulnerable_oldpkg_body() -> String {
    r#"{"ecosystem":"pypi","package_name":"oldpkg","version":"1.0.0","is_vulnerable":true,
        "matches":[{"advisory_id":"MAL-2024-0001","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":"2.0.0"}]}"#
        .to_string()
}

/// Registry stub serving only `/pypi/oldpkg/json` (published 2020 → never
/// recent). Everything else 404s.
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
                .unwrap_or("")
                .to_string();

            let (status, body) = match path.as_str() {
                "/pypi/oldpkg/json" => (
                    "200 OK",
                    r#"{"info":{"name":"oldpkg"},"releases":{"1.0.0":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z"}]}}"#.to_string(),
                ),
                _ => ("404 Not Found", r#"{"message":"not found"}"#.to_string()),
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

/// Write an executable fake `pip` into `dir`. It records its argv to `marker`
/// and exits with `exit_code` — proving both whether the install ran and that
/// the exit code propagates.
fn write_fake_pip(dir: &Path, marker: &Path, exit_code: i32) {
    use std::os::unix::fs::PermissionsExt;
    // Simulate an old pip with no `--report`: exit 2 on the tree dry-run
    // *without* touching the marker, so these tests exercise the named-only
    // fallback path and keep their pre-tree semantics.
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) exit 2;; esac\nprintf '%s' \"$*\" > '{}'\nexit {}\n",
        marker.display(),
        exit_code
    );
    let path = dir.join("pip");
    std::fs::write(&path, script).expect("write fake pip");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake pip");
}

/// `corgea` wired to the registry stub, a fake pip, and a vuln-api stub.
struct VerdictHarness {
    cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

impl VerdictHarness {
    /// `token: None` exercises tokenless mode (no CORGEA_TOKEN set).
    fn new(
        checks: HashMap<PackageKey, String>,
        statuses: HashMap<PackageKey, u16>,
        token: Option<&str>,
        pip_exit_code: i32,
    ) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_pip(bin.path(), &marker, pip_exit_code);
        let registry = spawn_pypi_stub();
        let vuln_stub = vuln_api_stub::spawn_with_statuses(checks, statuses);
        cmd.env("PATH", bin.path())
            .env("CORGEA_PYPI_REGISTRY", &registry)
            .env("CORGEA_VULN_API_URL", &vuln_stub.base_url);
        if let Some(t) = token {
            cmd.env("CORGEA_TOKEN", t);
        }
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
fn vulnerable_pin_blocks_without_running_install() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = VerdictHarness::new(checks, HashMap::new(), Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        h.recorded_argv(),
        None,
        "pip must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("MAL-2024-0001"), "stdout: {stdout}");
    assert!(stdout.contains("critical"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force"),
        "block message must name --force"
    );
}

#[test]
fn force_overrides_vulnerable_block_and_propagates_exit_code() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = VerdictHarness::new(checks, HashMap::new(), Some("test-token"), 7);
    let out = h
        .cmd
        .args(["pip", "--force", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(7),
        "manager exit code must propagate under --force"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("MAL-2024-0001"),
        "findings must still print under --force: {stdout}"
    );
}

#[test]
fn verdict_503_fails_closed() {
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    let mut h = VerdictHarness::new(HashMap::new(), statuses, Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "unverifiable must block (fail-closed)"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not be verified"), "stdout: {stdout}");
}

#[test]
fn tokenless_degrades_to_recency_only_with_login_prompt() {
    // Stub would flag oldpkg, but with no token it must never be consulted.
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = VerdictHarness::new(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "old + unchecked package must install"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("corgea login"),
        "tokenless mode must prompt for login"
    );
}

#[test]
fn json_carries_verdict_object_and_mode() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = VerdictHarness::new(checks, HashMap::new(), Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["verdict_mode"], "full");
    assert_eq!(parsed["results"][0]["verdict"]["status"], "vulnerable");
    assert_eq!(
        parsed["results"][0]["verdict"]["matches"][0]["advisory_id"],
        "MAL-2024-0001"
    );
    assert_eq!(
        parsed["results"][0]["verdict"]["matches"][0]["fixed_version"],
        "2.0.0"
    );
    assert_eq!(parsed["summary"]["vulnerable"], 1);
}
