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
                "/oldpkg" => (
                    "200 OK",
                    r#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}"#.to_string(),
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

/// Sentinel payload that makes the fake manager exit non-zero on its tree
/// (resolution) invocation, forcing the named-only fallback.
const RESOLUTION_FAILS: &str = "RESOLUTION_FAILS";

/// Write an executable fake package manager into `dir`. On an invocation
/// whose argv contains `tree_flag` it emits `payload` (to stdout for pip's
/// `--dry-run --report -`, into `./package-lock.json` for npm's
/// `--package-lock-only`, whose cwd is the resolver's throwaway temp dir) and
/// exits 0 — the tree pass; if `payload` is `RESOLUTION_FAILS` it exits
/// non-zero instead, emitting nothing. Any other invocation records its argv
/// to `marker` and exits `exit_code`.
///
/// The payload is read from a sibling file via shell builtins so it works
/// under the test's locked-down `PATH` (which has no `cat`); the
/// `|| [ -n "$line" ]` guard keeps the final line when the payload file has
/// no trailing newline.
fn write_fake_pm(dir: &Path, marker: &Path, binary: &str, payload: &str, exit_code: i32) {
    use std::os::unix::fs::PermissionsExt;
    let (tree_flag, redirect, fail_exit) = match binary {
        "pip" => ("--dry-run", "", 2),
        "npm" => ("--package-lock-only", " > package-lock.json", 1),
        other => panic!("unsupported fake manager {other}"),
    };
    let tree_branch = if payload == RESOLUTION_FAILS {
        format!("exit {fail_exit}")
    } else {
        let payload_path = dir.join(format!("{binary}-tree-payload.json"));
        std::fs::write(&payload_path, payload).expect("write fake pm payload");
        format!(
            "while IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < '{}'{redirect}; exit 0",
            payload_path.display()
        )
    };
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" {tree_flag} \"*) {tree_branch};; esac\nprintf '%s' \"$*\" > '{marker}'\nexit {exit_code}\n",
        marker = marker.display(),
    );
    let path = dir.join(binary);
    std::fs::write(&path, script).expect("write fake pm");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod fake pm");
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
        write_fake_pm(bin.path(), &marker, binary, payload, exit_code);
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
