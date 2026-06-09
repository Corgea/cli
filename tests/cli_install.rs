//! Hermetic end-to-end tests for the install wrappers (`corgea pip|npm …`).
//!
//! Each test spawns the real binary (`CARGO_BIN_EXE_corgea`) against:
//!   * a local TcpListener stub standing in for PyPI / the npm registry
//!     (wired up via `CORGEA_PYPI_REGISTRY` / `CORGEA_NPM_REGISTRY`), and
//!   * a fake package manager on `PATH` — a shell script that records its
//!     argv to a marker file, proving whether the install actually ran.
//!
//! No live network. The fake package managers are Unix shell scripts, so
//! the whole file is Unix-only (matching the repo's Linux/macOS CI).

#![cfg(unix)]

mod common;

use common::corgea_isolated;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

/// Spawn a registry stub serving both the PyPI and npm routes the
/// resolver hits. Returns the base URL and a counter of accepted
/// connections (used to prove "no registry hit" for passthroughs).
///
/// Routes:
///   * `/pypi/oldpkg/json`   — one release, published 2020-01-01
///   * `/pypi/freshpkg/json` — one release, published one hour ago
///   * `/oldpkg`             — npm metadata, published 2020-01-01
///   * `/freshpkg`           — npm metadata, published one hour ago
///   * anything else         — 404
fn spawn_registry_stub() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in_thread = Arc::clone(&hits);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            hits_in_thread.fetch_add(1, Ordering::SeqCst);
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

            let fresh_ts = (chrono::Utc::now() - chrono::Duration::hours(1))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            let (status, body) = match path.as_str() {
                "/pypi/oldpkg/json" => (
                    "200 OK",
                    r#"{"info":{"name":"oldpkg"},"releases":{"1.0.0":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z"}]}}"#.to_string(),
                ),
                "/pypi/freshpkg/json" => (
                    "200 OK",
                    format!(
                        r#"{{"info":{{"name":"freshpkg"}},"releases":{{"9.9.9":[{{"upload_time_iso_8601":"{fresh_ts}"}}]}}}}"#,
                    ),
                ),
                "/oldpkg" => (
                    "200 OK",
                    r#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}"#.to_string(),
                ),
                "/freshpkg" => (
                    "200 OK",
                    format!(
                        r#"{{"dist-tags":{{"latest":"9.9.9"}},"versions":{{"9.9.9":{{}}}},"time":{{"9.9.9":"{fresh_ts}"}}}}"#,
                    ),
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
    (base_url, hits)
}

/// Write an executable fake package manager named `binary` into `dir`.
/// It records its argv to `marker` and exits with `exit_code` — proving
/// both "the install ran (with these args)" and exit-code forwarding.
fn write_fake_package_manager(dir: &Path, binary: &str, marker: &Path, exit_code: i32) {
    use std::os::unix::fs::PermissionsExt;
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"$*\" > '{}'\nexit {}\n",
        marker.display(),
        exit_code
    );
    let path = dir.join(binary);
    std::fs::write(&path, script).expect("write fake package manager");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake package manager");
}

/// A ready-to-run wrapper invocation: isolated `corgea` command with the
/// registry stub wired in and a fake `binary` on a PATH of its own.
struct WrapperHarness {
    cmd: Command,
    marker: PathBuf,
    registry_hits: Arc<AtomicUsize>,
    _home: TempDir,
    _bin: TempDir,
}

impl WrapperHarness {
    /// `registry_env` is `CORGEA_PYPI_REGISTRY` or `CORGEA_NPM_REGISTRY`,
    /// matching `binary`'s ecosystem.
    fn new(binary: &str, registry_env: &str, pm_exit_code: i32) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_package_manager(bin.path(), binary, &marker, pm_exit_code);
        let (base_url, registry_hits) = spawn_registry_stub();
        cmd.env("PATH", bin.path()).env(registry_env, &base_url);
        Self {
            cmd,
            marker,
            registry_hits,
            _home: home,
            _bin: bin,
        }
    }

    /// The argv the fake package manager was invoked with, if it ran.
    fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

#[test]
fn pip_fresh_pin_blocks_without_running_install() {
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run when blocked");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("within threshold"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Refusing to run install"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn pip_old_pin_runs_install_with_forwarded_args() {
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("published"), "stdout: {stdout}");
}

#[test]
fn pip_no_fail_demotes_block_and_installs() {
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "--no-fail", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install freshpkg==9.9.9"),
        "--no-fail must still run the install"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("within threshold"), "stdout: {stdout}");
}

#[test]
fn pip_non_install_subcommand_passes_through_without_registry_hit() {
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "list"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("list"));
    assert_eq!(
        h.registry_hits.load(Ordering::SeqCst),
        0,
        "passthrough must not touch the registry"
    );
}

#[test]
fn pip_json_reports_fresh_pin_as_recent() {
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "freshpkg==9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["results"][0]["status"], "recent");
    assert_eq!(parsed["results"][0]["name"], "freshpkg");
    assert_eq!(parsed["summary"]["recent"], 1);
}

#[test]
fn pip_resolution_error_prints_error_but_install_proceeds() {
    // `nosuchpkg` hits the stub's 404 route → an error outcome, which
    // warns but never blocks in the baseline (fail-closed is a later
    // chunk) — the install must still run.
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "nosuchpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        h.registry_hits.load(Ordering::SeqCst) >= 1,
        "the 404 route must have been hit"
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install nosuchpkg==1.0.0"),
        "a resolution error must not block the install"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("not found"), "stdout: {stdout}");
    assert!(stdout.contains("1 errors"), "stdout: {stdout}");
}

#[test]
fn pip_mixed_fresh_and_old_pins_block_without_running_install() {
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 0);
    let out = h
        .cmd
        .args(["pip", "install", "freshpkg==9.9.9", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        h.recorded_argv(),
        None,
        "one recent target must block the whole install"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("within threshold"), "stdout: {stdout}");
    assert!(stdout.contains("1 ok, 1 recent"), "stdout: {stdout}");
}

#[test]
fn npm_fresh_pin_blocks_without_running_install() {
    let mut h = WrapperHarness::new("npm", "CORGEA_NPM_REGISTRY", 0);
    let out = h
        .cmd
        .args(["npm", "install", "freshpkg@9.9.9"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "npm must not run when blocked");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Refusing to run install"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn npm_old_pin_runs_install_with_forwarded_args() {
    let mut h = WrapperHarness::new("npm", "CORGEA_NPM_REGISTRY", 0);
    let out = h
        .cmd
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg@1.0.0"));
}

#[test]
fn wrapper_forwards_package_manager_exit_code() {
    let mut h = WrapperHarness::new("pip", "CORGEA_PYPI_REGISTRY", 7);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(7),
        "the package manager's exit code must be forwarded"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
}
