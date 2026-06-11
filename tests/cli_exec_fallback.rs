//! Hermetic e2e tests for package-manager binary resolution: the pip→pip3
//! fallback and the missing-binary error (exit 127).
//!
//! Same harness shape as `cli_install.rs`: the real `corgea` binary, a local
//! TcpListener stub standing in for PyPI, and a controlled `PATH` dir that
//! either holds a fake `pip3` (recording its argv to a marker file) or
//! nothing at all. Unix-only — the fake manager is a shell script.

#![cfg(unix)]

mod common;

use common::corgea_isolated;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use tempfile::TempDir;

/// Spawn a PyPI stub serving `/pypi/oldpkg/json` (published 2020-01-01,
/// safely past the recency threshold). Anything else 404s.
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
            let (status, body) = if path == "/pypi/oldpkg/json" {
                (
                    "200 OK",
                    r#"{"info":{"name":"oldpkg"},"releases":{"1.0.0":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z"}]}}"#,
                )
            } else {
                ("404 Not Found", r#"{"message":"not found"}"#)
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

/// Write an executable fake package manager named `binary` into `dir`.
/// It records its argv to `marker` and exits 0.
fn write_fake_package_manager(dir: &Path, binary: &str, marker: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"$*\" > '{}'\nexit 0\n",
        marker.display()
    );
    let path = dir.join(binary);
    std::fs::write(&path, script).expect("write fake package manager");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake package manager");
}

/// Isolated `corgea` wired to the PyPI stub, with `PATH` set to a private
/// temp dir containing only the named fake binaries.
struct FallbackHarness {
    cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

impl FallbackHarness {
    fn new(binaries: &[&str]) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        for binary in binaries {
            write_fake_package_manager(bin.path(), binary, &marker);
        }
        let registry = spawn_pypi_stub();
        cmd.env("PATH", bin.path())
            .env("CORGEA_PYPI_REGISTRY", &registry);
        Self {
            cmd,
            marker,
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
fn pip_install_falls_back_to_pip3_when_pip_missing() {
    let mut h = FallbackHarness::new(&["pip3"]);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install oldpkg==1.0.0"),
        "the install must run via pip3 with forwarded args"
    );
}

#[test]
fn pip_passthrough_falls_back_to_pip3() {
    let mut h = FallbackHarness::new(&["pip3"]);
    let out = h.cmd.args(["pip", "list"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("list"));
}

#[test]
fn pip_missing_both_pip_and_pip3_exits_127_with_message() {
    let mut h = FallbackHarness::new(&[]);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(127));
    assert_eq!(h.recorded_argv(), None, "nothing must have run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: 'pip' not found on PATH (also tried 'pip3')"),
        "stderr: {stderr}"
    );
}

#[test]
fn npm_missing_binary_error_names_binary_without_fallback() {
    let mut h = FallbackHarness::new(&[]);
    let out = h.cmd.args(["npm", "list"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: 'npm' not found on PATH"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("also tried"),
        "npm has no fallback alias; stderr: {stderr}"
    );
}
