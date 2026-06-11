//! Hermetic e2e tests for zero-spec ("bare") installs.
//!
//! With a token and a `package.json`, bare `npm install` is gated like any
//! other install: the tree pass resolves the full lockfile set and verdicts
//! every package, so a vulnerable lockfile blocks (exit 1, `--force` escape).
//! Bare yarn/pnpm/uv installs have no safe dry-run — they exec unchecked
//! behind one honest stderr note.
//!
//! Harness mirrors `cli_tree.rs`: fake package manager on a private PATH
//! (tree-aware for npm, plain argv recorder for yarn/pnpm/uv) + local
//! registry stub + in-crate vuln-api stub. `oldpkg` is published in 2020 so
//! recency never blocks here.

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

/// npm lockfile-v3 fixture the fake npm "resolves" from `package.json`:
/// `oldpkg` 1.0.0 + `evildep` 0.4.2 — with zero specs, both are transitive.
const NPM_LOCK: &str = r#"{"name":"proj","lockfileVersion":3,"packages":{
  "":{"name":"proj","version":"1.0.0"},
  "node_modules/oldpkg":{"version":"1.0.0"},
  "node_modules/evildep":{"version":"0.4.2"}}}"#;

const PACKAGE_JSON: &str = r#"{"name":"proj","version":"1.0.0","dependencies":{"oldpkg":"1.0.0"}}"#;

fn vulnerable_evildep_body() -> String {
    r#"{"ecosystem":"npm","package_name":"evildep","version":"0.4.2","is_vulnerable":true,
        "matches":[{"advisory_id":"MAL-2024-0002","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":null}]}"#
        .to_string()
}

/// Registry stub serving the `/oldpkg` npm packument, published 2020 → never
/// recent. Everything else 404s.
fn spawn_registry_stub() -> String {
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
            let (status, body) = if path == "/oldpkg" {
                (
                    "200 OK",
                    r#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}"#,
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

/// Sentinel payload: the fake npm exits non-zero on its tree (resolution)
/// invocation, forcing the named-only fallback.
const RESOLUTION_FAILS: &str = "RESOLUTION_FAILS";

/// Tree-aware fake npm (same scheme as `cli_tree.rs`): an invocation carrying
/// `--package-lock-only` writes `payload` to `./package-lock.json` (the
/// resolver's throwaway temp dir) and exits 0, or exits 1 when `payload` is
/// `RESOLUTION_FAILS`. Any other invocation records its argv to `marker` and
/// exits `exit_code`. Payload is emitted via shell builtins — the locked-down
/// PATH has no `cat`.
fn write_fake_npm(dir: &Path, marker: &Path, payload: &str, exit_code: i32) {
    use std::os::unix::fs::PermissionsExt;
    let tree_branch = if payload == RESOLUTION_FAILS {
        "exit 1".to_string()
    } else {
        let payload_path = dir.join("npm-tree-payload.json");
        std::fs::write(&payload_path, payload).expect("write fake npm payload");
        format!(
            "while IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < '{}' > package-lock.json; exit 0",
            payload_path.display()
        )
    };
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" --package-lock-only \"*) {tree_branch};; esac\nprintf '%s' \"$*\" > '{marker}'\nexit {exit_code}\n",
        marker = marker.display(),
    );
    let path = dir.join("npm");
    std::fs::write(&path, script).expect("write fake npm");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// Plain recorder for managers with no tree pass (yarn/pnpm/uv): record argv
/// to `marker`, exit `exit_code`.
fn write_fake_recorder(dir: &Path, marker: &Path, binary: &str, exit_code: i32) {
    use std::os::unix::fs::PermissionsExt;
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"$*\" > '{marker}'\nexit {exit_code}\n",
        marker = marker.display(),
    );
    let path = dir.join(binary);
    std::fs::write(&path, script).expect("write fake pm");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// `corgea` wired to a fake package manager, the registry + vuln-api stubs,
/// a token, and a throwaway project dir as cwd.
struct BareHarness {
    cmd: Command,
    marker: PathBuf,
    project: TempDir,
    _home: TempDir,
    _bin: TempDir,
}

impl BareHarness {
    /// `npm_payload`: `Some` wires a tree-aware fake npm with that canned
    /// lockfile (or `RESOLUTION_FAILS`); `None` wires a plain recorder for
    /// `binary`. `exit_code` is what the fake exits with on the exec'd
    /// (non-tree) invocation.
    fn new(
        binary: &str,
        checks: HashMap<PackageKey, String>,
        npm_payload: Option<&str>,
        exit_code: i32,
    ) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let project = TempDir::new().expect("project dir");
        let marker = bin.path().join("pm-argv.txt");
        match npm_payload {
            Some(payload) => write_fake_npm(bin.path(), &marker, payload, exit_code),
            None => write_fake_recorder(bin.path(), &marker, binary, exit_code),
        }
        let registry = spawn_registry_stub();
        let vuln_stub = vuln_api_stub::spawn_with_statuses(checks, HashMap::new());
        cmd.env("PATH", bin.path())
            .env("CORGEA_NPM_REGISTRY", &registry)
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

    fn with_package_json(self) -> Self {
        std::fs::write(self.project.path().join("package.json"), PACKAGE_JSON)
            .expect("write package.json");
        self
    }

    fn recorded_argv(&self) -> Option<String> {
        std::fs::read_to_string(&self.marker).ok()
    }
}

#[test]
fn bare_npm_install_vulnerable_lockfile_blocks() {
    let mut checks = HashMap::new();
    checks.insert(key("npm", "evildep", "0.4.2"), vulnerable_evildep_body());
    let mut h = BareHarness::new("npm", checks, Some(NPM_LOCK), 0).with_package_json();
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
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not gated"),
        "gated bare npm must not print the ungated note: {stderr}"
    );
    // A bare install names no targets, so everything resolved is the
    // existing tree's — the refusal must say so.
    assert!(
        stderr.contains("your existing dependency tree has known-vulnerable packages"),
        "bare install blames the existing tree: {stderr}"
    );
}

#[test]
fn bare_npm_install_clean_lockfile_proceeds() {
    let mut h = BareHarness::new("npm", HashMap::new(), Some(NPM_LOCK), 0).with_package_json();
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
    checks.insert(key("npm", "evildep", "0.4.2"), vulnerable_evildep_body());
    let mut h = BareHarness::new("npm", checks, Some(NPM_LOCK), 0).with_package_json();
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
fn bare_npm_install_json_carries_tree_object() {
    let mut checks = HashMap::new();
    checks.insert(key("npm", "evildep", "0.4.2"), vulnerable_evildep_body());
    let mut h = BareHarness::new("npm", checks, Some(NPM_LOCK), 0).with_package_json();
    let out = h
        .cmd
        .args(["npm", "--json", "install"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["tree"]["mode"], "full");
    assert_eq!(parsed["tree"]["resolved_count"], 2);
    assert_eq!(parsed["summary"]["vulnerable"], 1);
    assert_eq!(
        parsed["results"].as_array().map(Vec::len),
        Some(0),
        "zero named targets"
    );
}

#[test]
fn bare_npm_resolution_failure_falls_back_with_warning() {
    // Fake npm exits 1 on `--package-lock-only`. Nothing named remains to
    // verify, so the install proceeds behind the loud fallback warning.
    let mut h =
        BareHarness::new("npm", HashMap::new(), Some(RESOLUTION_FAILS), 0).with_package_json();
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
    let mut h = BareHarness::new("npm", HashMap::new(), Some(NPM_LOCK), 3);
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(3), "npm's own exit code propagates");
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("Pre-checking"), "stdout: {stdout}");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("not gated"),
        "npm never gets the yarn/pnpm/uv note"
    );
}

#[test]
fn bare_npm_tokenless_passes_through() {
    // package.json present but no token → recency-only mode has no tree pass;
    // bare install execs untouched.
    let mut h = BareHarness::new("npm", HashMap::new(), Some(NPM_LOCK), 0).with_package_json();
    h.cmd.env_remove("CORGEA_TOKEN");
    let out = h.cmd.args(["npm", "install"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Pre-checking"));
}

#[test]
fn bare_yarn_install_prints_note_and_execs() {
    let mut h = BareHarness::new("yarn", HashMap::new(), None, 7);
    let out = h
        .cmd
        .args(["yarn", "install"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(7),
        "yarn's own exit code propagates"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(
            "note: bare 'yarn install' is not gated (no safe dry-run) — dependencies install unchecked"
        ),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bare_yarn_note_prints_without_token_too() {
    let mut h = BareHarness::new("yarn", HashMap::new(), None, 0);
    h.cmd.env_remove("CORGEA_TOKEN");
    let out = h
        .cmd
        .args(["yarn", "install"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bare 'yarn install' is not gated"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bare_pnpm_install_prints_note() {
    let mut h = BareHarness::new("pnpm", HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pnpm", "install"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("install"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bare 'pnpm install' is not gated"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bare_uv_add_and_pip_install_print_note() {
    let mut h = BareHarness::new("uv", HashMap::new(), None, 0);
    let out = h.cmd.args(["uv", "add"]).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("add"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bare 'uv add' is not gated"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut h = BareHarness::new("uv", HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["uv", "pip", "install"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(h.recorded_argv().as_deref(), Some("pip install"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bare 'uv pip install' is not gated"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn yarn_named_target_does_not_print_bare_note() {
    // A named target takes the gated path: named-only warning, no bare note.
    let mut h = BareHarness::new("yarn", HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["yarn", "add", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean named target proceeds");
    assert_eq!(h.recorded_argv().as_deref(), Some("add oldpkg@1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not gated"),
        "named install must not print the bare note: {stderr}"
    );
    assert!(
        stderr.contains("transitive dependencies not checked"),
        "named-only warning still applies to yarn: {stderr}"
    );
}
