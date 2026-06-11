//! Hermetic e2e tests for provenance labels on tree-pass findings:
//! `(from requirements)` for pip-requested packages, `(already in
//! package.json)` for npm direct deps the project already declares (plus the
//! `fix with:` advertised-fix hint), `(transitive)` otherwise, and the
//! `"origin"` field in `--json` output.
//!
//! Same harness pattern as `cli_tree.rs`: fake package manager on a private
//! PATH (answers the tree-resolution invocation with a canned payload),
//! a local registry stub, and the in-crate vuln-api stub. `oldpkg` is
//! published in 2020 so recency never blocks — every block is the verdict's.

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

/// Vulnerable verdict body; `fixed_version` is spliced in as given
/// (`"1.2.2"` or `null`).
fn vulnerable_body(ecosystem: &str, name: &str, version: &str, fixed: &str) -> String {
    format!(
        r#"{{"ecosystem":"{ecosystem}","package_name":"{name}","version":"{version}","is_vulnerable":true,
        "matches":[{{"advisory_id":"MAL-2024-0002","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":{fixed}}}]}}"#
    )
}

/// Pip report: only `reqpkg`, requested (as if it came from a `-r` file).
const PIP_REQ_REPORT: &str = r#"{"version":"1","pip_version":"24.0","install":[
  {"metadata":{"name":"reqpkg","version":"6.0.0"},"requested":true}]}"#;

/// Pip report mixing all three origins: `oldpkg` (named on the CLI, matches
/// the named outcome), `reqpkg` (requested via `-r`), `evildep` (transitive).
const PIP_MIXED_REPORT: &str = r#"{"version":"1","pip_version":"24.0","install":[
  {"metadata":{"name":"oldpkg","version":"1.0.0"},"requested":true},
  {"metadata":{"name":"reqpkg","version":"6.0.0"},"requested":true},
  {"metadata":{"name":"evildep","version":"0.4.2"},"requested":false}]}"#;

/// npm lockfile-v3: named `oldpkg` 1.0.0 + `evildep` 0.4.2 (resolved from the
/// project's pre-existing direct dep).
const NPM_LOCK: &str = r#"{"name":"proj","lockfileVersion":3,"packages":{
  "":{"name":"proj","version":"1.0.0"},
  "node_modules/oldpkg":{"version":"1.0.0"},
  "node_modules/evildep":{"version":"0.4.2"}}}"#;

/// Project manifest that already declares `evildep` as a direct dep.
const PROJECT_MANIFEST: &str =
    r#"{"name":"proj","version":"1.0.0","dependencies":{"evildep":"^0.4.0"}}"#;

/// Registry stub serving `/pypi/oldpkg/json` (pypi) and `/oldpkg` (npm
/// packument), both published 2020 → never recent. Everything else 404s.
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

/// Write an executable fake package manager into `dir`. The tree-resolution
/// invocation (pip `--dry-run` / npm `--package-lock-only`) emits `payload`
/// (stdout for pip, `./package-lock.json` for npm) and exits 0; any other
/// invocation records its argv to `marker` and exits 0. The payload is read
/// via shell builtins because the locked-down test `PATH` has no `cat`.
fn write_fake_pm(dir: &Path, marker: &Path, binary: &str, payload: &str) {
    use std::os::unix::fs::PermissionsExt;
    let (tree_flag, redirect) = match binary {
        "pip" => ("--dry-run", ""),
        "npm" => ("--package-lock-only", " > package-lock.json"),
        other => panic!("unsupported fake manager {other}"),
    };
    let payload_path = dir.join(format!("{binary}-tree-payload.json"));
    std::fs::write(&payload_path, payload).expect("write fake pm payload");
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" {tree_flag} \"*) while IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < '{payload}'{redirect}; exit 0;; esac\nprintf '%s' \"$*\" > '{marker}'\nexit 0\n",
        payload = payload_path.display(),
        marker = marker.display(),
    );
    let path = dir.join(binary);
    std::fs::write(&path, script).expect("write fake pm");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod fake pm");
}

/// `corgea` wired to the registry stub, a tree-aware fake manager, and a
/// vuln-api stub.
struct Harness {
    cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

impl Harness {
    fn new(binary: &str, checks: HashMap<PackageKey, String>, payload: &str) -> Self {
        Self::new_with_statuses(binary, checks, HashMap::new(), payload)
    }

    fn new_with_statuses(
        binary: &str,
        checks: HashMap<PackageKey, String>,
        statuses: HashMap<PackageKey, u16>,
        payload: &str,
    ) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_pm(bin.path(), &marker, binary, payload);
        let registry = spawn_registry_stub();
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

/// Project dir holding a `package.json` that already declares `evildep`.
fn npm_project() -> TempDir {
    let project = TempDir::new().expect("project dir");
    std::fs::write(project.path().join("package.json"), PROJECT_MANIFEST)
        .expect("write package.json");
    project
}

#[test]
fn pip_requirements_finding_labeled_from_requirements() {
    // The flagged package comes from a `-r` file (pip marks it `requested`),
    // so it must not be mislabeled "(transitive)".
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "reqpkg", "6.0.0"),
        vulnerable_body("pypi", "reqpkg", "6.0.0", "null"),
    );
    let mut h = Harness::new("pip", checks, PIP_REQ_REPORT);
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
    // steer re-check verified 1.2.2 clean (the stub defaults unknown
    // versions to clean), so the hint drops the "(advertised fix)" hedge.
    let project = npm_project();
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", r#""1.2.2""#),
    );
    let mut h = Harness::new("npm", checks, NPM_LOCK);
    let out = h
        .cmd
        .current_dir(project.path())
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
fn npm_preexisting_fix_hint_keeps_hedge_when_unverifiable() {
    // The steer re-check for 1.2.2 fails (503), so the bare steer line stays
    // quiet and the fix-command hint keeps its "(advertised fix)" hedge.
    let project = npm_project();
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", r#""1.2.2""#),
    );
    let mut statuses = HashMap::new();
    statuses.insert(key("npm", "evildep", "1.2.2"), 503u16);
    let mut h = Harness::new_with_statuses("npm", checks, statuses, NPM_LOCK);
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "pre-existing vuln must block");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("fix with: corgea npm install evildep@1.2.2 (advertised fix)"),
        "unverified fix hint must keep the hedge: {stdout}"
    );
    assert!(
        !stdout.contains("→ safe version"),
        "an unverified steer must stay quiet: {stdout}"
    );
}

/// PR #108 review regression: unverifiable tree findings block too, so the
/// refusal may not blame the existing tree when a command-added transitive
/// is part of the block — even if the only *vulnerable* finding is a
/// pre-existing direct dep.
#[test]
fn preexisting_vulnerable_with_unverifiable_transitive_keeps_generic_refusal() {
    const LOCK_WITH_NEWDEP: &str = r#"{"name":"proj","lockfileVersion":3,"packages":{
      "":{"name":"proj","version":"1.0.0"},
      "node_modules/oldpkg":{"version":"1.0.0"},
      "node_modules/evildep":{"version":"0.4.2"},
      "node_modules/newdep":{"version":"2.0.0"}}}"#;
    let project = npm_project();
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "null"),
    );
    let mut statuses = HashMap::new();
    statuses.insert(key("npm", "newdep", "2.0.0"), 503u16);
    let mut h = Harness::new_with_statuses("npm", checks, statuses, LOCK_WITH_NEWDEP);
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "must block");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Refusing to run install. Pass --force to proceed despite findings."),
        "the command-added unverifiable transitive keeps the generic refusal: {stderr}"
    );
    assert!(
        !stderr.contains("your existing dependency tree"),
        "existing-tree refusal must not fire when a command-added finding blocks: {stderr}"
    );
}

#[test]
fn npm_preexisting_without_fix_has_no_hint() {
    let project = npm_project();
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", "null"),
    );
    let mut h = Harness::new("npm", checks, NPM_LOCK);
    let out = h
        .cmd
        .current_dir(project.path())
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
fn pip_json_carries_origin_per_tree_entry() {
    // All-clean run mixing origins: the named `oldpkg` matches its outcome,
    // `reqpkg` (requested) and `evildep` (transitive) land in `tree.transitive`
    // with their origins.
    let mut h = Harness::new("pip", HashMap::new(), PIP_MIXED_REPORT);
    let out = h
        .cmd
        .args([
            "pip",
            "--json",
            "install",
            "oldpkg==1.0.0",
            "-r",
            "reqs.txt",
        ])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "clean tree must proceed");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["tree"]["mode"], "full");
    let entries = parsed["tree"]["transitive"]
        .as_array()
        .expect("transitive array");
    let origin_of = |name: &str| {
        entries
            .iter()
            .find(|e| e["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing from tree entries"))["origin"]
            .clone()
    };
    assert_eq!(origin_of("reqpkg"), "requested");
    assert_eq!(origin_of("evildep"), "transitive");
    assert_eq!(entries.len(), 2, "named oldpkg must not be a tree entry");
}

#[test]
fn npm_json_carries_preexisting_origin() {
    let project = npm_project();
    let mut checks = HashMap::new();
    checks.insert(
        key("npm", "evildep", "0.4.2"),
        vulnerable_body("npm", "evildep", "0.4.2", r#""1.2.2""#),
    );
    let mut h = Harness::new("npm", checks, NPM_LOCK);
    let out = h
        .cmd
        .current_dir(project.path())
        .args(["npm", "--json", "install", "oldpkg@1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["tree"]["transitive"][0]["name"], "evildep");
    assert_eq!(parsed["tree"]["transitive"][0]["origin"], "pre-existing");
    assert_eq!(
        parsed["tree"]["transitive"][0]["verdict"]["status"],
        "vulnerable"
    );
}
