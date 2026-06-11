//! Hermetic e2e tests for remediation steering: a blocked install names the
//! safe version from the verdict's `fixed_version` data — but only after the
//! proposed version itself re-verdicts clean against vuln-api. A flagged
//! proposal prints the rejection note instead; a failed re-check suppresses
//! the steer quietly without moving counts or exit codes.
//!
//! Mirrors the `cli_verdict.rs` harness (inline PyPI stub published 2020 so
//! recency never blocks, a fake pip recording its argv, the in-crate vuln-api
//! stub, and a set token) — every block here is the verdict's doing.

#![cfg(unix)]

mod common;

use common::{
    corgea_isolated, spawn_http_stub, write_fake_pip_without_report, NOT_FOUND_JSON,
    OLDPKG_PYPI_JSON,
};
use corgea::vuln_api_stub::{self, PackageKey};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn key(eco: &str, name: &str, ver: &str) -> PackageKey {
    (eco.to_string(), name.to_string(), ver.to_string())
}

fn fixed_body() -> String {
    r#"{"ecosystem":"pypi","package_name":"oldpkg","version":"1.0.0","is_vulnerable":true,
        "matches":[{"advisory_id":"MAL-2024-0001","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":"2.0.0"}]}"#
        .to_string()
}

fn no_fix_body() -> String {
    r#"{"ecosystem":"pypi","package_name":"oldpkg","version":"1.0.0","is_vulnerable":true,
        "matches":[{"advisory_id":"MAL-2024-0002","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":null}]}"#
        .to_string()
}

/// The advertised fix `oldpkg@2.0.0` is itself flagged — the steer re-check
/// must reject it.
fn flagged_fix_body() -> String {
    r#"{"ecosystem":"pypi","package_name":"oldpkg","version":"2.0.0","is_vulnerable":true,
        "matches":[{"advisory_id":"MAL-2024-0003","severity_level":"critical","tier":1,
                    "vulnerable_version_range":null,"fixed_version":null}]}"#
        .to_string()
}

/// Registry stub serving only `/pypi/oldpkg/json` (published 2020 → never
/// recent). Everything else 404s.
fn spawn_pypi_stub() -> String {
    spawn_http_stub(|path| match path {
        "/pypi/oldpkg/json" => ("200 OK", OLDPKG_PYPI_JSON.to_string()),
        _ => ("404 Not Found", NOT_FOUND_JSON.to_string()),
    })
}

/// `corgea` wired to the registry stub, a fake pip, and a vuln-api stub.
struct RemediationHarness {
    cmd: Command,
    marker: PathBuf,
    _home: TempDir,
    _bin: TempDir,
}

impl RemediationHarness {
    fn new(checks: HashMap<PackageKey, String>, token: Option<&str>, pip_exit_code: i32) -> Self {
        Self::with_statuses(checks, HashMap::new(), token, pip_exit_code)
    }

    fn with_statuses(
        checks: HashMap<PackageKey, String>,
        statuses: HashMap<PackageKey, u16>,
        token: Option<&str>,
        pip_exit_code: i32,
    ) -> Self {
        let (mut cmd, home) = corgea_isolated();
        let bin = TempDir::new().expect("temp bin dir");
        let marker = bin.path().join("pm-argv.txt");
        write_fake_pip_without_report(bin.path(), &marker, pip_exit_code);
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
fn fixed_match_blocks_and_names_safe_version() {
    // The stub answers default-clean for the unscripted `oldpkg@2.0.0` steer
    // re-check, so the proposal verifies and the steer prints.
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), fixed_body());
    let mut h = RemediationHarness::new(checks, Some("test-token"), 0);
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
    assert!(stdout.contains("fixed in 2.0.0"), "stdout: {stdout}");
    assert!(
        stdout.contains("safe version: oldpkg@2.0.0"),
        "stdout: {stdout}"
    );
}

#[test]
fn no_fix_match_reports_no_fixed_version_known() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), no_fix_body());
    let mut h = RemediationHarness::new(checks, Some("test-token"), 0);
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
    assert!(
        stdout.contains("no fixed version known"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("safe version:"),
        "no steer line when the fix is unknown: {stdout}"
    );
}

#[test]
fn json_remediation_carries_safe_version() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), fixed_body());
    let mut h = RemediationHarness::new(checks, Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        parsed["results"][0]["verdict"]["remediation"], "2.0.0",
        "parsed: {parsed}"
    );
}

#[test]
fn json_remediation_null_when_no_fix() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), no_fix_body());
    let mut h = RemediationHarness::new(checks, Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    let v = &parsed["results"][0]["verdict"];
    assert!(
        v.as_object().unwrap().contains_key("remediation"),
        "verdict must carry the remediation key: {parsed}"
    );
    assert!(
        v["remediation"].is_null(),
        "remediation must be null when no fix is known: {parsed}"
    );
}

#[test]
fn rejected_fix_prints_rejection_instead_of_steer() {
    // oldpkg@1.0.0 is vulnerable with an advertised fix of 2.0.0 — but the
    // stub flags 2.0.0 too, so the steer must turn into the rejection note.
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), fixed_body());
    checks.insert(key("pypi", "oldpkg", "2.0.0"), flagged_fix_body());
    let mut h = RemediationHarness::new(checks, Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("advertised fix 2.0.0 is also flagged — no safe version to suggest"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("safe version:"),
        "a rejected fix must not print the steer: {stdout}"
    );
    assert!(
        stdout.contains("1 vulnerable, 0 unverifiable"),
        "the steer re-check must not inflate counts: {stdout}"
    );
}

#[test]
fn unverified_fix_suppresses_steer_quietly() {
    // The steer re-check for oldpkg@2.0.0 503s. The steer disappears with no
    // substitute line, and counts/exit stay exactly as without the re-check.
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), fixed_body());
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "2.0.0"), 503u16);
    let mut h = RemediationHarness::with_statuses(checks, statuses, Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("safe version:"),
        "an unverified fix must not print the steer: {stdout}"
    );
    assert!(
        !stdout.contains("also flagged"),
        "an unverified fix must stay quiet, not claim rejection: {stdout}"
    );
    assert!(
        stdout.contains("1 vulnerable, 0 unverifiable"),
        "a failed steer re-check must not change counts: {stdout}"
    );
    assert!(
        stdout.contains("fixed in 2.0.0"),
        "advisory fix data still prints: {stdout}"
    );
}

#[test]
fn json_remediation_null_when_fix_rejected() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), fixed_body());
    checks.insert(key("pypi", "oldpkg", "2.0.0"), flagged_fix_body());
    let mut h = RemediationHarness::new(checks, Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    let v = &parsed["results"][0]["verdict"];
    assert_eq!(v["status"], "vulnerable", "parsed: {parsed}");
    assert!(
        v["remediation"].is_null(),
        "remediation must be null when the fix re-verdicts vulnerable: {parsed}"
    );
    assert_eq!(
        parsed["summary"]["vulnerable"], 1,
        "the steer re-check must not inflate counts: {parsed}"
    );
}
