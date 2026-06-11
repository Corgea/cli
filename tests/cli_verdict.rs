//! Hermetic e2e tests for the install-gate vuln-api verdict
//! (`corgea pip install …` with public/authenticated `CORGEA_VULN_API_URL` stubs).
//!
//! Composes the `cli_install.rs` harness pattern (fake package manager on a
//! private PATH + local pypi registry stub) with the in-crate vuln-api stub —
//! the shared `common::PipHarness`. `oldpkg==1.0.0` is published in 2020, so
//! recency never blocks here — every block in this file is the verdict's
//! doing.

#![cfg(unix)]

mod common;

use common::{key, vulnerable_body, PipHarness};
use corgea::vuln_api_stub::{header_value, spawn_capturing_vuln_api_stub};
use std::collections::HashMap;

fn vulnerable_oldpkg_body() -> String {
    vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0"))
}

#[test]
fn vulnerable_pin_blocks_without_running_install() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = PipHarness::new(checks, HashMap::new(), Some("test-token"), 0);
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
fn alternate_pypi_spelling_hits_canonical_verdict() {
    // Advisories are keyed by the PEP 503 canonical name; `Flask_Cors`
    // must query (and block on) the `flask-cors` verdict.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "flask-cors", "1.0.0"),
        vulnerable_body("pypi", "flask-cors", "1.0.0", "GHSA-TEST-0001", None),
    );
    let mut h = PipHarness::new(checks, HashMap::new(), Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "Flask_Cors==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "alternate spelling must not bypass the gate"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GHSA-TEST-0001"), "stdout: {stdout}");
}

#[test]
fn force_overrides_vulnerable_block_and_propagates_exit_code() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = PipHarness::new(checks, HashMap::new(), Some("test-token"), 7);
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
fn resolution_error_fails_closed_when_authenticated() {
    // The wildcard registry stub only knows version 1.0.0, so `==2.0.0`
    // is a resolution error: no verdict was obtained, and authenticated
    // mode must block — otherwise a registry outage bypasses the gate.
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), Some("test-token"), 0);
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "nosuchpkg==2.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a resolution error must fail closed in authenticated mode"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 errors"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force"),
        "block message must name --force"
    );
}

#[test]
fn verdict_503_fails_closed() {
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    let mut h = PipHarness::new(HashMap::new(), statuses, Some("test-token"), 0);
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "authenticated unverifiable must block (fail-closed)"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not be verified"), "stdout: {stdout}");
}

#[test]
fn tokenless_public_check_blocks_vulnerable_pin() {
    // No token still runs public CVE checks and blocks a vulnerable verdict.
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = PipHarness::new(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "public CVE checks must block vulnerable packages"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("MAL-2024-0001"), "stdout: {stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("using public CVE checks"),
        "tokenless mode must disclose public CVE checks: {stderr}"
    );
    assert!(
        stderr.contains("authenticated enforcement")
            && stderr.contains("private Corgea intelligence"),
        "tokenless warning must name the authenticated benefit: {stderr}"
    );
}

#[test]
fn tokenless_vuln_api_outage_warns_but_installs() {
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), None, 0);
    h.cmd.env("CORGEA_VULN_API_URL", "http://127.0.0.1:1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "public lookup outage must fail open"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("CVE check unavailable; continuing because public mode is fail-open"),
        "stderr: {stderr}"
    );
}

#[test]
fn progress_line_prints_only_above_eight_verdict_jobs() {
    // Nine resolvable named targets → 9 verdict jobs (> 8) → progress line.
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), Some("test-token"), 0);
    let mut args = vec!["pip".to_string(), "install".to_string()];
    args.extend((1..=9).map(|i| format!("pkg{i}==1.0.0")));
    let out = h.cmd.args(&args).output().expect("run corgea");
    assert_eq!(out.status.code(), Some(0), "all clean + old must install");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("checking 9 packages against Corgea vuln-api"),
        "stderr: {stderr}"
    );

    // Two jobs → quiet.
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "pkg1==1.0.0", "pkg2==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("against Corgea vuln-api"),
        "no progress line at or below 8 jobs: {stderr}"
    );
}

#[test]
fn outage_noise_collapses_above_three_unverifiable() {
    // vuln-api refuses connections: every check fails with the same
    // error-prefix (only the per-package URL differs). Four findings →
    // one collapsed line; counts and fail-closed exit code unchanged.
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), Some("test-token"), 0);
    h.cmd.env("CORGEA_VULN_API_URL", "http://127.0.0.1:1");
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args([
            "pip",
            "install",
            "pkg1==1.0.0",
            "pkg2==1.0.0",
            "pkg3==1.0.0",
            "pkg4==1.0.0",
        ])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "unverifiable must still block");
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("4 packages could not be verified (vuln-api unreachable:"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("could not be verified:"),
        "per-package lines must collapse: {stdout}"
    );
    assert!(
        stdout.contains("4 unverifiable"),
        "summary counts unchanged: {stdout}"
    );

    // Three findings stay per-line — no collapse at the threshold.
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), Some("test-token"), 0);
    h.cmd.env("CORGEA_VULN_API_URL", "http://127.0.0.1:1");
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args([
            "pip",
            "install",
            "pkg1==1.0.0",
            "pkg2==1.0.0",
            "pkg3==1.0.0",
        ])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.matches("could not be verified:").count(),
        3,
        "three findings must keep per-package lines: {stdout}"
    );
    assert!(
        !stdout.contains("vuln-api unreachable:"),
        "no collapsed line at exactly the threshold: {stdout}"
    );
}

#[test]
fn json_carries_verdict_object_and_mode() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), vulnerable_oldpkg_body());
    let mut h = PipHarness::new(checks, HashMap::new(), Some("test-token"), 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["verdict_mode"], "public");
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

#[test]
fn custom_vuln_api_url_with_token_does_not_send_token_by_default() {
    let (base_url, requests) = spawn_capturing_vuln_api_stub();
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
    h.cmd.env("CORGEA_VULN_API_URL", &base_url);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    let captured = requests.lock().unwrap();
    let request = captured.first().expect("one vuln-api request");
    assert!(header_value(request, "Authorization").is_none());
    assert!(header_value(request, "CORGEA-TOKEN").is_none());
}

#[test]
fn custom_vuln_api_url_sends_token_only_with_opt_in() {
    let (base_url, requests) = spawn_capturing_vuln_api_stub();
    let mut h = PipHarness::new(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
    h.cmd
        .env("CORGEA_VULN_API_URL", &base_url)
        .env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    let captured = requests.lock().unwrap();
    let request = captured.first().expect("one vuln-api request");
    assert_eq!(
        header_value(request, "CORGEA-TOKEN").as_deref(),
        Some("opaque-token")
    );
    assert!(header_value(request, "Authorization").is_none());
}
