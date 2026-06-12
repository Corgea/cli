//! Hermetic e2e tests for the install-gate vuln-api verdict
//! (`corgea pip install …` with public/authenticated `CORGEA_VULN_API_URL`
//! stubs).
//!
//! Composes the `cli_install.rs` harness pattern (fake package manager on a
//! private PATH + local pypi registry stub) with the in-crate vuln-api stub —
//! the shared `common::pip_harness`. Every package is published in 2020, so
//! recency never blocks here — every block in this file is the verdict's
//! doing.

#![cfg(unix)]

mod common;

use common::{key, pip_harness, vulnerable_body};
use corgea::vuln_api_stub::{header_value, spawn_capturing_vuln_api_stub};
use std::collections::HashMap;

#[test]
fn vulnerable_pin_blocks_without_running_install() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
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
    // Advisories are keyed by lowercase(canonical) — the server does NOT
    // apply PEP 503. `pip install Flask_Cors` must still block on the
    // `flask-cors` row: resolution adopts the registry's canonical
    // spelling (`info.name`, like real PyPI, which answers any PEP 503-
    // equivalent request) and the verdict checks that.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "flask-cors", "1.0.0"),
        vulnerable_body("pypi", "flask-cors", "1.0.0", "GHSA-TEST-0001", None),
    );
    // Model real PyPI: serve the alternate request spelling, echo the
    // canonical name in info.name.
    let registry = common::spawn_http_stub(|path| match path {
        "/pypi/Flask_Cors/json" | "/pypi/flask-cors/json" => (
            "200 OK",
            common::pypi_release_json("Flask-Cors", "1.0.0", common::OLD_TS),
        ),
        _ => ("404 Not Found", common::NOT_FOUND_JSON.to_string()),
    });
    // Like `pip_harness` (public mode): the tree dry-run exits 2 (old pip,
    // no --report), so the block is the named verdict's doing and a
    // recorded argv would mean the real install ran.
    let mut h = common::GateHarness::new()
        .fake_tree_pm("pip", common::RESOLUTION_FAILS, 0)
        .registry_env("CORGEA_PYPI_REGISTRY", &registry)
        .vuln_checks(checks)
        .build();
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
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 7);
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
fn no_fail_does_not_waive_vulnerable_block() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "--no-fail", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "--no-fail demotes recency only, never a vulnerable verdict"
    );
    assert_eq!(h.recorded_argv(), None);
}

#[test]
fn verdict_503_warns_and_fails_open() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), "{}".to_string());
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    let mut h = pip_harness(checks, statuses, None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a 503 verdict must fail open in public mode; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not be verified"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("CVE check unavailable; continuing because public mode is fail-open"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn resolution_error_fails_closed_when_authenticated() {
    // The wildcard registry stub only knows version 1.0.0, so `==2.0.0`
    // is a resolution error: no verdict was obtained, and authenticated
    // mode must block — otherwise a registry outage bypasses the gate.
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("test-token"), 0);
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
fn verdict_503_fails_closed_when_authenticated() {
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    let mut h = pip_harness(HashMap::new(), statuses, Some("test-token"), 0);
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
fn tokenless_public_check_discloses_mode() {
    // No token still runs public CVE checks; the hint names what login adds.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
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
fn custom_vuln_api_url_with_token_does_not_send_token_by_default() {
    let (base_url, requests) = spawn_capturing_vuln_api_stub();
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
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
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
    h.cmd
        .env("CORGEA_VULN_API_URL", &base_url)
        .env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    // The opt-in puts the gate in authenticated mode, and pip_harness's tree
    // pass degrades to named-only, so the install fails closed (exit 1) — but
    // the named target's verdict request is still made first, which is what
    // this test asserts: with the opt-in, the token IS sent to the custom URL.
    assert_eq!(out.status.code(), Some(1));
    let captured = requests.lock().unwrap();
    let request = captured.first().expect("one vuln-api request");
    assert_eq!(
        header_value(request, "CORGEA-TOKEN").as_deref(),
        Some("opaque-token")
    );
    assert!(header_value(request, "Authorization").is_none());
}

#[test]
fn json_carries_verdict_object_and_mode() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
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
fn vuln_api_outage_warns_but_installs() {
    let mut h = pip_harness(HashMap::new(), HashMap::new(), None, 0);
    // Point the gate at a dead vuln-api: connection refused on every check.
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
