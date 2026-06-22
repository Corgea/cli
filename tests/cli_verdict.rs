//! Hermetic e2e tests for the install-gate vuln-api verdict
//! (`corgea pip install …` with a public `CORGEA_VULN_API_URL` stub).
//!
//! Composes the `cli_install.rs` harness pattern (fake package manager on a
//! private PATH + local pypi registry stub) with the in-crate vuln-api stub —
//! the shared `common::pip_harness`. Every package is published in 2020, so
//! recency never blocks here — every block in this file is the verdict's
//! doing. Lookups are public: outages warn and fail open.

#![cfg(unix)]

mod common;

use common::{key, pip_harness, vulnerable_body};
use std::collections::HashMap;

#[test]
fn vulnerable_pin_blocks_without_running_install() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), 0);
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
    // Like `pip_harness`: the tree dry-run exits 2 (old pip, no --report),
    // so the block is the named verdict's doing and a recorded argv would
    // mean the real install ran.
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
    let mut h = pip_harness(checks, HashMap::new(), 7);
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
    let mut h = pip_harness(checks, HashMap::new(), 0);
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
    let mut h = pip_harness(checks, statuses, 0);
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
fn vuln_api_outage_warns_but_installs() {
    let mut h = pip_harness(HashMap::new(), HashMap::new(), 0);
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
