//! Hermetic e2e tests for remediation steering: a blocked install names the
//! safe version from the verdict's `fixed_version` data — the highest fix
//! covering every advisory. When any advisory has no known fix, no steer
//! prints and JSON `remediation` is null.
//!
//! Uses the shared `common::PipHarness` (pypi stub published 2020 so recency
//! never blocks, a fake pip recording its argv, the in-crate vuln-api stub,
//! and a set token) — every block here is the verdict's doing.

#![cfg(unix)]

mod common;

use common::{key, vulnerable_body, PipHarness};
use std::collections::HashMap;

fn fixed_body() -> String {
    vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0001", Some("2.0.0"))
}

fn no_fix_body() -> String {
    vulnerable_body("pypi", "oldpkg", "1.0.0", "MAL-2024-0002", None)
}

#[test]
fn fixed_match_blocks_and_names_safe_version() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), fixed_body());
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
    assert_eq!(
        parsed["results"][0]["verdict"]["remediation"], "2.0.0",
        "parsed: {parsed}"
    );
}

#[test]
fn json_remediation_null_when_no_fix() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), no_fix_body());
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
