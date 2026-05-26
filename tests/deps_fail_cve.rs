mod common;

use common::vuln_api_stub::{lodash_vulnerable_response, spawn};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn npm_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/deps/npm")
}

fn corgea_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_corgea"))
}

fn stub_env(stub_url: &str) -> [(&'static str, String); 3] {
    [
        ("CORGEA_VULN_API_URL", stub_url.to_string()),
        ("CORGEA_TOKEN", "test-token".to_string()),
        ("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1".to_string()),
    ]
}

#[test]
fn fail_cve_exits_one_when_vulnerable() {
    let mut fixtures = HashMap::new();
    fixtures.insert(
        ("npm".into(), "lodash".into(), "4.17.20".into()),
        lodash_vulnerable_response(),
    );
    let stub = spawn(fixtures);
    let fixture = npm_fixture_dir();

    let output = corgea_cmd()
        .args([
            "deps",
            "--check-cve",
            "--fail-cve",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ])
        .envs(stub_env(&stub.base_url))
        .output()
        .expect("spawn corgea");

    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_cve_json_includes_cves_and_cve_summary() {
    let mut fixtures = HashMap::new();
    fixtures.insert(
        ("npm".into(), "lodash".into(), "4.17.20".into()),
        lodash_vulnerable_response(),
    );
    let stub = spawn(fixtures);
    let fixture = npm_fixture_dir();

    let output = corgea_cmd()
        .args([
            "deps",
            "--check-cve",
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ])
        .envs(stub_env(&stub.base_url))
        .output()
        .expect("spawn corgea");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body: Value = serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");

    let summary = body
        .get("cve_summary")
        .expect("cve_summary should be present with --check-cve");
    assert_eq!(summary.get("skipped").and_then(Value::as_bool), Some(false));
    assert!(summary.get("checked").and_then(Value::as_u64).is_some());
    assert!(summary.get("vulnerable").and_then(Value::as_u64).is_some());
    assert!(summary.get("clean").and_then(Value::as_u64).is_some());
    assert!(summary.get("errors").and_then(Value::as_u64).is_some());

    let results = body
        .get("results")
        .and_then(Value::as_array)
        .expect("results array");
    let lodash = results
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some("lodash"))
        .expect("lodash result");
    let cves = lodash
        .get("cves")
        .and_then(Value::as_array)
        .expect("cves array on lodash");
    assert_eq!(cves.len(), 1);
    let entry = &cves[0];
    assert_eq!(
        entry.get("advisory_id").and_then(Value::as_str),
        Some("GHSA-integration-test")
    );
    assert_eq!(
        entry.get("severity_level").and_then(Value::as_str),
        Some("high")
    );
    assert_eq!(entry.get("tier").and_then(Value::as_u64), Some(2));
    assert!(entry.get("vulnerable_version_range").is_some());
    assert!(entry.get("fixed_version").is_some());
}

#[test]
fn json_omits_cve_fields_without_check_cve() {
    let fixture = npm_fixture_dir();

    let output = corgea_cmd()
        .args([
            "deps",
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ])
        .env("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1")
        .output()
        .expect("spawn corgea");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body: Value = serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");
    assert!(body.get("cve_summary").is_none());
    let results = body
        .get("results")
        .and_then(Value::as_array)
        .expect("results array");
    assert!(!results.is_empty());
    for dep in results {
        assert!(dep.get("cves").is_none());
        assert!(dep.get("cve_status").is_none());
    }
}

#[test]
fn fail_cve_without_check_cve_errors() {
    let output = corgea_cmd()
        .args(["deps", "--fail-cve"])
        .output()
        .expect("spawn corgea");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("check-cve") || stderr.contains("check_cve"),
        "expected requires --check-cve message, got: {stderr}"
    );
}
