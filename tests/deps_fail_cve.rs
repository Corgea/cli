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

fn run_deps(args: &[&str], extra_env: &[(&str, String)]) -> std::process::Output {
    let mut cmd = corgea_cmd();
    cmd.args(args);
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn corgea")
}

fn run_deps_json(args: &[&str], extra_env: &[(&str, String)]) -> Value {
    let output = run_deps(args, extra_env);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON")
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

    let output = run_deps(
        &[
            "deps",
            "--check-cve",
            "--fail-cve",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &stub_env(&stub.base_url),
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fail_cve_exits_zero_when_all_clean() {
    let stub = spawn(HashMap::new());
    let fixture = npm_fixture_dir();

    let output = run_deps(
        &[
            "deps",
            "--check-cve",
            "--fail-cve",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &stub_env(&stub.base_url),
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fail_cve_and_fail_flags_are_independent() {
    let mut fixtures = HashMap::new();
    fixtures.insert(
        ("npm".into(), "lodash".into(), "4.17.20".into()),
        lodash_vulnerable_response(),
    );
    let stub = spawn(fixtures);
    let fixture = npm_fixture_dir();
    let env = stub_env(&stub.base_url);
    let path = fixture.to_str().unwrap();

    // CVE present, neither gate flag → success.
    let neither = run_deps(&["deps", "--check-cve", "-e", "npm", "-p", path], &env);
    assert_eq!(neither.status.code(), Some(0));

    // --fail-cve alone gates on CVEs.
    let fail_cve_only = run_deps(
        &["deps", "--check-cve", "--fail-cve", "-e", "npm", "-p", path],
        &env,
    );
    assert_eq!(fail_cve_only.status.code(), Some(1));

    // --fail alone also gates on CVE findings (legacy behavior).
    let fail_only = run_deps(
        &["deps", "--check-cve", "--fail", "-e", "npm", "-p", path],
        &env,
    );
    assert_eq!(fail_only.status.code(), Some(1));
}

#[test]
fn fail_cve_not_triggered_by_cve_lookup_errors() {
    let fixture = npm_fixture_dir();
    let env = [
        ("CORGEA_VULN_API_URL", "http://127.0.0.1:1".to_string()),
        ("CORGEA_TOKEN", "test-token".to_string()),
        ("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1".to_string()),
    ];

    let fail_cve = run_deps(
        &[
            "deps",
            "--check-cve",
            "--fail-cve",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        fail_cve.status.code(),
        Some(0),
        "--fail-cve should not trip on lookup errors alone; stderr: {}",
        String::from_utf8_lossy(&fail_cve.stderr)
    );

    let fail = run_deps(
        &[
            "deps",
            "--check-cve",
            "--fail",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        fail.status.code(),
        Some(1),
        "--fail should still trip on CVE lookup errors; stderr: {}",
        String::from_utf8_lossy(&fail.stderr)
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

    let body = run_deps_json(
        &[
            "deps",
            "--check-cve",
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &stub_env(&stub.base_url),
    );

    let summary = body
        .get("cve_summary")
        .expect("cve_summary should be present with --check-cve");
    assert_eq!(summary.get("vulnerable").and_then(Value::as_u64), Some(1));
    assert_eq!(summary.get("clean").and_then(Value::as_u64), Some(2));
    assert_eq!(summary.get("errors").and_then(Value::as_u64), Some(0));
    assert!(summary.get("checked").and_then(Value::as_u64).is_some());
    assert!(
        summary.get("skipped").is_none(),
        "skipped key removed from cve_summary"
    );
    // Severity-floor schema lock (chunk 08): both keys always present
    // when cve_summary is emitted; default floor is "any" and
    // vulnerable_above_floor == vulnerable.
    assert_eq!(
        summary.get("severity_floor").and_then(Value::as_str),
        Some("any")
    );
    assert_eq!(
        summary
            .get("vulnerable_above_floor")
            .and_then(Value::as_u64),
        Some(1)
    );

    let results = body
        .get("results")
        .and_then(Value::as_array)
        .expect("results array");
    let lodash = results
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some("lodash"))
        .expect("lodash result");
    assert_eq!(
        lodash.get("cve_status").and_then(Value::as_str),
        Some("vulnerable")
    );
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
fn json_clean_deps_have_empty_cves_array() {
    let stub = spawn(HashMap::new());
    let fixture = npm_fixture_dir();

    let body = run_deps_json(
        &[
            "deps",
            "--check-cve",
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &stub_env(&stub.base_url),
    );

    let results = body
        .get("results")
        .and_then(Value::as_array)
        .expect("results array");
    let semver = results
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some("semver"))
        .expect("semver result");
    assert_eq!(
        semver.get("cve_status").and_then(Value::as_str),
        Some("clean")
    );
    assert_eq!(
        semver.get("cves").and_then(Value::as_array).map(Vec::len),
        Some(0)
    );
    assert!(semver.get("cve_error").is_none());

    // Severity-floor schema lock (chunk 08): floor defaults to "any" and
    // vulnerable_above_floor is 0 when there are no findings.
    let summary = body
        .get("cve_summary")
        .expect("cve_summary should be present with --check-cve");
    assert_eq!(
        summary.get("severity_floor").and_then(Value::as_str),
        Some("any")
    );
    assert_eq!(
        summary
            .get("vulnerable_above_floor")
            .and_then(Value::as_u64),
        Some(0)
    );
}

#[test]
fn json_omits_cve_fields_without_check_cve() {
    let fixture = npm_fixture_dir();

    let body = run_deps_json(
        &[
            "deps",
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &[("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1".to_string())],
    );
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
fn cve_check_total_failure_renders_explicit_message() {
    let fixture = npm_fixture_dir();
    let env = [
        ("CORGEA_VULN_API_URL", "http://127.0.0.1:1".to_string()),
        ("CORGEA_TOKEN", "test-token".to_string()),
        ("CORGEA_NPM_REGISTRY", "http://127.0.0.1:1".to_string()),
    ];

    let output = run_deps(
        &[
            "deps",
            "--check-cve",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("✗ CVE check did not complete"),
        "expected explicit failure message under 'Known vulnerabilities:'; stdout:\n{}",
        stdout
    );
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
