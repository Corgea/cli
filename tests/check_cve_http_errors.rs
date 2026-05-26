mod common;

use common::vuln_api_stub::spawn_with_statuses;
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
fn check_cve_404_is_clean_in_json() {
    let mut fixtures = HashMap::new();
    fixtures.insert(
        ("npm".into(), "semver".into(), "5.4.1".into()),
        r#"{"error":"not found"}"#.to_string(),
    );
    let mut statuses = HashMap::new();
    statuses.insert(("npm".into(), "semver".into(), "5.4.1".into()), 404);

    let stub = spawn_with_statuses(fixtures, statuses);
    let output = corgea_cmd()
        .args([
            "deps",
            "--check-cve",
            "--json",
            "-e",
            "npm",
            "-p",
            npm_fixture_dir().to_str().unwrap(),
        ])
        .envs(stub_env(&stub.base_url))
        .output()
        .expect("spawn corgea");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();

    let summary = body.get("cve_summary").expect("cve_summary");
    assert_eq!(summary.get("errors").and_then(Value::as_u64), Some(0));

    let results = body.get("results").and_then(Value::as_array).unwrap();
    let semver = results
        .iter()
        .find(|r| r["name"] == "semver")
        .expect("semver");
    assert_eq!(
        semver.get("cve_status").and_then(Value::as_str),
        Some("clean")
    );
    assert_eq!(
        semver.get("cves").and_then(Value::as_array).map(Vec::len),
        Some(0)
    );
    assert!(semver.get("cve_error").is_none());
}

#[test]
fn check_cve_http_errors_render_actionable_messages() {
    let mut fixtures = HashMap::new();
    let mut statuses = HashMap::new();

    for (name, ver, code, body) in [
        ("lodash", "4.17.20", 401u16, r#"{"error":"unauthorized"}"#),
        ("semver", "5.4.1", 403, r#"{"error":"forbidden"}"#),
        ("json5", "2.2.1", 429, r#"{"error":"rate limited"}"#),
    ] {
        fixtures.insert(("npm".into(), name.into(), ver.into()), body.to_string());
        statuses.insert(("npm".into(), name.into(), ver.into()), code);
    }

    let stub = spawn_with_statuses(fixtures, statuses);
    let output = corgea_cmd()
        .args([
            "deps",
            "--check-cve",
            "-e",
            "npm",
            "-p",
            npm_fixture_dir().to_str().unwrap(),
        ])
        .envs(stub_env(&stub.base_url))
        .output()
        .expect("spawn corgea");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CVE lookup errors:"));
    assert!(stdout.contains("rejected the Corgea token"));
    assert!(stdout.contains("access denied"));
    assert!(stdout.contains("rate-limited"));
}

#[test]
fn check_cve_500_renders_unavailable_message() {
    let mut fixtures = HashMap::new();
    fixtures.insert(
        ("npm".into(), "lodash".into(), "4.17.20".into()),
        r#"{"error":"internal"}"#.to_string(),
    );
    let mut statuses = HashMap::new();
    statuses.insert(("npm".into(), "lodash".into(), "4.17.20".into()), 500);

    let stub = spawn_with_statuses(fixtures, statuses);
    let output = corgea_cmd()
        .args([
            "deps",
            "--check-cve",
            "-e",
            "npm",
            "-p",
            npm_fixture_dir().to_str().unwrap(),
        ])
        .envs(stub_env(&stub.base_url))
        .output()
        .expect("spawn corgea");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("unavailable (HTTP 500)"));
}
