mod common;

use common::corgea_cmd;
use common::stub_env;
use common::vuln_api_stub::{
    lodash_critical_and_high_response, lodash_critical_high_and_medium_response,
    lodash_unknown_severity_response, lodash_vulnerable_response, spawn, VulnApiStub,
};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

fn npm_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/deps/npm")
}

fn run_deps(args: &[&str], extra_env: &[(&'static str, String)]) -> std::process::Output {
    let _lock = common::cve_integration_lock();
    let mut cmd = corgea_cmd();
    cmd.args(args);
    // Serialize requests against the in-process stub so parallel test
    // runs don't overwhelm its single-threaded accept loop. Mirrors the
    // CLI's `--cve-concurrency` flag (clap-validated 1..32).
    cmd.args(["--cve-concurrency", "1"]);
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn corgea")
}

fn stub_with_lodash(body: String) -> (VulnApiStub, [(&'static str, String); 3]) {
    let mut fixtures = HashMap::new();
    fixtures.insert(
        (
            "npm".to_string(),
            "lodash".to_string(),
            "4.17.20".to_string(),
        ),
        body,
    );
    let stub = spawn(fixtures);
    let env = stub_env(&stub.base_url);
    (stub, env)
}

#[test]
fn severity_critical_blocks_only_critical_findings() {
    let (_stub, env) = stub_with_lodash(lodash_critical_and_high_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "critical",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn severity_critical_exits_zero_when_only_high_finding() {
    // lodash_vulnerable_response emits a single match at severity "high".
    let (_stub, env) = stub_with_lodash(lodash_vulnerable_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "critical",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn severity_low_blocks_everything_at_or_above_low() {
    let (_stub, env) = stub_with_lodash(lodash_critical_and_high_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "low",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn severity_any_preserves_chunk_02_behavior() {
    let (_stub, env) = stub_with_lodash(lodash_vulnerable_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "any",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn severity_oneof_matches_exact_set() {
    let (_stub, env) = stub_with_lodash(lodash_critical_high_and_medium_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "critical,high",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn severity_without_fail_cve_errors() {
    // Pre-flight (no stub) — non-Any --severity without --fail-cve must
    // exit 2 at the runtime guard before any work is done.
    let output = corgea_cmd()
        .args(["deps", "verify", "--check-cve", "--severity", "critical"])
        .output()
        .expect("spawn corgea");
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--severity requires --fail-cve"),
        "expected runtime --severity requires --fail-cve message, got: {stderr}"
    );
}

#[test]
fn explicit_severity_any_without_fail_cve_succeeds() {
    // Explicit `--severity any` is a no-op gate-wise; the runtime guard
    // must NOT require --fail-cve in that case, so CI matrices that
    // always pass `--severity any` keep working without `--fail-cve`.
    let (_stub, env) = stub_with_lodash(lodash_vulnerable_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--severity",
            "any",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "explicit --severity any without --fail-cve must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn severity_invalid_value_exits_two() {
    let output = corgea_cmd()
        .args([
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "bogus",
        ])
        .output()
        .expect("spawn corgea");
    assert_eq!(output.status.code(), Some(2));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        combined.contains("invalid value") || combined.contains("unknown severity"),
        "expected clap value-parser error, got: {combined}"
    );
}

#[test]
fn severity_unknown_server_string_treated_as_info() {
    let fixture = npm_fixture_dir();

    // --severity any: must still trip on the "unknown" finding.
    let (_stub_any, env_any) = stub_with_lodash(lodash_unknown_severity_response());
    let output_any = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "any",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env_any,
    );
    assert_eq!(
        output_any.status.code(),
        Some(1),
        "Any floor must catch unknown severity; stderr: {}",
        String::from_utf8_lossy(&output_any.stderr)
    );

    // --severity critical: must NOT trip on "unknown" (collapses to Info).
    let (_stub_critical, env_critical) = stub_with_lodash(lodash_unknown_severity_response());
    let output_critical = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "critical",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env_critical,
    );
    assert_eq!(
        output_critical.status.code(),
        Some(0),
        "Critical floor must filter out unknown severity (Info); stderr: {}",
        String::from_utf8_lossy(&output_critical.stderr)
    );
}

#[test]
fn severity_does_not_widen_fail_broad_gate() {
    // --fail still trips on any CVE finding regardless of floor: even
    // with --severity critical and a high-only fixture, --fail must
    // still exit 1.
    let (_stub, env) = stub_with_lodash(lodash_vulnerable_response()); // high only
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail",
            "--fail-cve",
            "--severity",
            "critical",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "--fail must still trip on any CVE finding regardless of --severity; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn severity_critical_below_floor_note_appears_in_text_output() {
    let (_stub, env) = stub_with_lodash(lodash_critical_and_high_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "critical",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("advisory matches below --severity floor (critical)"),
        "expected below-floor note in stdout, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("informational only"),
        "expected 'informational only' phrase, got:\n{}",
        stdout
    );
    // Below-floor matches still render with their severity tag.
    assert!(
        stdout.contains("(severity: high)"),
        "expected below-floor match still rendered, got:\n{}",
        stdout
    );
}

#[test]
fn severity_oneof_outside_set_note_appears_in_text_output() {
    let (_stub, env) = stub_with_lodash(lodash_critical_high_and_medium_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "critical,high",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("advisory matches outside --severity set (critical,high)"),
        "expected outside-set note in stdout, got:\n{}",
        stdout
    );
}

#[test]
fn severity_any_does_not_emit_below_floor_note() {
    let (_stub, env) = stub_with_lodash(lodash_critical_and_high_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "any",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("below --severity floor"),
        "Any floor must not emit below-floor note, got:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("outside --severity set"),
        "Any floor must not emit outside-set note, got:\n{}",
        stdout
    );
}

#[test]
fn severity_floor_emitted_in_cve_summary_json() {
    let (_stub, env) = stub_with_lodash(lodash_critical_and_high_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "critical",
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    // --fail-cve trips → exit 1 — but JSON still printed on stdout
    // before exit. Parse it without asserting status.
    let body: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON even on exit 1");
    let summary = body
        .get("cve_summary")
        .expect("cve_summary should be present");
    assert_eq!(
        summary.get("severity_floor").and_then(Value::as_str),
        Some("critical")
    );
    assert_eq!(
        summary
            .get("vulnerable_above_floor")
            .and_then(Value::as_u64),
        Some(1)
    );
    // Existing keys untouched.
    assert_eq!(summary.get("vulnerable").and_then(Value::as_u64), Some(1));
}

#[test]
fn severity_any_emits_floor_as_any_in_json() {
    let (_stub, env) = stub_with_lodash(lodash_vulnerable_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    let body: Value = serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");
    let summary = body
        .get("cve_summary")
        .expect("cve_summary should be present");
    assert_eq!(
        summary.get("severity_floor").and_then(Value::as_str),
        Some("any")
    );
    // vulnerable_above_floor must equal vulnerable when floor is Any.
    let vulnerable = summary.get("vulnerable").and_then(Value::as_u64).unwrap();
    assert_eq!(
        summary
            .get("vulnerable_above_floor")
            .and_then(Value::as_u64),
        Some(vulnerable)
    );
}

#[test]
fn severity_oneof_emits_descending_label_in_json() {
    let (_stub, env) = stub_with_lodash(lodash_critical_high_and_medium_response());
    let fixture = npm_fixture_dir();
    let output = run_deps(
        &[
            "deps",
            "verify",
            "--check-cve",
            "--fail-cve",
            "--severity",
            "high,critical", // user input order
            "--json",
            "-e",
            "npm",
            "-p",
            fixture.to_str().unwrap(),
        ],
        &env,
    );
    let body: Value = serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");
    let summary = body
        .get("cve_summary")
        .expect("cve_summary should be present");
    // Label is always rendered descending-by-severity for stability.
    assert_eq!(
        summary.get("severity_floor").and_then(Value::as_str),
        Some("critical,high")
    );
}
