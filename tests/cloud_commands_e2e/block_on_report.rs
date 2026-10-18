//! `--out-format`/`--out-file` and `--sbom` under a CI blocking-rule gate: a
//! pipeline that fails on policy is the one that needs the report, so a tripped
//! gate must not take the report file down with it.
//!
//! The stub's plan is ordered, so these tests are also what pins the report
//! ahead of the gate: reordering them back puts the report request after the
//! `check_blocking_rules` request and fails the plan.

use crate::common::*;
use hyper::Method;
use serde_json::json;
use tempfile::TempDir;

const PROJECT: &str = "cloud-e2e";
const SCAN_ID: &str = "blast-scan-123";

/// `check_blocking_rules` answering "blocked", with the server's
/// pre-pagination total.
fn blocked_response() -> serde_json::Value {
    json!({
        "block": true,
        "blocking_issues": [{
            "id": "issue-1",
            "triggered_by_rules": ["7"],
            "triggered_by_slugs": ["criticals"]
        }],
        "total_pages": 1,
        "stats": {"blocked_issues": 3},
        "status": "complete"
    })
}

/// The SARIF report request the CLI makes for `--out-format sarif`.
fn sarif_report_request() -> ExpectedRequest {
    expected_request(
        "generate the SARIF report",
        |request| {
            assert_authenticated_request(
                request,
                Method::GET,
                &format!("/api/v1/scan/{SCAN_ID}/report"),
            )?;
            assert_query(request, "format", "sarif")
        },
        json_response(json!({"version": "2.1.0", "runs": []})),
    )
}

/// A blocking-rules check that reports the scan as blocked. `block_on` is the
/// expected query value, or `None` for the rule-wide `--fail` form.
fn blocked_check_request(block_on: Option<&'static str>) -> ExpectedRequest {
    expected_request(
        "evaluate the blocking rules",
        move |request| {
            assert_authenticated_request(
                request,
                Method::GET,
                &format!("/api/v1/scan/{SCAN_ID}/check_blocking_rules"),
            )?;
            match block_on {
                Some(slugs) => assert_query(request, "block_on", slugs),
                // --fail evaluates every active rule, so it must not narrow the
                // check to slugs.
                None => match query_value(request, "block_on") {
                    Ok(value) => Err(format!("unexpected block_on={value} for --fail")),
                    Err(_) => Ok(()),
                },
            }
        },
        json_response(blocked_response()),
    )
}

#[test]
fn block_on_writes_the_report_and_sbom_before_failing_the_gate() {
    let project = git_project();
    let out_dir = TempDir::new().expect("create output directory");
    let out_file = out_dir.path().join("results.sarif");
    let sbom_file = out_dir.path().join("bom.json");
    let mut plan = blast_upload_plan(&project.sha, false, false);
    plan.push(sarif_report_request());
    plan.push(blocked_check_request(Some("criticals")));
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--block-on",
        "criticals",
        "--out-format",
        "sarif",
        "--out-file",
        out_file.to_str().expect("UTF-8 report path"),
        "--sbom",
        sbom_file.to_str().expect("UTF-8 SBOM path"),
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("3 issue(s) violated the blocking rule(s)"),
        "{context}"
    );
    let report = std::fs::read_to_string(&out_file)
        .unwrap_or_else(|error| panic!("report should exist despite the gate: {error}\n{context}"));
    assert!(report.contains("2.1.0"), "{context}");
    let sbom = std::fs::read_to_string(&sbom_file)
        .unwrap_or_else(|error| panic!("SBOM should exist despite the gate: {error}\n{context}"));
    assert!(sbom.contains("bomFormat"), "SBOM body: {sbom}\n{context}");
}

/// `--fail` is deprecated but still supported, and it exits through the same
/// gate, so it must not drop the report either.
#[test]
fn fail_writes_the_report_before_failing_the_gate() {
    let project = git_project();
    let out_dir = TempDir::new().expect("create output directory");
    let out_file = out_dir.path().join("results.sarif");
    let mut plan = blast_upload_plan(&project.sha, false, false);
    plan.push(sarif_report_request());
    plan.push(blocked_check_request(None));
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--fail",
        "--out-format",
        "sarif",
        "--out-file",
        out_file.to_str().expect("UTF-8 report path"),
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let report = std::fs::read_to_string(&out_file)
        .unwrap_or_else(|error| panic!("report should exist despite the gate: {error}\n{context}"));
    assert!(report.contains("2.1.0"), "{context}");
}

/// A gate that passes has always written the report; the reorder must not have
/// changed that, and the scan still exits 0.
#[test]
fn block_on_still_writes_the_report_when_the_gate_passes() {
    let project = git_project();
    let out_dir = TempDir::new().expect("create output directory");
    let out_file = out_dir.path().join("results.sarif");
    let mut plan = blast_upload_plan(&project.sha, false, false);
    plan.push(sarif_report_request());
    plan.push(expected_request(
        "evaluate the blocking rules",
        |request| {
            assert_authenticated_request(
                request,
                Method::GET,
                &format!("/api/v1/scan/{SCAN_ID}/check_blocking_rules"),
            )
        },
        json_response(json!({
            "block": false,
            "blocking_issues": [],
            "total_pages": 1,
            "stats": {"blocked_issues": 0},
            "status": "complete"
        })),
    ));
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--block-on",
        "criticals",
        "--out-format",
        "sarif",
        "--out-file",
        out_file.to_str().expect("UTF-8 report path"),
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The slug itself is color-coded, so the literal stops at the colon.
    assert!(
        stdout.contains("No issues violated the blocking rule(s):"),
        "{context}"
    );
    let report = std::fs::read_to_string(&out_file)
        .unwrap_or_else(|error| panic!("report should exist: {error}\n{context}"));
    assert!(report.contains("2.1.0"), "{context}");
}
