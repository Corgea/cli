//! Contracts for the CI blocking-rule gate: that a tripped `--block-on` still
//! produces the report the pipeline asked for.

use crate::common::*;
use hyper::Method;
use serde_json::json;
use tempfile::TempDir;

const PROJECT: &str = "cloud-e2e";

/// `check_blocking_rules` answering "blocked by `criticals`", with the server's
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

/// A tripped `--block-on` gate exits 1, but the pipeline still needs the report
/// to ingest the findings it failed on. The stub's plan is ordered, so it is
/// also what proves the report is fetched before the gate is evaluated.
#[test]
fn scan_block_on_writes_the_report_before_failing_the_gate() {
    let project = git_project();
    let out_dir = TempDir::new().expect("create report directory");
    let out_file = out_dir.path().join("results.sarif");
    let mut plan = blast_upload_plan(&project.sha, false, false);
    plan.push(expected_request(
        "generate the SARIF report",
        |request| {
            assert_authenticated_request(
                request,
                Method::GET,
                "/api/v1/scan/blast-scan-123/report",
            )?;
            assert_query(request, "format", "sarif")
        },
        json_response(json!({"version": "2.1.0", "runs": []})),
    ));
    plan.push(expected_request(
        "evaluate the blocking rules",
        |request| {
            assert_authenticated_request(
                request,
                Method::GET,
                "/api/v1/scan/blast-scan-123/check_blocking_rules",
            )?;
            assert_query(request, "block_on", "criticals")
        },
        json_response(blocked_response()),
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
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("3 issue(s) violated the blocking rule(s)"),
        "{context}"
    );
    let written = std::fs::read_to_string(&out_file)
        .unwrap_or_else(|error| panic!("report should exist despite the gate: {error}\n{context}"));
    assert!(written.contains("2.1.0"), "{context}");
}
