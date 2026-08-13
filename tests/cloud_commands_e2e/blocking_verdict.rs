//! Contracts for `corgea list --block-on`: reporting a past scan's verdict
//! against the CI blocking rules a pipeline gates on, without rescanning.

use crate::common::*;
use hyper::{Method, StatusCode};
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

fn scan_at(id: &str, status: &str, git_sha: &str) -> serde_json::Value {
    json!({
        "id": id,
        "project": PROJECT,
        "repo": "https://github.com/corgea/cloud-e2e.git",
        "branch": "e2e-main",
        "status": status,
        "engine": "blast",
        "created_at": "2026-07-30T12:00:00Z",
        "git_sha": git_sha
    })
}

/// The duplicate-scan path: read a past scan's verdict against the same CI
/// rules the pipeline gates on, without running a scan.
#[test]
fn list_block_on_attaches_a_verdict_to_every_scan() {
    let project = TempDir::new().expect("create list project");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "list scans to evaluate",
            |request| {
                assert_authenticated_request(request, Method::GET, "/api/v1/scans")?;
                assert_query(request, "project", PROJECT)?;
                // A verdict costs a request per scan, so the default page is
                // the number of scans the pass will evaluate.
                assert_query(request, "page_size", "10")
            },
            json_response(scans_response(vec![
                scan_response("scan-blocked", PROJECT, "complete"),
                scan_response("scan-running", PROJECT, "scanning"),
            ])),
        ),
        expected_request(
            "evaluate the completed scan",
            |request| {
                assert_authenticated_request(
                    request,
                    Method::GET,
                    "/api/v1/scan/scan-blocked/check_blocking_rules",
                )?;
                assert_query(request, "block_on", "criticals,malicious-deps")
            },
            json_response(blocked_response()),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "list",
        "--json",
        "--project-name",
        PROJECT,
        "--block-on",
        "criticals,malicious-deps",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let body = parse_output_json(&output, &transcript);
    let results = body["results"].as_array().expect("list JSON results");
    assert_eq!(results.len(), 2, "{context}");

    let blocked = &results[0]["blocking_verdict"];
    assert_eq!(blocked["status"], "complete", "{context}");
    assert_eq!(blocked["block"], true, "{context}");
    assert_eq!(blocked["blocked_issues"], 3, "{context}");
    assert_eq!(
        blocked["triggered_rules"],
        json!(["criticals"]),
        "{context}"
    );
    assert_eq!(
        blocked["block_on"],
        json!(["criticals", "malicious-deps"]),
        "{context}"
    );

    // A scan that has not finished is never evaluated — the plan above would
    // have flagged the request — and reports a null verdict rather than a pass.
    let running = &results[1]["blocking_verdict"];
    assert_eq!(running["status"], "unavailable", "{context}");
    assert!(running["block"].is_null(), "{context}");
}

/// `--sha` narrows the lookup to the commit the pipeline skipped scanning.
#[test]
fn list_sha_asks_the_server_for_one_commit_and_re_checks_it() {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let project = TempDir::new().expect("create list project");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "list the scans of one commit",
            move |request| {
                assert_authenticated_request(request, Method::GET, "/api/v1/scans")?;
                assert_query(request, "sha", "0123456789abcdef0123456789abcdef01234567")
            },
            // A backend that does not support the filter answers the
            // unfiltered page, whose other commits must not be reported as
            // this one's.
            json_response(scans_response(vec![
                scan_at("scan-at-head", "complete", sha),
                scan_at(
                    "scan-earlier",
                    "complete",
                    "f00dcafef00dcafef00dcafef00dcafef00dcafe",
                ),
            ])),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "list",
        "--json",
        "--project-name",
        PROJECT,
        "--sha",
        &sha.to_ascii_uppercase(),
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let body = parse_output_json(&output, &transcript);
    let results = body["results"].as_array().expect("list JSON results");
    assert_eq!(results.len(), 1, "{context}");
    assert_eq!(results[0]["id"], "scan-at-head", "{context}");
}

/// A short SHA would match nothing server-side, and a duplicate-scan check
/// reads a miss as "never scanned", so it is rejected rather than sent.
#[test]
fn list_sha_rejects_a_short_sha_without_dialing_the_api() {
    let project = TempDir::new().expect("create list project");
    let api = ApiStub::start(vec![verify_request()]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "list",
        "--json",
        "--project-name",
        PROJECT,
        "--sha",
        "0123456",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expects a full commit SHA"), "{context}");
}

/// On an issue listing the flag would silently do nothing, and a pipeline
/// reading a missing verdict as a pass is what `--block-on` exists to prevent.
#[test]
fn list_block_on_is_rejected_on_an_issue_listing() {
    let project = TempDir::new().expect("create list project");
    let api = ApiStub::start(vec![verify_request()]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "list",
        "--issues",
        "--project-name",
        PROJECT,
        "--block-on",
        "criticals",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only supported for the scan listing"),
        "{context}"
    );
}

/// A verdict a pipeline gates on must not degrade into a missing field that
/// reads as "not blocked".
#[test]
fn list_block_on_exits_one_when_the_evaluation_fails() {
    let project = TempDir::new().expect("create list project");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "list scans to evaluate",
            |request| assert_authenticated_request(request, Method::GET, "/api/v1/scans"),
            json_response(scans_response(vec![scan_response(
                "scan-blocked",
                PROJECT,
                "complete",
            )])),
        ),
        expected_request(
            "reject the unknown rule slug",
            |request| {
                assert_authenticated_request(
                    request,
                    Method::GET,
                    "/api/v1/scan/scan-blocked/check_blocking_rules",
                )
            },
            json_response_with_status(
                StatusCode::BAD_REQUEST,
                json!({
                    "status": "error",
                    "message": "Invalid block_on rule(s)",
                    "unknown_slugs": ["criticalz"]
                }),
            ),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "list",
        "--json",
        "--project-name",
        PROJECT,
        "--block-on",
        "criticalz",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown blocking rule(s): criticalz"),
        "{context}"
    );
}
