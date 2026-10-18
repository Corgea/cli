use crate::common::*;
use hyper::{Method, StatusCode};
use serde_json::json;
use tempfile::TempDir;

#[test]
fn inspect_scan_json_returns_requested_scan() {
    let project = TempDir::new().expect("create inspect project");
    let scan_id = "inspect-scan-123";
    let scan_path = format!("/api/v1/scan/{scan_id}");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "inspect scan as JSON",
            move |request| assert_authenticated_request(request, Method::GET, &scan_path),
            json_response(json!({
                "id": scan_id,
                "project": "inspect-project",
                "repo": "https://github.com/corgea/inspect-project.git",
                "branch": "main",
                "status": "complete",
                "engine": "blast",
                "created_at": "2026-07-30T12:00:00Z",
                "git_sha": "abcdef0123456789abcdef0123456789abcdef01"
            })),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["inspect", scan_id, "--json"]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let body = parse_output_json(&output, &transcript);
    assert_eq!(body["id"], scan_id, "{context}");
    assert_eq!(body["project"], "inspect-project", "{context}");
    assert_eq!(body["status"], "complete", "{context}");
    assert_eq!(body["engine"], "blast", "{context}");
    assert_eq!(
        body["git_sha"], "abcdef0123456789abcdef0123456789abcdef01",
        "{context}"
    );
}

#[test]
fn inspect_issue_json_returns_requested_issue() {
    let project = TempDir::new().expect("create inspect project");
    let issue_id = "inspect-issue-123";
    let issue_path = format!("/api/v1/issue/{issue_id}");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "inspect issue as JSON",
            move |request| assert_authenticated_request(request, Method::GET, &issue_path),
            json_response(json!({
                "status": "ok",
                "issue": regular_issue(
                    issue_id,
                    "inspect-scan-123",
                    "inspect-project",
                    "HI"
                )
            })),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["inspect", "--issue", "--json", issue_id]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let body = parse_output_json(&output, &transcript);
    assert_eq!(body["status"], "ok", "{context}");
    assert_eq!(body["issue"]["id"], issue_id, "{context}");
    assert_eq!(body["issue"]["scan_id"], "inspect-scan-123", "{context}");
    assert_eq!(body["issue"]["urgency"], "HI", "{context}");
    assert_eq!(
        body["issue"]["classification"]["name"], "HI test issue",
        "{context}"
    );
    assert_eq!(
        body["issue"]["location"]["file"]["path"], "src/main.py",
        "{context}"
    );
    assert_eq!(body["issue"]["location"]["line_number"], 7, "{context}");
}

fn inspect_issue_with_scanner_metadata(args: &[&str]) -> (std::process::Output, String) {
    let project = TempDir::new().expect("create inspect project");
    let issue_id = "inspect-fortify-issue";
    let issue_path = format!("/api/v1/issue/{issue_id}");
    let mut issue = regular_issue(issue_id, "inspect-scan-123", "inspect-project", "HI");
    issue["scanner_metadata"] = json!({"scanner": "fortify", "kingdom": "stale"});
    issue["metadata"] = json!({
        "instance_id": "6B481068C7D139B941ADF736E39E0676",
        "class_id": "78E0700E-56FE-45A2-A11B-6A560F730576",
        "kingdom": "Encapsulation",
        "category": "Cross-Site Request Forgery",
        "analyzer": "content",
        "build_id": "TODS",
        "sub_category": null
    });
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "inspect issue with scanner metadata",
            move |request| {
                assert_authenticated_request(request, Method::GET, &issue_path)?;
                assert_query(request, "include_metadata", "true")
            },
            json_response(json!({"status": "ok", "issue": issue})),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command
        .args(["inspect", "--issue"])
        .args(args)
        .arg(issue_id);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    (output, transcript)
}

#[test]
fn inspect_issue_json_includes_scanner_metadata() {
    let (output, transcript) = inspect_issue_with_scanner_metadata(&["--json"]);
    let body = parse_output_json(&output, &transcript);
    let issue = &body["issue"];
    assert_eq!(issue["scanner_metadata"]["scanner"], "fortify");
    assert_eq!(
        issue["metadata"]["instance_id"],
        "6B481068C7D139B941ADF736E39E0676"
    );
    assert_eq!(issue["metadata"]["kingdom"], "Encapsulation");
    assert_eq!(issue["metadata"]["build_id"], "TODS");
}

#[test]
fn inspect_issue_summary_prints_scanner_metadata() {
    let (output, transcript) = inspect_issue_with_scanner_metadata(&["--summary"]);
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scanner Metadata:"), "{context}");
    for expected in [
        "instance_id  : 6B481068C7D139B941ADF736E39E0676",
        "class_id     : 78E0700E-56FE-45A2-A11B-6A560F730576",
        "kingdom      : Encapsulation",
        "category     : Cross-Site Request Forgery",
        "analyzer     : content",
        "build_id     : TODS",
        "scanner      : fortify",
    ] {
        assert!(stdout.contains(expected), "missing {expected:?}\n{context}");
    }
    assert!(!stdout.contains("stale"), "{context}");
    assert!(!stdout.contains("sub_category"), "{context}");
}

#[test]
fn inspect_scan_exits_one_on_server_error() {
    let project = TempDir::new().expect("create inspect project");
    let scan_id = "inspect-error-scan";
    let scan_path = format!("/api/v1/scan/{scan_id}");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "reject scan inspection",
            move |request| assert_authenticated_request(request, Method::GET, &scan_path),
            json_response_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"status": "error"}),
            ),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["inspect", scan_id]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(scan_id), "{context}");
}

#[test]
fn inspect_issue_exits_one_on_invalid_contract() {
    let project = TempDir::new().expect("create inspect project");
    let issue_id = "inspect-invalid-issue";
    let issue_path = format!("/api/v1/issue/{issue_id}");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "return invalid issue contract",
            move |request| assert_authenticated_request(request, Method::GET, &issue_path),
            json_response(json!({"unexpected": true})),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["inspect", "--issue", "--json", issue_id]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(issue_id), "{context}");
    assert!(stderr.contains("Failed to parse response"), "{context}");
}
