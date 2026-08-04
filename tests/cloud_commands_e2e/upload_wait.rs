use crate::common::*;
use hyper::{Method, StatusCode};
use serde_json::json;
use tempfile::TempDir;

#[test]
fn upload_prints_tracking_url_from_returned_ids() {
    let project = report_project();
    let api = ApiStub::start(upload_plan("scan-upload-123", 42));
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "upload",
        project.report_path().to_str().expect("UTF-8 report path"),
        "--project-name",
        "upload-contract",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan-upload-123"), "{context}");
    assert!(
        stdout.contains("/project/42/?scan_id=scan-upload-123"),
        "{context}"
    );
    assert!(
        stdout.contains("continue securely in the Corgea cloud"),
        "{context}"
    );
}

#[test]
fn upload_wait_uses_returned_ids_and_stops_at_complete() {
    let project = report_project();
    let local_project = temp_project_name(project.path());
    let mut plan = upload_plan("wait-scan-123", 73);
    append_wait_plan(
        &mut plan,
        &local_project,
        "wait-scan-123",
        &["processing", "complete"],
    );
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "upload",
        project.report_path().to_str().expect("UTF-8 report path"),
        "--project-name",
        "upload-contract",
        "--wait",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/project/73/?scan_id=wait-scan-123"),
        "{context}"
    );
    assert_issue_summary(&stdout, &context);
}

#[test]
fn wait_reports_an_immediately_complete_scan() {
    let project = TempDir::new().expect("create wait project");
    let local_project = temp_project_name(project.path());
    let mut plan = vec![verify_request()];
    append_wait_plan(
        &mut plan,
        &local_project,
        "complete-scan-123",
        &["complete"],
    );
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["wait", "complete-scan-123"]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Scan has been processed successfully!"),
        "{context}"
    );
    assert!(stdout.contains("scan_id=complete-scan-123"), "{context}");
    assert_issue_summary(&stdout, &context);
}

#[test]
fn wait_exits_one_when_scan_list_fails() {
    let project = TempDir::new().expect("create wait project");
    let local_project = temp_project_name(project.path());
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "reject scan list",
            move |request| assert_scan_list_request(request, &local_project),
            json_response_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"status": "error"}),
            ),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.arg("wait");

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unable to query the scan list"),
        "{context}"
    );
}

#[test]
fn wait_exits_one_when_scan_detail_fails() {
    let project = TempDir::new().expect("create wait project");
    let scan_id = "detail-error-scan";
    let detail_path = format!("/api/v1/scan/{scan_id}");
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "reject scan detail",
            move |request| assert_authenticated_request(request, Method::GET, &detail_path),
            json_response_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"status": "error"}),
            ),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["wait", scan_id]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Oops! Something went wrong"), "{context}");
}
