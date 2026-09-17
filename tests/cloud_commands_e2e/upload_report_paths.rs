//! `corgea upload` when the report's paths are not relative to the directory
//! the command runs in.
//!
//! A scanner that ran on a build agent records that agent's paths, so the files
//! the report names are not where the report says they are. The CLI has to find
//! them anyway, and has to keep uploading them under the paths the report uses,
//! because the engine matches the report against those and never sees this
//! working tree.

use crate::common::*;
use hyper::Method;
use serde_json::json;
use tempfile::TempDir;

/// A project whose sources sit at `src/`, reported under a build-agent prefix.
fn build_agent_report_project() -> (TempDir, String) {
    let root = TempDir::new().expect("create report project");
    let source_dir = root.path().join("src");
    std::fs::create_dir(&source_dir).expect("create source directory");
    for name in ["main.py", "helper.py"] {
        std::fs::write(source_dir.join(name), SOURCE_BODY).expect("write source");
    }
    let report = r#"{"version":"semgrep.dev/v1","results":[{"path":"/builds/acme/repo/src/main.py"},{"path":"/builds/acme/repo/src/helper.py"}]}"#;
    let report_path = root.path().join("semgrep.json");
    std::fs::write(&report_path, report).expect("write report");
    (root, report.to_string())
}

fn expect_source_upload(report_path: &'static str) -> ExpectedRequest {
    expected_request(
        "upload referenced source",
        move |request| {
            assert_authenticated_request(request, Method::POST, "/api/v1/code-upload")?;
            assert_query(request, "path", report_path)?;
            assert_body_contains(request, SOURCE_BODY.as_bytes())
        },
        json_response(json!({"status": "ok"})),
    )
}

#[test]
fn upload_finds_sources_under_a_build_agent_prefix_and_keeps_the_reported_paths() {
    let (project, report) = build_agent_report_project();
    let api = ApiStub::start(vec![
        verify_request(),
        expect_source_upload("/builds/acme/repo/src/main.py"),
        expect_source_upload("/builds/acme/repo/src/helper.py"),
        expected_request(
            "upload report",
            move |request| {
                assert_authenticated_request(request, Method::POST, "/api/v1/scan-upload")?;
                assert_body_contains(request, report.as_bytes())
            },
            json_response(json!({
                "status": "ok",
                "sast_scan_id": "prefix-scan-123",
                "project_id": 7
            })),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "upload",
        project
            .path()
            .join("semgrep.json")
            .to_str()
            .expect("UTF-8 report path"),
        "--project-name",
        "upload-contract",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Dropping 'builds/acme/repo/'"),
        "{context}"
    );
}

/// A scanner that ran with the repo mounted at `/src` reports `/src/main.py`
/// while the file is at `src/main.py`. No prefix needs dropping -- the paths
/// already match once the leading slash is gone -- but they still have to be
/// read under the working tree rather than at the absolute path, which is
/// nothing on this machine.
#[test]
fn upload_finds_sources_named_by_a_rooted_path() {
    let project = TempDir::new().expect("create report project");
    let source_dir = project.path().join("src");
    std::fs::create_dir(&source_dir).expect("create source directory");
    for name in ["main.py", "helper.py"] {
        std::fs::write(source_dir.join(name), SOURCE_BODY).expect("write source");
    }
    let report = r#"{"version":"semgrep.dev/v1","results":[{"path":"/src/main.py"},{"path":"/src/helper.py"}]}"#;
    std::fs::write(project.path().join("semgrep.json"), report).expect("write report");

    let api = ApiStub::start(vec![
        verify_request(),
        expect_source_upload("/src/main.py"),
        expect_source_upload("/src/helper.py"),
        expected_request(
            "upload report",
            move |request| {
                assert_authenticated_request(request, Method::POST, "/api/v1/scan-upload")?;
                assert_body_contains(request, report.as_bytes())
            },
            json_response(json!({
                "status": "ok",
                "sast_scan_id": "rooted-scan-123",
                "project_id": 9
            })),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "upload",
        project
            .path()
            .join("semgrep.json")
            .to_str()
            .expect("UTF-8 report path"),
        "--project-name",
        "upload-contract",
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
}

/// Nothing resolves however much is dropped, so the report really was generated
/// against a different tree and the command still refuses to guess.
#[test]
fn upload_still_exits_one_when_no_prefix_resolves_the_report() {
    let project = TempDir::new().expect("create report project");
    std::fs::write(
        project.path().join("semgrep.json"),
        r#"{"version":"semgrep.dev/v1","results":[{"path":"/builds/acme/repo/src/main.py"}]}"#,
    )
    .expect("write report");
    let api = ApiStub::start(vec![verify_request()]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "upload",
        project
            .path()
            .join("semgrep.json")
            .to_str()
            .expect("UTF-8 report path"),
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Required file /builds/acme/repo/src/main.py"),
        "{context}"
    );
    assert!(
        stderr.contains("builds/acme/repo/src/main.py') not found"),
        "names where it looked, which is not the path in the report: {context}"
    );
}
