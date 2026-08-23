use crate::common::*;
use hyper::{Method, StatusCode};
use serde_json::json;
use tempfile::TempDir;

#[test]
fn scan_fail_on_malicious_sends_sha_and_list_renders_it() {
    let project = git_project();
    let scan_api = ApiStub::start(blast_plan(&project.sha));
    let (mut scan_command, _scan_home) = cloud_command(&scan_api, project.path());
    scan_command.args([
        "scan",
        "blast",
        "--fail-on",
        "malicious",
        "--project-name",
        "cloud-e2e",
    ]);

    let scan_output = run_with_timeout(scan_command, &scan_api);
    let scan_transcript = scan_api.assert_finished();
    let scan_context = output_context(&scan_output, &scan_transcript);
    assert_eq!(scan_output.status.code(), Some(1), "{scan_context}");
    let scan_stdout = String::from_utf8_lossy(&scan_output.stdout);
    assert!(
        scan_stdout.contains("matched --fail-on malicious"),
        "{scan_context}"
    );
    assert!(
        !scan_stdout.contains("Working tree has uncommitted changes"),
        "clean tree must not print dirty notice\n{scan_context}"
    );

    let list_response_sha = project.sha.clone();
    let list_api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "resolve Git project",
            |request| {
                assert_authenticated_request(request, Method::GET, "/api/v1/projects")?;
                assert_query(request, "repo_url", "corgea/cloud-e2e")?;
                assert_query(request, "page", "1")?;
                assert_query(request, "page_size", "50")
            },
            json_response(json!({
                "status": "ok",
                "projects": [{
                    "name": "cloud-e2e",
                    "repo_url": "https://github.com/corgea/cloud-e2e.git"
                }]
            })),
        ),
        expected_request(
            "list scans for Git project",
            move |request| assert_scan_list_request(request, "cloud-e2e"),
            json_response(scans_response(vec![json!({
                "id": "blast-scan-123",
                "project": "cloud-e2e",
                "repo": "https://github.com/corgea/cloud-e2e.git",
                "branch": "e2e-main",
                "status": "complete",
                "engine": "blast",
                "created_at": "2026-07-30T12:00:00Z",
                "git_sha": list_response_sha
            })])),
        ),
    ]);
    let (mut list_command, _list_home) = cloud_command(&list_api, project.path());
    list_command.arg("list");

    let list_output = run_with_timeout(list_command, &list_api);
    let list_transcript = list_api.assert_finished();
    let list_context = output_context(&list_output, &list_transcript);
    assert_eq!(list_output.status.code(), Some(0), "{list_context}");
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_stdout.contains(&project.sha[..8]), "{list_context}");
}

#[test]
fn scan_dirty_worktree_sends_dirty_true_and_prints_notice() {
    let project = git_project();
    std::fs::write(project.path().join("main.py"), "print('dirty')\n")
        .expect("modify tracked file");
    let short_sha = &project.sha[..7];
    let scan_api = ApiStub::start(blast_upload_plan(&project.sha, true, false));
    let (mut scan_command, _scan_home) = cloud_command(&scan_api, project.path());
    scan_command.args(["scan", "blast", "--project-name", "cloud-e2e"]);

    let scan_output = run_with_timeout(scan_command, &scan_api);
    let scan_transcript = scan_api.assert_finished();
    let scan_context = output_context(&scan_output, &scan_transcript);
    assert_eq!(scan_output.status.code(), Some(0), "{scan_context}");
    let scan_stdout = String::from_utf8_lossy(&scan_output.stdout);
    assert!(
        scan_stdout.contains(&format!(
            "Working tree has uncommitted changes - scanning your local files, not commit {short_sha}."
        )),
        "{scan_context}"
    );
}

/// A worktree `git status` calls clean is scanned as clean, whatever libgit2
/// makes of it. A clean filter (how git-lfs and similar tools store a file) is
/// one way a checkout gets there: the worktree bytes differ from the stored
/// blob by design, and libgit2 runs no filters, so it reads every such file as
/// modified.
#[cfg(unix)]
#[test]
fn scan_clean_by_git_status_sends_dirty_false_without_worktree_notice() {
    let project = git_project();
    run_git(
        project.path(),
        &["config", "filter.upper.clean", "tr a-z A-Z"],
    );
    run_git(project.path(), &["config", "filter.upper.smudge", "cat"]);
    std::fs::write(
        project.path().join(".gitattributes"),
        "*.txt filter=upper\n",
    )
    .expect("write attributes");
    std::fs::write(project.path().join("payload.txt"), "lowercase\n").expect("write payload");
    run_git(project.path(), &["add", ".gitattributes", "payload.txt"]);
    run_git(project.path(), &["commit", "-m", "filtered"]);
    // A checkout restored from a CI cache carries stale timestamps, so the
    // index's stat cache stops answering and the content is compared instead.
    assert!(
        std::process::Command::new("touch")
            .args(["-t", "203001010000"])
            .arg(project.path().join("payload.txt"))
            .status()
            .expect("run touch")
            .success(),
        "touch failed"
    );
    let status = run_git(project.path(), &["status", "--porcelain"]);
    assert!(
        status.stdout.is_empty(),
        "fixture must be clean to git: {}",
        String::from_utf8_lossy(&status.stdout)
    );
    let sha = String::from_utf8(run_git(project.path(), &["rev-parse", "HEAD"]).stdout)
        .expect("UTF-8 Git SHA")
        .trim()
        .to_string();

    let scan_api = ApiStub::start(blast_upload_plan(&sha, false, false));
    let (mut scan_command, _scan_home) = cloud_command(&scan_api, project.path());
    scan_command.args(["scan", "blast", "--project-name", "cloud-e2e"]);

    let scan_output = run_with_timeout(scan_command, &scan_api);
    let scan_transcript = scan_api.assert_finished();
    let scan_context = output_context(&scan_output, &scan_transcript);
    assert_eq!(scan_output.status.code(), Some(0), "{scan_context}");
    let scan_stdout = String::from_utf8_lossy(&scan_output.stdout);
    assert!(
        !scan_stdout.contains("Working tree has uncommitted changes"),
        "a tree git status calls clean must not print the dirty notice\n{scan_context}"
    );
}

#[test]
fn scan_clean_target_upload_sends_dirty_true_without_worktree_notice() {
    let project = git_project();
    std::fs::write(project.path().join("other.py"), "print('other')\n").expect("write other");
    run_git(project.path(), &["add", "other.py"]);
    run_git(project.path(), &["commit", "-m", "add other"]);
    let sha = String::from_utf8(run_git(project.path(), &["rev-parse", "HEAD"]).stdout)
        .expect("UTF-8 SHA")
        .trim()
        .to_string();

    let scan_api = ApiStub::start(blast_upload_plan(&sha, true, false));
    let (mut scan_command, _scan_home) = cloud_command(&scan_api, project.path());
    scan_command.args([
        "scan",
        "blast",
        "--target",
        "main.py",
        "--project-name",
        "cloud-e2e",
    ]);

    let scan_output = run_with_timeout(scan_command, &scan_api);
    let scan_context_early = output_context(&scan_output, &scan_api.transcript());
    assert_eq!(scan_output.status.code(), Some(0), "{scan_context_early}");
    let scan_transcript = scan_api.assert_finished();
    let scan_context = output_context(&scan_output, &scan_transcript);
    let scan_stdout = String::from_utf8_lossy(&scan_output.stdout);
    assert!(
        !scan_stdout.contains("Working tree has uncommitted changes"),
        "clean partial target must not print dirty worktree notice\n{scan_context}"
    );
}

#[test]
fn scan_clean_exclude_upload_sends_dirty_true_without_worktree_notice() {
    let project = git_project();
    std::fs::write(project.path().join("other.py"), "print('other')\n").expect("write other");
    run_git(project.path(), &["add", "other.py"]);
    run_git(project.path(), &["commit", "-m", "add other"]);
    let sha = String::from_utf8(run_git(project.path(), &["rev-parse", "HEAD"]).stdout)
        .expect("UTF-8 SHA")
        .trim()
        .to_string();

    let scan_api = ApiStub::start(blast_upload_plan(&sha, true, false));
    let (mut scan_command, _scan_home) = cloud_command(&scan_api, project.path());
    scan_command.args([
        "scan",
        "blast",
        "--exclude",
        "other.py",
        "--project-name",
        "cloud-e2e",
    ]);

    let scan_output = run_with_timeout(scan_command, &scan_api);
    let scan_context_early = output_context(&scan_output, &scan_api.transcript());
    assert_eq!(scan_output.status.code(), Some(0), "{scan_context_early}");
    let scan_transcript = scan_api.assert_finished();
    let scan_context = output_context(&scan_output, &scan_transcript);
    let scan_stdout = String::from_utf8_lossy(&scan_output.stdout);
    assert!(
        !scan_stdout.contains("Working tree has uncommitted changes"),
        "clean exclude scan must not print dirty worktree notice\n{scan_context}"
    );
}

#[test]
fn list_json_returns_filtered_scan_contract() {
    let project = TempDir::new().expect("create list project");
    let local_project = temp_project_name(project.path());
    let response_project = local_project.clone();
    let query_project = local_project.clone();
    let api = ApiStub::start(vec![
        verify_request(),
        expected_request(
            "list filtered scans as JSON",
            move |request| assert_scan_list_request(request, &query_project),
            json_response(json!({
                "status": "ok",
                "page": 1,
                "total_pages": 2,
                "scans": [{
                    "id": "list-scan-123",
                    "project": response_project,
                    "repo": "https://github.com/corgea/list-contract.git",
                    "branch": "main",
                    "status": "complete",
                    "engine": "blast",
                    "created_at": "2026-07-30T12:00:00Z",
                    "git_sha": "0123456789abcdef0123456789abcdef01234567"
                }]
            })),
        ),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["list", "--json"]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(0), "{context}");
    let body = parse_output_json(&output, &transcript);
    assert_eq!(body["page"], 1, "{context}");
    assert_eq!(body["total_pages"], 2, "{context}");
    let results = body["results"].as_array().expect("list JSON results");
    assert_eq!(results.len(), 1, "{context}");
    assert_eq!(results[0]["id"], "list-scan-123", "{context}");
    assert_eq!(results[0]["project"], local_project, "{context}");
    assert_eq!(results[0]["status"], "complete", "{context}");
    assert_eq!(
        results[0]["git_sha"], "0123456789abcdef0123456789abcdef01234567",
        "{context}"
    );
}

#[test]
fn list_exits_one_on_server_error() {
    let project = TempDir::new().expect("create list project");
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
    command.arg("list");

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    assert_eq!(output.status.code(), Some(1), "{context}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unable to fetch scans"), "{context}");
}
