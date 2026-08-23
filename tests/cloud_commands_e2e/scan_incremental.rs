//! Incremental scans, attempted by default on every `corgea scan blast`: find
//! the project's last clean scan, diff this commit against it locally, send the
//! changed-file list with the archive.
//!
//! The stub asserts the exact wire contract because those two fields are what
//! the server acts on: `incremental_base_sha` picks whose findings carry
//! forward, `incremental_changed_files` picks which files are excluded from
//! that and analyzed instead.
//!
//! Being the default, the ways it declines matter as much as the way it works,
//! so each is a case here: stay correct, and do not even look for a baseline
//! when it already cannot be used.

use crate::common::*;
use hyper::Method;
use serde_json::{json, Value};

const PROJECT: &str = "cloud-e2e";
const BASELINE_SCAN: &str = "baseline-scan-123";

fn baseline_scan(sha: &str) -> Value {
    json!({
        "id": BASELINE_SCAN,
        "project": PROJECT,
        "repo": null,
        "branch": "e2e-main",
        "status": "complete",
        "engine": "corgea-blast",
        "created_at": "2026-07-30T12:00:00Z",
        "git_sha": sha,
        "worktree_dirty": false
    })
}

fn baseline_lookup(scans: Vec<Value>) -> ExpectedRequest {
    expected_request(
        "look up a baseline scan to diff against",
        move |request| assert_baseline_lookup_request(request, PROJECT),
        json_response(scans_response(scans)),
    )
}

/// Everything after the archive upload, which incremental does not change.
fn scan_tail() -> Vec<ExpectedRequest> {
    let detail_path = "/api/v1/scan/blast-scan-123".to_string();
    let issue_path = "/api/v1/scan/blast-scan-123/issues".to_string();
    vec![
        expected_request(
            "read completed BLAST scan",
            move |request| assert_authenticated_request(request, Method::GET, &detail_path),
            json_response(scan_response("blast-scan-123", PROJECT, "complete")),
        ),
        expected_request(
            "read regular BLAST issues",
            move |request| {
                assert_authenticated_request(request, Method::GET, &issue_path)?;
                assert_query(request, "page", "1")?;
                assert_query(request, "page_size", "30")
            },
            json_response(empty_issue_page()),
        ),
    ]
}

fn start_upload() -> ExpectedRequest {
    expected_request(
        "start BLAST upload",
        |request| {
            assert_authenticated_request(request, Method::POST, "/api/v1/start-scan")?;
            assert_query(request, "scan_type", "blast")
        },
        json_response(json!({"transfer_id": "transfer-123"})),
    )
}

/// Adds a file and edits another, so the diff has more than one entry and a
/// file the baseline already contained.
fn second_commit(project: &GitProject) -> String {
    std::fs::write(project.path().join("helper.py"), "print('helper')\n").expect("write helper");
    std::fs::write(project.path().join("main.py"), "print('edited')\n").expect("edit main");
    run_git(project.path(), &["add", "."]);
    run_git(project.path(), &["commit", "-m", "second"]);
    String::from_utf8(run_git(project.path(), &["rev-parse", "HEAD"]).stdout)
        .expect("UTF-8 SHA")
        .trim()
        .to_string()
}

#[test]
fn the_upload_carries_the_baseline_commit_and_the_files_that_changed_since_it() {
    let project = git_project();
    let base_sha = project.sha.clone();
    let head_sha = second_commit(&project);

    let patch_sha = head_sha.clone();
    let expected_base = base_sha.clone();
    let mut plan = vec![
        verify_request(),
        baseline_lookup(vec![baseline_scan(&base_sha)]),
        start_upload(),
        expected_request(
            "upload BLAST archive with the diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_multipart_text_field(request, "sha", &patch_sha)?;
                assert_multipart_text_field(request, "dirty", "false")?;
                assert_multipart_text_field(request, "incremental_base_sha", &expected_base)?;
                // Both sides of the diff, sorted, as JSON — a path may contain a
                // comma, so the list is never a delimited string.
                assert_multipart_text_field(
                    request,
                    "incremental_changed_files",
                    r#"["helper.py","main.py"]"#,
                )
            },
            json_response(json!({"scan_id": "blast-scan-123", "project_id": 91})),
        ),
    ];
    plan.extend(scan_tail());

    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["scan", "blast", "--project-name", PROJECT]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(
        stdout.contains("Incremental scan: 2 file(s) changed since commit"),
        "{context}"
    );
}

/// No scan to diff against is a full scan, not an error. Every project's first
/// scan takes this path and must still produce a complete result.
#[test]
fn a_project_with_no_baseline_scan_uploads_without_a_diff() {
    let project = git_project();
    let head_sha = second_commit(&project);

    let patch_sha = head_sha.clone();
    let mut plan = vec![
        verify_request(),
        baseline_lookup(vec![]),
        start_upload(),
        expected_request(
            "upload BLAST archive with no diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_multipart_text_field(request, "sha", &patch_sha)?;
                // Neither field alone, nor at all: a base commit without a
                // list lets the server carry everything forward.
                assert_no_multipart_field(request, "incremental_base_sha")?;
                assert_no_multipart_field(request, "incremental_changed_files")
            },
            json_response(json!({"scan_id": "blast-scan-123", "project_id": 91})),
        ),
    ];
    plan.extend(scan_tail());

    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["scan", "blast", "--project-name", PROJECT]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(
        stdout.contains("Scanning every file: no earlier completed scan of a clean worktree"),
        "{context}"
    );
}

/// The opt-out is absolute: no baseline lookup, no fields, no message. Someone
/// reaching for it wants every file analyzed, usually because something outside
/// `corgea.yaml` changed that the server's baseline checks cannot see.
#[test]
fn disable_incremental_does_not_even_look_for_a_baseline() {
    let project = git_project();
    let head_sha = second_commit(&project);

    let patch_sha = head_sha.clone();
    let mut plan = vec![
        verify_request(),
        start_upload(),
        expected_request(
            "upload BLAST archive with no diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_multipart_text_field(request, "sha", &patch_sha)?;
                assert_multipart_text_field(request, "dirty", "false")?;
                assert_no_multipart_field(request, "incremental_base_sha")?;
                assert_no_multipart_field(request, "incremental_changed_files")
            },
            json_response(json!({"scan_id": "blast-scan-123", "project_id": 91})),
        ),
    ];
    plan.extend(scan_tail());

    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--disable-incremental",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(!stdout.contains("Scanning every file:"), "{context}");
    assert!(!stdout.contains("Incremental scan:"), "{context}");
}

/// `--target` already uploads a chosen subset. Carrying findings forward for
/// files the archive no longer holds would be wrong, so incremental is skipped
/// — silently, since "scanning every file" would be a lie here.
#[test]
fn a_narrowed_archive_skips_incremental_without_claiming_a_full_scan() {
    let project = git_project();
    second_commit(&project);

    let mut plan = vec![
        verify_request(),
        start_upload(),
        expected_request(
            "upload narrowed BLAST archive",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                // A partial archive is never an exact snapshot of the commit.
                assert_multipart_text_field(request, "dirty", "true")?;
                assert_no_multipart_field(request, "incremental_base_sha")?;
                assert_no_multipart_field(request, "incremental_changed_files")
            },
            json_response(json!({"scan_id": "blast-scan-123", "project_id": 91})),
        ),
    ];
    plan.extend(scan_tail());

    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--target",
        "main.py",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(!stdout.contains("Scanning every file:"), "{context}");
}

/// No git repository must not stall or fail: no commit to diff from, so skip
/// the lookup and scan everything.
#[test]
fn a_directory_that_is_not_a_git_repository_scans_everything() {
    let project = tempfile::TempDir::new().expect("create project");
    std::fs::write(project.path().join("main.py"), "print('hi')\n").expect("write source");

    let mut plan = vec![
        verify_request(),
        start_upload(),
        expected_request(
            "upload BLAST archive with no repo metadata",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_no_multipart_field(request, "incremental_base_sha")?;
                assert_no_multipart_field(request, "incremental_changed_files")
            },
            json_response(json!({"scan_id": "blast-scan-123", "project_id": 91})),
        ),
    ];
    plan.extend(scan_tail());

    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["scan", "blast", "--project-name", PROJECT]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(
        stdout.contains("Scanning every file: no git branch and commit to diff from"),
        "{context}"
    );
}

/// The server refuses a dirty tree too, and the refusal must come before the
/// baseline lookup: a commit-to-commit diff cannot see uncommitted edits, so no
/// baseline makes the list correct.
#[test]
fn a_dirty_worktree_skips_the_baseline_lookup_and_scans_everything() {
    let project = git_project();
    let head_sha = second_commit(&project);
    std::fs::write(project.path().join("main.py"), "print('uncommitted')\n")
        .expect("dirty the tree");

    let patch_sha = head_sha.clone();
    let mut plan = vec![
        verify_request(),
        start_upload(),
        expected_request(
            "upload BLAST archive with no diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_multipart_text_field(request, "sha", &patch_sha)?;
                assert_multipart_text_field(request, "dirty", "true")?;
                assert_no_multipart_field(request, "incremental_base_sha")?;
                assert_no_multipart_field(request, "incremental_changed_files")
            },
            json_response(json!({"scan_id": "blast-scan-123", "project_id": 91})),
        ),
    ];
    plan.extend(scan_tail());

    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["scan", "blast", "--project-name", PROJECT]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(
        stdout.contains("Scanning every file: this worktree has uncommitted changes"),
        "{context}"
    );
}
