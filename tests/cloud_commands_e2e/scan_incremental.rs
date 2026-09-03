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
use hyper::{Method, StatusCode};
use serde_json::{json, Value};

const PROJECT: &str = "cloud-e2e";
const BASELINE_SCAN: &str = "baseline-scan-123";

fn baseline_scan(sha: &str) -> Value {
    json!({
        "id": BASELINE_SCAN,
        "project": PROJECT,
        "repo": null,
        "branch": "main",
        "status": "complete",
        "engine": "corgea-blast",
        "created_at": "2026-07-30T12:00:00Z",
        "git_sha": sha,
        "worktree_dirty": false
    })
}

fn baseline_lookup(branch: &'static str, scans: Vec<Value>) -> ExpectedRequest {
    expected_request(
        "look up a baseline scan to diff against",
        move |request| assert_baseline_lookup_request(request, PROJECT, branch),
        json_response(scans_response(scans)),
    )
}

/// The lookups a fixture repo makes when no trunk branch has a baseline. It
/// records no origin/HEAD, so the candidates are `main` then `master`.
fn baseline_lookups_finding_nothing() -> Vec<ExpectedRequest> {
    vec![
        baseline_lookup("main", vec![]),
        baseline_lookup("master", vec![]),
    ]
}

/// One page of the baseline lookup, for the walk an old backend forces.
fn baseline_lookup_page(
    branch: &'static str,
    page: u16,
    total_pages: u32,
    scans: Vec<Value>,
) -> ExpectedRequest {
    expected_request(
        "look up a baseline scan to diff against",
        move |request| {
            assert_authenticated_request(request, Method::GET, "/api/v1/scans")?;
            assert_query(request, "project", PROJECT)?;
            assert_query(request, "branch", branch)?;
            assert_query(request, "page", &page.to_string())?;
            assert_query(request, "engine", "corgea-blast")
        },
        json_response(json!({
            "status": "ok",
            "page": page,
            "total_pages": total_pages,
            "scans": scans,
        })),
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
        baseline_lookup("main", vec![baseline_scan(&base_sha)]),
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
        stdout.contains("Incremental scan: 2 files changed since commit"),
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
    let mut plan = vec![verify_request()];
    plan.extend(baseline_lookups_finding_nothing());
    plan.extend([
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
    ]);
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
        stdout.contains("has no completed scan of a clean worktree on main or master"),
        "{context}"
    );
}

/// A backend predating the server-side filters returns scans of every kind, so
/// a page can hold nothing usable. The walk is what stops that project from
/// being permanently unable to find a baseline it has.
#[test]
fn a_baseline_on_a_later_page_is_still_found() {
    let project = git_project();
    let base_sha = project.sha.clone();
    let head_sha = second_commit(&project);

    let mut unusable = baseline_scan(&head_sha);
    unusable["worktree_dirty"] = json!(true);
    let expected_base = base_sha.clone();

    let mut plan = vec![
        verify_request(),
        baseline_lookup_page("main", 1, 2, vec![unusable]),
        baseline_lookup_page("main", 2, 2, vec![baseline_scan(&base_sha)]),
        start_upload(),
        expected_request(
            "upload BLAST archive with the diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_multipart_text_field(request, "incremental_base_sha", &expected_base)
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

    assert_eq!(output.status.code(), Some(0), "{context}");
}

/// A lookup that failed says so. Reporting it as "no earlier scan" tells someone
/// with years of scan history that they have none, and now that incremental is
/// the default, any network blip would say it.
#[test]
fn a_failed_lookup_is_not_reported_as_a_missing_baseline() {
    let project = git_project();
    second_commit(&project);

    let mut plan = vec![
        verify_request(),
        expected_request(
            "fail the baseline lookup",
            |request| assert_baseline_lookup_request(request, PROJECT, "main"),
            json_response_with_status(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": "boom"})),
        ),
        start_upload(),
        expected_request(
            "upload BLAST archive with no diff",
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
    assert!(stdout.contains("could not be looked up"), "{context}");
    assert!(
        !stdout.contains("no completed scan of a clean worktree"),
        "a lookup failure must not claim the project has no scan history\n{context}"
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

/// `--ignore-dirty-worktree` does not pretend the tree is clean: it moves the
/// far side of the diff to the working tree, so the edited file is named and
/// rescanned rather than keeping findings nothing analyzed.
#[test]
fn ignore_dirty_worktree_diffs_the_working_tree_instead_of_refusing() {
    let project = git_project();
    let base_sha = project.sha.clone();
    std::fs::write(project.path().join("main.py"), "print('uncommitted')\n")
        .expect("dirty the tree");

    let expected_base = base_sha.clone();
    let mut plan = vec![
        verify_request(),
        baseline_lookup("main", vec![baseline_scan(&base_sha)]),
        start_upload(),
        expected_request(
            "upload BLAST archive with a worktree diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                // Still reported dirty: the upload is not a snapshot of the
                // commit, and the scan must never become a baseline itself.
                assert_multipart_text_field(request, "dirty", "true")?;
                assert_multipart_text_field(request, "incremental_base_sha", &expected_base)?;
                assert_multipart_text_field(
                    request,
                    "incremental_changed_files",
                    r#"["main.py"]"#,
                )?;
                assert_multipart_text_field(request, "incremental_covers_worktree", "true")
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
        "--ignore-dirty-worktree",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(stdout.contains("and your uncommitted changes"), "{context}");
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
