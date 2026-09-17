//! Incremental scans, attempted by default on every `corgea scan blast`: find
//! the project's last clean scan, work out what changed since it, send the
//! changed-file list with the archive.
//!
//! The stub asserts the exact wire contract because those two fields are what
//! the server acts on: the baseline field picks whose findings carry forward,
//! `incremental_changed_files` picks which files are excluded from that and
//! analyzed instead.
//!
//! Two ways to reach the same list, so both are here. The baseline's stored
//! file checksums are preferred and name the baseline by scan id; `git diff`
//! is the fallback and names it by commit. The checksum cases are the ones
//! that used to be impossible: no `.git`, and a dirty tree without a flag.
//!
//! Being the default, the ways it declines matter as much as the way it works,
//! so each is a case here.

use crate::common::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use hyper::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;

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

/// A baseline scan advertising stored checksums of `files`, and the gzipped
/// manifest the download then has to serve.
///
/// The format is spelled out here rather than built with the CLI's own encoder,
/// so a change to how a manifest is written shows up as a failing test instead
/// of agreeing with itself.
fn baseline_scan_with_checksums(sha: &str, files: &[(&str, &str)]) -> (Value, Vec<u8>) {
    let mut canonical = String::from("corgea-file-manifest/1 sha256\n");
    let mut sorted = files.to_vec();
    sorted.sort();
    for (path, contents) in sorted {
        canonical.push_str(&format!(
            "{:x} {path}\n",
            Sha256::digest(contents.as_bytes())
        ));
    }
    let root = format!("{:x}", Sha256::digest(canonical.as_bytes()));

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(canonical.as_bytes()).expect("gzip");

    let mut scan = baseline_scan(sha);
    scan["file_manifest_root"] = json!(root);
    scan["file_manifest_version"] = json!("1");
    (scan, encoder.finish().expect("gzip"))
}

/// A baseline as it looks when the scan that produced it had no git either: no
/// branch, no commit, no dirty flag. Only its checksums make it usable, and a
/// project scanned this way has no other kind of history to offer.
fn without_git(mut scan: Value) -> Value {
    scan["branch"] = json!(null);
    scan["git_sha"] = json!(null);
    scan["worktree_dirty"] = json!(null);
    scan
}

fn checksum_download(body: Vec<u8>) -> ExpectedRequest {
    let path = format!("/api/v1/scan/{BASELINE_SCAN}/file-manifest");
    expected_request(
        "download the baseline scan's file checksums",
        move |request| assert_authenticated_request(request, Method::GET, &path),
        raw_response(StatusCode::OK, "application/gzip", body),
    )
}

fn baseline_lookup(branch: &'static str, scans: Vec<Value>) -> ExpectedRequest {
    expected_request(
        "look up a baseline scan to diff against",
        move |request| assert_baseline_lookup_request(request, PROJECT, Some(branch), false),
        json_response(scans_response(scans)),
    )
}

/// The single lookup a clone with no git makes. It cannot say which branch is
/// trunk, and the scans it is looking for name none either.
fn branchless_baseline_lookup(scans: Vec<Value>) -> ExpectedRequest {
    expected_request(
        "look up a baseline scan on any branch",
        move |request| assert_baseline_lookup_request(request, PROJECT, None, false),
        json_response(scans_response(scans)),
    )
}

/// The second walk, which does let the server drop what is not known-clean.
fn clean_baseline_lookup(branch: &'static str, scans: Vec<Value>) -> ExpectedRequest {
    expected_request(
        "look up a clean baseline scan to diff against",
        move |request| assert_baseline_lookup_request(request, PROJECT, Some(branch), true),
        json_response(scans_response(scans)),
    )
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

/// Checksums are preferred over `git diff` wherever the baseline has them, so
/// the upload names the scan rather than its commit. Both arrive at the same
/// list here; the cases below are the ones where only checksums can.
#[test]
fn the_baselines_stored_checksums_are_used_in_preference_to_a_git_diff() {
    let project = git_project();
    let base_sha = project.sha.clone();
    second_commit(&project);

    let (scan, manifest) = baseline_scan_with_checksums(&base_sha, &[("main.py", SOURCE_BODY)]);
    let mut plan = vec![
        verify_request(),
        baseline_lookup("main", vec![scan]),
        checksum_download(manifest),
        start_upload(),
        expected_request(
            "upload BLAST archive with the checksum diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                // The scan, not its commit: checksums are stored per scan, and
                // the upload that wrote them may have had no commit at all.
                assert_multipart_text_field(request, "incremental_base_scan_id", BASELINE_SCAN)?;
                assert_no_multipart_field(request, "incremental_base_sha")?;
                assert_multipart_text_field(
                    request,
                    "incremental_changed_files",
                    r#"["helper.py","main.py"]"#,
                )?;
                // Checksums are taken over the files on disk, so the list
                // covers uncommitted work by construction.
                assert_multipart_text_field(request, "incremental_covers_worktree", "true")
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
        stdout.contains("Incremental scan: 2 files changed since the last scan of main"),
        "{context}"
    );
}

/// The case this exists for. A pipeline that unpacks a tarball has no commit to
/// diff from and used to analyze every file on every run, forever; checksums
/// need no history, so it scans only what changed.
///
/// Every scan of such a project records no branch, no commit and no dirty flag,
/// so the lookup must ask for none of them: a baseline that has to be a clean
/// commit on trunk describes nothing this project has ever uploaded.
#[test]
fn a_directory_with_no_git_scans_incrementally_from_the_stored_checksums() {
    let project = tempfile::TempDir::new().expect("create project");
    std::fs::write(project.path().join("main.py"), "print('edited')\n").expect("write source");
    std::fs::write(project.path().join("helper.py"), "print('helper')\n").expect("write helper");

    let (scan, manifest) = baseline_scan_with_checksums("unused", &[("main.py", "print('hi')\n")]);
    let mut plan = vec![
        verify_request(),
        branchless_baseline_lookup(vec![without_git(scan)]),
        checksum_download(manifest),
        start_upload(),
        expected_request(
            "upload BLAST archive with the checksum diff and no commit",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_no_multipart_field(request, "sha")?;
                assert_multipart_text_field(request, "incremental_base_scan_id", BASELINE_SCAN)?;
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
        stdout.contains("Incremental scan: 2 files changed since the last scan of this project."),
        "{context}"
    );
}

/// A dirty tree needs no flag when checksums are available: they are taken over
/// the files as they sit on disk, so the uncommitted edit is named in the list
/// rather than missing from it.
#[test]
fn a_dirty_worktree_is_scanned_incrementally_from_the_stored_checksums() {
    let project = git_project();
    let base_sha = project.sha.clone();
    std::fs::write(project.path().join("main.py"), "print('uncommitted')\n")
        .expect("dirty the tree");

    let (scan, manifest) = baseline_scan_with_checksums(&base_sha, &[("main.py", SOURCE_BODY)]);
    let mut plan = vec![
        verify_request(),
        baseline_lookup("main", vec![scan]),
        checksum_download(manifest),
        start_upload(),
        expected_request(
            "upload dirty BLAST archive with the checksum diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                // Still reported dirty: the upload is not a snapshot of the
                // commit, and the scan must never become a baseline itself.
                assert_multipart_text_field(request, "dirty", "true")?;
                assert_multipart_text_field(request, "incremental_base_scan_id", BASELINE_SCAN)?;
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
    command.args(["scan", "blast", "--project-name", PROJECT]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(
        stdout.contains("Incremental scan: 1 file changed since the last scan of main"),
        "{context}"
    );
}

/// A manifest that arrives damaged is not a smaller tree. Reading it as one
/// would report every file it lost as deleted, dropping their findings; the
/// run falls back to the git diff instead.
#[test]
fn checksums_that_do_not_match_their_digest_fall_back_to_the_git_diff() {
    let project = git_project();
    let base_sha = project.sha.clone();
    second_commit(&project);

    let (scan, mut manifest) = baseline_scan_with_checksums(&base_sha, &[("main.py", SOURCE_BODY)]);
    manifest.truncate(manifest.len() / 2);

    let expected_base = base_sha.clone();
    let mut plan = vec![
        verify_request(),
        baseline_lookup("main", vec![scan]),
        checksum_download(manifest),
        start_upload(),
        expected_request(
            "upload BLAST archive with the git diff",
            move |request| {
                assert_authenticated_request(
                    request,
                    Method::PATCH,
                    "/api/v1/start-scan/transfer-123/",
                )?;
                assert_multipart_text_field(request, "incremental_base_sha", &expected_base)?;
                assert_no_multipart_field(request, "incremental_base_scan_id")?;
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

    assert_eq!(output.status.code(), Some(0), "{context}");
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
    plan.extend(baseline_lookups_finding_nothing(PROJECT));
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
        stdout.contains("has no completed scan on main or master that could be diffed against"),
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
            |request| assert_baseline_lookup_request(request, PROJECT, Some("main"), false),
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
        !stdout.contains("has no completed scan"),
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

/// A clean baseline behind a page of dirty scans is still found.
///
/// The first walk cannot ask the server for clean scans only, because that is
/// how a git-less scan reports itself and those are the ones worth having. The
/// cost is that dirty scans now reach the client, and a project with enough of
/// them could bury the clean scan it does have past the page budget. Every
/// project looks like that in the window before any of its scans has stored
/// checksums, so the second walk asks for what the first could not.
#[test]
fn a_clean_baseline_is_found_even_when_dirty_scans_come_back_first() {
    let project = git_project();
    let base_sha = project.sha.clone();
    let head_sha = second_commit(&project);

    let mut dirty = baseline_scan(&"d".repeat(40));
    dirty["worktree_dirty"] = json!(true);

    let expected_base = base_sha.clone();
    let mut plan = vec![
        verify_request(),
        baseline_lookup("main", vec![dirty]),
        baseline_lookup("master", vec![]),
        clean_baseline_lookup("main", vec![baseline_scan(&base_sha)]),
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
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert_ne!(head_sha, base_sha);
    assert!(
        stdout.contains("Incremental scan: 2 files changed since commit"),
        "{context}"
    );
}

/// No git repository and a baseline that stored no checksums leaves nothing to
/// compare either way, which must not stall or fail the scan.
#[test]
fn a_directory_that_is_not_a_git_repository_scans_everything() {
    let project = tempfile::TempDir::new().expect("create project");
    std::fs::write(project.path().join("main.py"), "print('hi')\n").expect("write source");

    let mut plan = vec![
        verify_request(),
        branchless_baseline_lookup(vec![without_git(baseline_scan("unused"))]),
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
                assert_no_multipart_field(request, "incremental_base_scan_id")?;
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
        stdout.contains(
            "Scanning every file: project 'cloud-e2e' has no completed scan of its whole \
             state that could be diffed against"
        ),
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

/// Without checksums to fall back on, a dirty tree still scans everything: a
/// commit-to-commit diff cannot see uncommitted edits, so their old findings
/// would be carried forward over content nothing analyzed.
#[test]
fn a_dirty_worktree_with_no_stored_checksums_scans_everything() {
    let project = git_project();
    let base_sha = project.sha.clone();
    let head_sha = second_commit(&project);
    std::fs::write(project.path().join("main.py"), "print('uncommitted')\n")
        .expect("dirty the tree");

    let patch_sha = head_sha.clone();
    let mut plan = vec![
        verify_request(),
        baseline_lookup("main", vec![baseline_scan(&base_sha)]),
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
