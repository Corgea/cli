//! End-to-end tests for `corgea list` repo-URL project resolution (COR-1577).
//! The stub route table lives in `common::Routes`.

mod common;

use common::{
    projects_empty, projects_match, scans_empty, scans_one, temp_git_repo, temp_plain_dir, Routes,
    CANON, REMOTE,
};
use std::path::Path;
use std::process::Output;

// --- stub bodies -----------------------------------------------------------

/// `/issues` returning one issue (status `ok`).
fn issues_one() -> String {
    r#"{"status":"ok","page":1,"total_pages":1,"total_issues":1,"issues":[{"id":"issue-abc","scan_id":"scan-123","status":"open","urgency":"high","created_at":"2026-01-01T00:00:00Z","classification":{"id":"CWE-89","name":"SQL Injection","description":null},"location":{"file":{"name":"app.py","language":"python","path":"src/app.py"},"line_number":42,"project":{"name":"bohappdev/dotnet-azure-web-tsb","branch":null,"git_sha":null}},"details":null,"auto_triage":{"false_positive_detection":{"status":"none","reasoning":null}},"auto_fix_suggestion":null}]}"#.to_string()
}

/// `/issues` exact-name miss (HTTP 200 `no_project_found`, mapped to 404).
fn issues_miss() -> String {
    r#"{"status":"no_project_found"}"#.to_string()
}

// --- harness ---------------------------------------------------------------

/// The three listing endpoints `list` reads.
fn routes(projects: String, scans: String, issues: String) -> Routes {
    Routes {
        projects: Some(projects),
        scans: Some(scans),
        issues: Some(issues),
        ..Default::default()
    }
}

fn spawn_stub(projects: String, scans: String, issues: String) -> String {
    common::spawn_resolution_stub(routes(projects, scans, issues))
}

fn run_list(args: &[&str], url: &str, cwd: &Path) -> Output {
    common::run_corgea("list", args, url, cwd)
}

// --- tests -----------------------------------------------------------------

#[test]
fn list_uses_canonical_name_from_repo() {
    let url = spawn_stub(projects_match(), scans_one(CANON), issues_one());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Project column shows the canonical org/repo, proving resolution, not the
    // dir basename, drove the listing.
    assert!(
        stdout.contains("bohappdev/dotnet-azure-web-tsb"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("scan-123"), "stdout: {stdout}");
}

#[test]
fn list_issues_shows_repo_resolved_issue() {
    let url = spawn_stub(projects_match(), scans_one(CANON), issues_one());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--issues"], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("issue-abc"), "stdout: {stdout}");
}

#[test]
fn list_repo_flag_resolves_from_flag_not_remote() {
    // Records every request target so we can prove the slug came from --repo.
    let (url, hits) = common::spawn_recording_resolution_stub(Routes {
        projects: Some(projects_match()),
        scans: Some(scans_one(CANON)),
        ..Default::default()
    });
    // Non-git dir: no remote, so a resolved slug can ONLY have come from --repo.
    let (_tmp, dir) = temp_plain_dir("unrelated-dir");
    let out = run_list(&["--repo", "bohappdev/dotnet-azure-web-tsb"], &url, &dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("bohappdev/dotnet-azure-web-tsb"),
        "stdout: {stdout}"
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/projects?repo_url=bohappdev%2Fdotnet-azure-web-tsb")),
        "expected a /projects hit carrying the flag slug; hits: {hits:?}"
    );
}

#[test]
fn list_miss_names_repo_no_empty_table() {
    let url = spawn_stub(projects_empty(), scans_empty(), issues_miss());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("repo 'bohappdev/dotnet-azure-web-tsb'"),
        "stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Scan ID"),
        "should not render a table; stdout: {stdout}"
    );
}

#[test]
fn list_confirmed_project_with_no_scans_exits_zero() {
    // A confirmed project that simply has no scans is a valid empty result —
    // failing it would break CI polling.
    let url = spawn_stub(projects_match(), scans_empty(), issues_miss());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("has no scans yet"), "stdout: {stdout}");
}

#[test]
fn list_no_remote_falls_back_to_cwd_name() {
    // Regression: non-git dir whose basename matches a project the scans stub
    // serves under that exact name still lists scans (CWD-name fallback).
    let url = spawn_stub(projects_empty(), scans_one("myproject"), issues_one());
    let (_tmp, dir) = temp_plain_dir("myproject");
    let out = run_list(&[], &url, &dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("myproject"), "stdout: {stdout}");
    assert!(stdout.contains("scan-123"), "stdout: {stdout}");
}

#[test]
fn list_project_name_override() {
    let url = spawn_stub(projects_empty(), scans_one("some/name"), issues_one());
    let (_tmp, dir) = temp_plain_dir("whatever");
    let out = run_list(&["--project-name", "some/name"], &url, &dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("some/name"), "stdout: {stdout}");
}

#[test]
fn list_project_name_and_repo_are_mutually_exclusive() {
    let (_tmp, dir) = temp_plain_dir("whatever");
    let (mut cmd, _home) = common::corgea_isolated();
    cmd.args(["list", "--project-name", "a", "--repo", "b"])
        .env("CORGEA_URL", "http://127.0.0.1:1")
        .env("CORGEA_TOKEN", "test-token")
        .current_dir(&dir);
    let out = cmd.output().expect("spawn corgea");
    // clap rejects conflicting args at parse time with a usage error, exit 2.
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn list_json_miss_is_valid_empty_envelope() {
    let url = spawn_stub(projects_empty(), scans_empty(), issues_miss());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--json"], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Envelope on stdout, miss on stderr, exit 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout not JSON ({e}): {stdout}"));
    assert_eq!(
        v["results"].as_array().map(|a| a.len()),
        Some(0),
        "results should be empty; stdout: {stdout}"
    );
    assert!(
        !stdout.contains("No Corgea project"),
        "no human prose on stdout; stdout: {stdout}"
    );
}

#[test]
fn list_issues_with_scan_id_skips_project_resolution() {
    // The scan-id issue route ignores the project, so no /projects call should
    // be made even from a real git repo where a remote IS present. (COR-1577)
    // `projects` stays unset: dialing it would 404 and show up in the hits.
    let routes = Routes {
        scan_issues: Some(
            r#"{"status":"ok","page":1,"total_pages":1,"total_issues":0,"issues":[]}"#.to_string(),
        ),
        ..Default::default()
    };
    let (url, hits) = common::spawn_recording_http_stub(move |path| {
        if path.contains("/check_blocking_rules") {
            (
                "200 OK",
                r#"{"block":false,"blocking_issues":[],"total_pages":1}"#.to_string(),
            )
        } else {
            routes.answer(path)
        }
    });
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--issues", "--scan-id", "scan-xyz"], &url, &repo);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/projects")),
        "no /projects resolution for --issues --scan-id; hits: {hits:?}"
    );
    assert!(
        hits.iter().any(|h| h.contains("/scan/scan-xyz/issues")),
        "expected the scan-id issue route; hits: {hits:?}"
    );
}

#[test]
fn list_resolves_from_subdirectory() {
    let (url, hits) = common::spawn_recording_resolution_stub(Routes {
        projects: Some(projects_match()),
        scans: Some(scans_one(CANON)),
        ..Default::default()
    });
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let subdir = repo.join("src");
    std::fs::create_dir(&subdir).expect("create subdir");
    let out = run_list(&[], &url, &subdir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Discovery walks up from src/ to the repo root, so the remote slug — not
    // the `src` basename — drives resolution: a /projects hit proves it.
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/projects?repo_url=bohappdev%2Fdotnet-azure-web-tsb")),
        "expected /projects resolution from the subdir; hits: {hits:?}"
    );
    assert!(
        stdout.contains("bohappdev/dotnet-azure-web-tsb"),
        "stdout: {stdout}"
    );
}

#[test]
fn list_issues_json_miss_keeps_stdout_clean() {
    let url = spawn_stub(projects_empty(), scans_empty(), issues_miss());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--issues", "--json"], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The --issues miss is a hard error via log::error! (stderr); stdout stays
    // clean so JSON consumers never see corrupt output.
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "stdout must be clean; stdout: {stdout}"
    );
    assert!(
        stderr.contains("No Corgea project found"),
        "stderr should name the miss; stderr: {stderr}"
    );
}
