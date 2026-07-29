//! End-to-end tests for `corgea wait` repo-URL project resolution (COR-1577).
//! The stub route table lives in `common::Routes`, whose `scan`/`scan_issues`
//! arms serve `check_scan_status` and `report_scan_status` respectively.

mod common;

use common::{
    projects_empty, projects_match, scans_empty, scans_one, temp_git_repo, temp_plain_dir, Routes,
    CANON, REMOTE,
};
use std::path::Path;
use std::process::Output;

// --- stub bodies -----------------------------------------------------------

/// `GET /api/v1/scan/{id}` returning a completed scan (`check_scan_status`
/// checks the lowercase `complete`).
fn scan_complete() -> String {
    r#"{"id":"scan-123","project":"bohappdev/dotnet-azure-web-tsb","repo":"https://github.com/bohappdev/dotnet-azure-web-tsb","branch":"main","status":"complete","engine":"blast","created_at":"2026-01-01T00:00:00Z"}"#.to_string()
}

/// `GET /api/v1/scan/{id}/issues` returning an empty page — enough for
/// `report_scan_status` to succeed and print the result link.
fn scan_issues_empty() -> String {
    r#"{"status":"ok","page":1,"total_pages":1,"total_issues":0,"issues":[]}"#.to_string()
}

// --- harness ---------------------------------------------------------------

/// The single-scan endpoints every `wait` run reads once it has a scan id.
fn scan_routes() -> Routes {
    Routes {
        scan: Some(scan_complete()),
        scan_issues: Some(scan_issues_empty()),
        ..Default::default()
    }
}

fn routes(projects: String, scans: String) -> Routes {
    Routes {
        projects: Some(projects),
        scans: Some(scans),
        ..scan_routes()
    }
}

fn spawn_stub(projects: String, scans: String) -> String {
    common::spawn_resolution_stub(routes(projects, scans))
}

fn run_wait(args: &[&str], url: &str, cwd: &Path) -> Output {
    common::run_corgea("wait", args, url, cwd)
}

// --- tests -----------------------------------------------------------------

#[test]
fn wait_uses_canonical_project_and_numeric_id_scan_url() {
    let url = spawn_stub(projects_match(), scans_one(CANON));
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_wait(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Numeric project id (7) from /projects, not the dir basename.
    assert!(
        stdout.contains("/project/7/?scan_id=scan-123"),
        "stdout: {stdout}"
    );
}

#[test]
fn wait_repo_flag_resolves_from_flag_not_remote() {
    // Records every request target so we can prove the slug came from --repo.
    let (url, hits) =
        common::spawn_recording_resolution_stub(routes(projects_match(), scans_one(CANON)));
    // Non-git dir: no remote, so a resolved slug can ONLY have come from --repo.
    let (_tmp, dir) = temp_plain_dir("unrelated-dir");
    let out = run_wait(&["--repo", "bohappdev/dotnet-azure-web-tsb"], &url, &dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("/project/7/?scan_id=scan-123"),
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
fn wait_miss_names_repo_no_bare_error() {
    let url = spawn_stub(projects_empty(), scans_empty());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_wait(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("repo 'bohappdev/dotnet-azure-web-tsb'"),
        "stderr should name the repo; stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Error querying scan list")
            && !stderr.contains("Error querying scan list"),
        "the bare error must be absent; stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn wait_project_name_override() {
    let url = spawn_stub(projects_empty(), scans_one("some/name"));
    let (_tmp, dir) = temp_plain_dir("whatever");
    let out = run_wait(&["--project-name", "some/name"], &url, &dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // No confirmed id, so the URL keeps the exact `--project-name` value.
    assert!(
        stdout.contains("/project/some/name?scan_id=scan-123"),
        "stdout: {stdout}"
    );
}

#[test]
fn wait_project_name_trailing_slash_is_trimmed() {
    // A slash-only or trailing-slash name would build `/project/foo//?scan_id=`.
    let url = spawn_stub(projects_empty(), scans_one("foo"));
    let (_tmp, dir) = temp_plain_dir("whatever");
    let out = run_wait(&["--project-name", "foo/"], &url, &dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("/project/foo?scan_id=scan-123"),
        "stdout: {stdout}"
    );
}

#[test]
fn wait_resolves_from_subdirectory() {
    let (url, hits) =
        common::spawn_recording_resolution_stub(routes(projects_match(), scans_one(CANON)));
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let subdir = repo.join("src");
    std::fs::create_dir(&subdir).expect("create subdir");
    let out = run_wait(&[], &url, &subdir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Discovery walks up from src/, so the remote — not the `src` basename —
    // drives resolution.
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/projects?repo_url=bohappdev%2Fdotnet-azure-web-tsb")),
        "expected /projects resolution from the subdir; hits: {hits:?}"
    );
    assert!(
        stdout.contains("/project/7/?scan_id=scan-123"),
        "stdout: {stdout}"
    );
}

#[test]
fn wait_with_scan_id_does_not_list_scans() {
    // `scans` stays unset — the assertion is that it is never dialed.
    let (url, hits) = common::spawn_recording_resolution_stub(Routes {
        projects: Some(projects_match()),
        ..scan_routes()
    });
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_wait(&["scan-123"], &url, &repo);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The listing is only read when no scan id was given.
    let hits = hits.lock().unwrap();
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/scans")),
        "no scan listing with --scan-id; hits: {hits:?}"
    );
}

#[test]
fn wait_project_id_flag_skips_resolution() {
    // A caller who already knows the id (CI passing it between steps) needs no
    // lookup at all: neither `projects` nor `scans` is served, and the id-form
    // URL still comes out. (PR #122 review)
    let (url, hits) = common::spawn_recording_resolution_stub(scan_routes());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_wait(&["scan-123", "--project-id", "42"], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("/project/42/?scan_id=scan-123"),
        "stdout: {stdout}"
    );
    let hits = hits.lock().unwrap();
    assert!(
        !hits
            .iter()
            .any(|h| h.starts_with("/api/v1/projects") || h.starts_with("/api/v1/scans")),
        "--project-id must resolve nothing; hits: {hits:?}"
    );
}

/// `corgea scan semgrep` with a fake `semgrep` on PATH: the post-scan wait gets
/// the project id straight from the upload response, so it must resolve nothing
/// — no `/projects`, no `/scans` — and still link the id-form URL.
#[cfg(unix)]
#[test]
fn scan_post_wait_uses_upload_project_id_without_resolving() {
    // Neither `projects` nor `scans` is served — the assertions are that
    // neither is dialed. The upload endpoints are this test's own.
    let routes = scan_routes();
    let (url, hits) = common::spawn_recording_http_stub(move |path| {
        if path.starts_with("/api/v1/code-upload") || path.starts_with("/api/v1/git-config-upload")
        {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        } else if path.starts_with("/api/v1/scan-upload") {
            (
                "200 OK",
                r#"{"status":"ok","sast_scan_id":"scan-123","project_id":42}"#.to_string(),
            )
        } else {
            routes.answer(path)
        }
    });
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    std::fs::write(repo.join("app.py"), "x = 1\n").expect("write source");
    let bin = repo.join("fakebin");
    std::fs::create_dir(&bin).expect("create fake bin dir");
    let report = r#"{"version":"1.0.0","errors":[],"results":[{"check_id":"rule","path":"app.py","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{"source":"https://semgrep.dev/r/rule"}}}]}"#;
    common::write_script(
        &bin,
        "semgrep",
        &format!("#!/bin/sh\nprintf '%s' '{report}'\n"),
    );

    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        .args(["scan", "semgrep"])
        .env("PATH", &bin)
        .env("CORGEA_URL", &url)
        .env("CORGEA_TOKEN", "test-token")
        // `running_in_ci()` is true under Actions, which sends `upload_scan`
        // down the GITHUB_REPOSITORY branch. Pin the non-CI path either way.
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .current_dir(&repo)
        .output()
        .expect("spawn corgea");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("/project/42/?scan_id=scan-123"),
        "expected the id-form scan URL; stdout: {stdout}"
    );
    let hits = hits.lock().unwrap();
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/projects")),
        "no /projects resolution after an upload that carried the id; hits: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/scans")),
        "no scan listing after an upload that carried the id; hits: {hits:?}"
    );
}

#[test]
fn wait_project_name_and_repo_are_mutually_exclusive() {
    let (_tmp, dir) = temp_plain_dir("whatever");
    let (mut cmd, _home) = common::corgea_isolated();
    cmd.args(["wait", "--project-name", "a", "--repo", "b"])
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
