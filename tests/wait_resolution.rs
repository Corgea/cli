//! End-to-end tests for `corgea wait` repo-URL project resolution (COR-1577).
//! The `/api/v1/scan/` arm serves both `GET /scan/{id}` (`check_scan_status`)
//! and `/scan/{id}/issues` (`report_scan_status`), branching on `/issues`.

mod common;

use common::{
    projects_empty, projects_match, scans_empty, scans_one, temp_git_repo, temp_plain_dir, Hits,
    CANON, NOT_FOUND_JSON, REMOTE,
};
use std::path::Path;
use std::process::Output;

// --- harness ---------------------------------------------------------------

/// `GET /api/v1/scan/{id}` returning a completed scan (`check_scan_status`
/// checks the lowercase `complete`); `/issues` under it returns an empty page,
/// enough for `report_scan_status` to succeed and print the result link.
fn spawn_stub(projects: String, scans: String) -> (String, Hits) {
    common::spawn_recording_http_stub(move |path| {
        if path.starts_with("/api/v1/verify") {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        } else if path.starts_with("/api/v1/projects?repo_url=") {
            ("200 OK", projects.clone())
        } else if path.starts_with("/api/v1/scans?") {
            ("200 OK", scans.clone())
        } else if path.starts_with("/api/v1/scan/") {
            if path.contains("/issues") {
                (
                    "200 OK",
                    r#"{"status":"ok","page":1,"total_pages":1,"total_issues":0,"issues":[]}"#
                        .to_string(),
                )
            } else {
                ("200 OK", r#"{"id":"scan-123","project":"bohappdev/dotnet-azure-web-tsb","repo":"https://github.com/bohappdev/dotnet-azure-web-tsb","branch":"main","status":"complete","engine":"blast","created_at":"2026-01-01T00:00:00Z"}"#.to_string())
            }
        } else {
            ("404 Not Found", NOT_FOUND_JSON.to_string())
        }
    })
}

fn run_wait(args: &[&str], url: &str, cwd: &Path) -> Output {
    common::run_corgea("wait", args, url, cwd)
}

// --- tests -----------------------------------------------------------------

#[test]
fn wait_uses_the_canonical_project_from_the_repo() {
    // The checkout is `build-123`; only resolution can produce the canonical
    // name, both in the /scans query and in the result link.
    let (url, hits) = spawn_stub(projects_match(), scans_one(CANON));
    let (_tmp, repo) = temp_git_repo("build-123", REMOTE);
    let out = run_wait(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The web route is `project/<id_or_name>/`, so the canonical name links.
    assert!(
        stdout.contains("/project/bohappdev/dotnet-azure-web-tsb?scan_id=scan-123"),
        "stdout: {stdout}"
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/scans?") && h.contains("project=bohappdev%2F")),
        "the canonical project must drive /scans; hits: {hits:?}"
    );
}

#[test]
fn wait_miss_names_the_repo_not_a_bare_error() {
    // Pre-COR-1577 this printed only "Error querying scan list".
    let (url, _hits) = spawn_stub(projects_empty(), scans_empty());
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
        stderr.contains(&format!("repo '{CANON}'")),
        "stderr should name the repo; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("Error querying scan list"),
        "the bare error must be absent; stderr: {stderr}"
    );
}

#[test]
fn wait_project_name_override_is_trimmed_before_the_query() {
    // The name goes into `?project=`, which the backend matches exactly, so a
    // trailing slash must be gone before the request — not only in the link.
    let (url, hits) = spawn_stub(projects_empty(), scans_one("foo"));
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
    let hits = hits.lock().unwrap();
    // `project` is the last query param, so `ends_with` also proves the value
    // is not the un-trimmed `foo%2F`.
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/scans?") && h.ends_with("project=foo")),
        "the scan listing must be queried for `foo`; hits: {hits:?}"
    );
}

#[test]
fn wait_with_scan_id_does_not_list_scans() {
    // `scans` is served but must never be dialed: the listing is only read
    // when no scan id was given.
    let (url, hits) = spawn_stub(projects_match(), scans_one(CANON));
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_wait(&["scan-123"], &url, &repo);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/scans")),
        "no scan listing with a scan id; hits: {hits:?}"
    );
}

#[test]
fn wait_project_id_flag_skips_resolution() {
    // A caller who already knows the id (CI passing it between steps) needs no
    // lookup at all: neither /projects nor /scans is dialed, and the id-form
    // URL still comes out.
    let (url, hits) = spawn_stub(projects_match(), scans_one(CANON));
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

#[test]
fn wait_project_id_requires_a_scan_id() {
    // Without a scan id the scan is still picked by the resolved project name,
    // so a lone --project-id would only relabel the link — pointing at a
    // different project than the scan. clap rejects it.
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_wait(&["--project-id", "42"], "http://127.0.0.1:1", &repo);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `corgea scan semgrep` with a fake `semgrep` on PATH: the post-scan wait gets
/// the project id straight from the upload response, so it must resolve nothing
/// — no `/projects`, no `/scans` — and still link the id-form URL.
#[cfg(unix)]
#[test]
fn scan_post_wait_uses_upload_project_id_without_resolving() {
    let (url, hits) = common::spawn_recording_http_stub(|path| {
        if path.starts_with("/api/v1/verify")
            || path.starts_with("/api/v1/code-upload")
            || path.starts_with("/api/v1/git-config-upload")
        {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        } else if path.starts_with("/api/v1/scan-upload") {
            (
                "200 OK",
                r#"{"status":"ok","sast_scan_id":"scan-123","project_id":42}"#.to_string(),
            )
        } else if path.starts_with("/api/v1/scan/") {
            if path.contains("/issues") {
                (
                    "200 OK",
                    r#"{"status":"ok","page":1,"total_pages":1,"total_issues":0,"issues":[]}"#
                        .to_string(),
                )
            } else {
                ("200 OK", r#"{"id":"scan-123","project":"p","repo":null,"branch":"main","status":"complete","engine":"blast","created_at":"2026-01-01T00:00:00Z"}"#.to_string())
            }
        } else {
            ("404 Not Found", NOT_FOUND_JSON.to_string())
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
        !hits
            .iter()
            .any(|h| h.starts_with("/api/v1/projects") || h.starts_with("/api/v1/scans")),
        "an upload that carried the id must resolve nothing; hits: {hits:?}"
    );
}
