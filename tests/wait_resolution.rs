//! End-to-end tests for `corgea wait` repo-URL project resolution (COR-1577).
//!
//! Mirrors `tests/list_resolution.rs`: each test runs the real binary against a
//! one-response-per-connection HTTP stub (`common::spawn_http_stub`) and, where
//! a git remote matters, a temp git repo built with `git2` whose directory
//! basename DIFFERS from the stored canonical project name (the Bank of Hope
//! case: dir `dotnet-azure-web-tsb` vs project `bohappdev/dotnet-azure-web-tsb`).
//!
//! Routing matches on the request-target PATH PREFIX with `starts_with`: the
//! `/projects` request carries a percent-encoded query string
//! (`?repo_url=bohappdev%2Fdotnet-azure-web-tsb`), so the full target is not a
//! stable key. `verify_token_and_exit_when_fail` calls `GET /api/v1/verify`
//! first, so every stub serves it. The `/api/v1/scan/` arm serves BOTH
//! `GET /api/v1/scan/{id}` (so `check_scan_status` succeeds) and
//! `/api/v1/scan/{id}/issues?…` (so `report_scan_status` succeeds) — branching
//! on `contains("/issues")`.

mod common;

use common::{
    projects_empty, projects_match, scans_empty, scans_one, temp_git_repo, temp_plain_dir, CANON,
    REMOTE,
};
use std::path::Path;
use std::process::Output;

// --- stub bodies -----------------------------------------------------------

/// `GET /api/v1/scan/{id}` returning a single completed scan (consumed by
/// `check_scan_status`/`get_scan`, which check the lowercase `complete`).
fn scan_complete() -> String {
    r#"{"id":"scan-123","project":"bohappdev/dotnet-azure-web-tsb","repo":"https://github.com/bohappdev/dotnet-azure-web-tsb","branch":"main","status":"complete","engine":"blast","created_at":"2026-01-01T00:00:00Z"}"#.to_string()
}

/// `GET /api/v1/scan/{id}/issues` returning an empty page (one round-trip:
/// `total_pages` 1). `report_scan_status` groups by urgency and succeeds with
/// no issues — enough to print the result link.
fn scan_issues_empty() -> String {
    r#"{"status":"ok","page":1,"total_pages":1,"total_issues":0,"issues":[]}"#.to_string()
}

// --- harness ---------------------------------------------------------------

/// Stub serving verify + projects + scans + the single-scan/scan-issues
/// endpoints, keyed on path prefix.
fn spawn_stub(projects: String, scans: String) -> String {
    common::spawn_http_stub(move |path| {
        if path.starts_with("/api/v1/verify") {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        } else if path.starts_with("/api/v1/projects?repo_url=") {
            ("200 OK", projects.clone())
        } else if path.starts_with("/api/v1/scans?") {
            ("200 OK", scans.clone())
        } else if path.starts_with("/api/v1/scan/") {
            if path.contains("/issues") {
                ("200 OK", scan_issues_empty())
            } else {
                ("200 OK", scan_complete())
            }
        } else {
            ("404 Not Found", r#"{"message":"not found"}"#.to_string())
        }
    })
}

/// Run `corgea wait <args...>` against `url` from `cwd`, isolated from the host
/// (temp HOME). `CORGEA_URL`/`CORGEA_TOKEN` are layered back on after
/// `corgea_isolated` strips them.
fn run_wait(args: &[&str], url: &str, cwd: &Path) -> Output {
    let (mut cmd, _home) = common::corgea_isolated();
    cmd.arg("wait");
    cmd.args(args);
    cmd.env("CORGEA_URL", url)
        .env("CORGEA_TOKEN", "test-token")
        .current_dir(cwd);
    cmd.output().expect("spawn corgea")
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
    // The scan URL uses the numeric project id (7) returned by /projects,
    // proving `resolved.project_id` flows through — not the dir basename.
    assert!(
        stdout.contains("/project/7/?scan_id=scan-123"),
        "stdout: {stdout}"
    );
}

#[test]
fn wait_repo_flag_resolves_from_flag_not_remote() {
    use std::sync::{Arc, Mutex};
    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let hits_c = hits.clone();
    // Records every request target so we can prove the slug came from --repo.
    let url = common::spawn_http_stub(move |path| {
        hits_c.lock().unwrap().push(path.to_string());
        if path.starts_with("/api/v1/verify") {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        } else if path.starts_with("/api/v1/projects?repo_url=") {
            ("200 OK", projects_match())
        } else if path.starts_with("/api/v1/scans?") {
            ("200 OK", scans_one(CANON))
        } else if path.starts_with("/api/v1/scan/") {
            if path.contains("/issues") {
                ("200 OK", scan_issues_empty())
            } else {
                ("200 OK", scan_complete())
            }
        } else {
            ("404 Not Found", r#"{"message":"not found"}"#.to_string())
        }
    });
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
    // Clear, actionable miss naming the repo the resolver tried.
    assert!(
        stderr.contains("repo 'bohappdev/dotnet-azure-web-tsb'"),
        "stderr should name the repo; stderr: {stderr}"
    );
    // The bare cryptic error is gone for good.
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
    // Override skips resolution: no confirmed project id, so the scan URL falls
    // back to the name form keyed on the exact `--project-name` value.
    assert!(
        stdout.contains("/project/some/name?scan_id=scan-123"),
        "stdout: {stdout}"
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
