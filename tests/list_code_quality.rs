//! End-to-end tests for `corgea list --code-quality`.
//!
//! The code quality routes are named asymmetrically on the backend
//! (`/issues/code-quality` for a project, `/scan/{id}/issues/quality` for a
//! scan), so the request targets are asserted rather than assumed. Stubs route
//! on the request-target path PREFIX.

mod common;

use common::{projects_empty, projects_match, Hits, Routes, CANON, REMOTE};
use std::path::Path;
use std::process::Output;

// --- stub bodies -----------------------------------------------------------

/// A code quality page: the classification is a label (`Maintainability`),
/// not a CWE, and carries no description.
fn quality_one() -> String {
    r#"{"status":"ok","page":1,"total_pages":1,"total_issues":1,"issues":[{"id":"quality-abc","scan_id":"scan-123","status":"open","urgency":"medium","created_at":"2026-01-01T00:00:00Z","classification":{"id":"Maintainability","name":"Maintainability","description":null},"location":{"file":{"name":"app.py","language":"python","path":"src/app.py"},"line_number":20,"project":{"name":"bohappdev/dotnet-azure-web-tsb","branch":null,"git_sha":null}},"details":null,"auto_triage":{"false_positive_detection":{"status":"valid","reasoning":null}},"auto_fix_suggestion":null}]}"#.to_string()
}

/// `/issues` returning one security issue, so a test can tell the two listings
/// apart by which id was rendered.
fn issues_one() -> String {
    r#"{"status":"ok","page":1,"total_pages":1,"total_issues":1,"issues":[{"id":"issue-abc","scan_id":"scan-123","status":"open","urgency":"high","created_at":"2026-01-01T00:00:00Z","classification":{"id":"CWE-89","name":"SQL Injection","description":null},"location":{"file":{"name":"app.py","language":"python","path":"src/app.py"},"line_number":42,"project":{"name":"bohappdev/dotnet-azure-web-tsb","branch":null,"git_sha":null}},"details":null,"auto_triage":{"false_positive_detection":{"status":"none","reasoning":null}},"auto_fix_suggestion":null}]}"#.to_string()
}

// --- harness ---------------------------------------------------------------

/// Serves the project-scoped code quality route plus the security routes it
/// must not fall back to.
fn spawn_project_stub(projects: String) -> (String, Hits) {
    common::spawn_resolution_stub(Routes {
        projects: Some(projects),
        issues: Some(issues_one()),
        code_quality_issues: Some(quality_one()),
        ..Default::default()
    })
}

fn run_list(args: &[&str], url: &str, cwd: &Path) -> Output {
    common::run_corgea("list", args, url, cwd)
}

fn assert_exit(out: &Output, code: i32) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- tests -----------------------------------------------------------------

#[test]
fn code_quality_reads_the_code_quality_endpoint_not_the_security_one() {
    let (url, hits) = spawn_project_stub(projects_empty());
    let (_tmp, repo) = common::temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--code-quality"], &url, &repo);
    assert_exit(&out, 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("quality-abc"), "stdout: {stdout}");
    // The label stands in for the CWE column.
    assert!(stdout.contains("Maintainability"), "stdout: {stdout}");
    assert!(
        !stdout.contains("issue-abc"),
        "the security listing must not answer --code-quality; stdout: {stdout}"
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/issues/code-quality?")),
        "expected the code quality endpoint; hits: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/issues?")),
        "the security issue endpoint must not be dialed; hits: {hits:?}"
    );
}

#[test]
fn code_quality_alias_and_short_flag_reach_the_same_endpoint() {
    for flag in ["--quality", "-q"] {
        let (url, hits) = spawn_project_stub(projects_empty());
        let (_tmp, repo) = common::temp_git_repo("dotnet-azure-web-tsb", REMOTE);
        let out = run_list(&[flag], &url, &repo);
        assert_exit(&out, 0);
        let hits = hits.lock().unwrap();
        assert!(
            hits.iter()
                .any(|h| h.starts_with("/api/v1/issues/code-quality?")),
            "{flag} should list code quality; hits: {hits:?}"
        );
    }
}

#[test]
fn code_quality_scopes_to_the_project_resolved_from_the_repo() {
    // The checkout is `build-123`, so a canonical `project=` can only have come
    // from /projects resolution — the same path `--issues` takes. (COR-1577)
    let (url, hits) = spawn_project_stub(projects_match());
    let (_tmp, repo) = common::temp_git_repo("build-123", REMOTE);
    let out = run_list(&["--code-quality"], &url, &repo);
    assert_exit(&out, 0);
    let encoded = CANON.replace('/', "%2F");
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/issues/code-quality?")
                && h.contains(&format!("project={encoded}"))),
        "the canonical project must scope the code quality request; hits: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.contains("project=build-123")),
        "the checkout dir name must not be queried; hits: {hits:?}"
    );
}

#[test]
fn code_quality_percent_encodes_the_project_name() {
    // Interpolated raw, an `&` would split the query and address `foo` instead.
    let (url, hits) = spawn_project_stub(projects_empty());
    let (_tmp, dir) = common::temp_plain_dir("whatever");
    let out = run_list(
        &["--code-quality", "--project-name", "foo&bar#baz"],
        &url,
        &dir,
    );
    assert_exit(&out, 0);
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/issues/code-quality?")
                && h.contains("project=foo%26bar%23baz")),
        "the delimiters must be encoded, not split the query; hits: {hits:?}"
    );
}

#[test]
fn code_quality_with_a_scan_id_uses_the_scan_route_and_skips_blocking_rules() {
    // Blocking rules are a security concern: with `check_blocking_rules`
    // unstubbed (404), reaching it would exit 1 even though the code quality
    // fetch succeeded.
    let (url, hits) = common::spawn_resolution_stub(Routes {
        scan_issues: Some(issues_one()),
        scan_quality_issues: Some(quality_one()),
        ..Default::default()
    });
    let (_tmp, repo) = common::temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--code-quality", "--scan-id", "scan-123"], &url, &repo);
    assert_exit(&out, 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("quality-abc"), "stdout: {stdout}");
    assert!(
        !stdout.contains("Blocking"),
        "no blocking columns on a code quality table; stdout: {stdout}"
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/scan/scan-123/issues/quality")),
        "expected the scan-scoped code quality endpoint; hits: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.contains("check_blocking_rules")),
        "blocking rules must not be checked for code quality; hits: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/projects")),
        "no /projects resolution on the --scan-id route; hits: {hits:?}"
    );
}

#[test]
fn code_quality_reports_a_missing_scan_rather_than_a_parse_failure() {
    // These endpoints answer a missing scan with a bare HTTP 404, so the status
    // has to be read before the body or the miss surfaces as "Failed to parse".
    let (url, _hits) = common::spawn_resolution_stub(Routes::default());
    let (_tmp, repo) = common::temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--code-quality", "--scan-id", "nope"], &url, &repo);
    assert_exit(&out, 1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Scan with ID 'nope'"), "stderr: {stderr}");
    assert!(
        !stderr.contains("Failed to parse"),
        "a 404 must not read as a parse failure; stderr: {stderr}"
    );
}

#[test]
fn issue_kind_flags_are_mutually_exclusive() {
    for args in [
        ["--issues", "--code-quality"],
        ["--sca-issues", "--code-quality"],
        ["--issues", "--sca-issues"],
    ] {
        let (url, _hits) = common::spawn_resolution_stub(Routes::default());
        let (_tmp, dir) = common::temp_plain_dir("whatever");
        let out = run_list(&args, &url, &dir);
        assert_exit(&out, 1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("Cannot use more than one of"),
            "{args:?} should be rejected; stderr: {stderr}"
        );
    }
}
