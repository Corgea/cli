//! `--skip-if-commit-scanned-recently`: the CLI reuses a recent scan of the
//! current commit instead of starting a duplicate one, and the rest of the
//! command — results, blocking-rule gate, exit code — runs against that scan.
//!
//! The stub asserts the exact request sequence, so "no new scan was started"
//! is proven by the absence of the upload calls rather than by the output.

use crate::common::*;
use chrono::{Duration, Utc};
use hyper::Method;
use serde_json::{json, Value};
use tempfile::TempDir;

const PRIOR_SCAN: &str = "prior-scan-123";
const PROJECT: &str = "cloud-e2e";

fn ago(hours: i64) -> String {
    (Utc::now() - Duration::hours(hours)).to_rfc3339()
}

fn prior_scan(sha: &str, created_at: &str) -> Value {
    json!({
        "id": PRIOR_SCAN,
        "project": PROJECT,
        "repo": null,
        "branch": "e2e-main",
        "status": "complete",
        "engine": "corgea-blast",
        "created_at": created_at,
        "git_sha": sha,
        "worktree_dirty": false
    })
}

fn commit_lookup(sha: &str, scans: Vec<Value>) -> ExpectedRequest {
    let sha = sha.to_string();
    expected_request(
        "look up prior scans of the commit",
        move |request| {
            assert_authenticated_request(request, Method::GET, "/api/v1/scans")?;
            assert_query(request, "project", PROJECT)?;
            assert_query(request, "sha", &sha)
        },
        json_response(scans_response(scans)),
    )
}

fn reused_scan_issues() -> ExpectedRequest {
    let path = format!("/api/v1/scan/{PRIOR_SCAN}/issues");
    expected_request(
        "read the reused scan's issues",
        move |request| assert_authenticated_request(request, Method::GET, &path),
        json_response(regular_issue_page(PRIOR_SCAN, PROJECT)),
    )
}

fn reused_scan_blocking_rules(block: bool) -> ExpectedRequest {
    let path = format!("/api/v1/scan/{PRIOR_SCAN}/check_blocking_rules");
    let body = json!({
        "block": block,
        "blocking_issues": if block {
            json!([{"id": "issue-cr", "triggered_by_rules": ["1"], "triggered_by_slugs": ["criticals"]}])
        } else {
            json!([])
        },
        "total_pages": 1,
        "status": "complete"
    });
    expected_request(
        "evaluate blocking rules against the reused scan",
        move |request| {
            assert_authenticated_request(request, Method::GET, &path)?;
            assert_query(request, "block_on", "criticals")
        },
        json_response(body),
    )
}

fn reused_scan_sarif_report() -> ExpectedRequest {
    let path = format!("/api/v1/scan/{PRIOR_SCAN}/report");
    expected_request(
        "generate the SARIF report from the reused scan",
        move |request| {
            assert_authenticated_request(request, Method::GET, &path)?;
            assert_query(request, "format", "sarif")
        },
        json_response(json!({"version": "2.1.0", "runs": []})),
    )
}

/// The whole point for CI: the reused scan still decides the exit code, so a
/// re-run of a commit that was blocked stays blocked without scanning again —
/// and, as for a fresh scan, the report is written before the gate exits.
#[test]
fn skipped_scan_still_fails_the_build_on_the_prior_scans_blocking_rules() {
    let project = git_project();
    let out_dir = TempDir::new().expect("create output directory");
    let out_file = out_dir.path().join("results.sarif");
    let api = ApiStub::start(vec![
        verify_request(),
        commit_lookup(&project.sha, vec![prior_scan(&project.sha, &ago(3))]),
        reused_scan_issues(),
        reused_scan_sarif_report(),
        reused_scan_blocking_rules(true),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--block-on",
        "criticals",
        "--out-format",
        "sarif",
        "--out-file",
        out_file.to_str().expect("UTF-8 report path"),
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{context}");
    assert!(stdout.contains("Skipping scan"), "{context}");
    assert!(stdout.contains("CORGEA_SCAN_SKIPPED=true"), "{context}");
    assert!(
        stdout.contains(&format!("CORGEA_SCAN_ID={PRIOR_SCAN}")),
        "{context}"
    );
    assert!(
        stdout.contains("violated the blocking rule(s)"),
        "{context}"
    );
    // The upload never happened; the stub would have failed on an extra
    // request, and the banner is the user-visible half of the same claim.
    assert!(!stdout.contains("Scanning with BLAST"), "{context}");
    let report = std::fs::read_to_string(&out_file)
        .unwrap_or_else(|error| panic!("report should exist despite the gate: {error}\n{context}"));
    assert!(report.contains("2.1.0"), "{context}");
}

/// A clean run of a skipped scan reports the prior findings and exits 0.
#[test]
fn skipped_scan_reports_the_prior_findings() {
    let project = git_project();
    let api = ApiStub::start(vec![
        verify_request(),
        commit_lookup(&project.sha, vec![prior_scan(&project.sha, &ago(3))]),
        reused_scan_issues(),
        reused_scan_blocking_rules(false),
    ]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--block-on",
        "criticals",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert_issue_summary(&stdout, &context);
    assert!(
        stdout.contains("No issues violated the blocking rule(s)"),
        "{context}"
    );
}

/// Outside the window the flag changes nothing: the commit is scanned again,
/// because the advisories it is scanned against have moved on.
#[test]
fn a_scan_older_than_the_window_still_triggers_a_new_scan() {
    let project = git_project();
    let mut plan = blast_upload_plan(&project.sha, false, false);
    plan.insert(
        1,
        commit_lookup(&project.sha, vec![prior_scan(&project.sha, &ago(30))]),
    );
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(stdout.contains("CORGEA_SCAN_SKIPPED=false"), "{context}");
    assert!(stdout.contains("running a new scan"), "{context}");
    assert!(stdout.contains("Scanning with BLAST"), "{context}");
}

/// `--scanned-within` is what makes a scan stale: the same 3h-old scan that
/// the default window reuses is too old for a 1h window.
#[test]
fn a_shorter_window_rejects_a_scan_the_default_would_reuse() {
    let project = git_project();
    let mut plan = blast_upload_plan(&project.sha, false, false);
    plan.insert(
        1,
        commit_lookup(&project.sha, vec![prior_scan(&project.sha, &ago(3))]),
    );
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--scanned-within",
        "1h",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(stdout.contains("in the last 1h"), "{context}");
    assert!(stdout.contains("CORGEA_SCAN_SKIPPED=false"), "{context}");
}

/// Uncommitted changes mean the commit does not describe what would be
/// scanned, so there is nothing a prior scan of it could stand in for — the
/// lookup is not even attempted.
#[test]
fn a_dirty_worktree_scans_instead_of_reusing_the_commits_scan() {
    let project = git_project();
    std::fs::write(project.path().join("main.py"), "print('dirty')\n")
        .expect("modify tracked file");
    let api = ApiStub::start(blast_upload_plan(&project.sha, true, false));
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(
        stdout.contains("does not describe what would be scanned"),
        "{context}"
    );
    assert!(stdout.contains("CORGEA_SCAN_SKIPPED=false"), "{context}");
}

/// Without a commit the flag has no question to answer, and quietly scanning
/// would hide that the pipeline is not getting the behavior it asked for.
#[test]
fn no_resolvable_commit_fails_before_anything_is_uploaded() {
    let project = TempDir::new().expect("create non-git project");
    std::fs::write(project.path().join("main.py"), "print('hi')\n").expect("write source");
    let api = ApiStub::start(vec![verify_request()]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{context}");
    assert!(
        stderr.contains("no git commit could be resolved"),
        "{context}"
    );
}

#[test]
fn an_unreadable_window_is_rejected_before_the_scan_starts() {
    let project = git_project();
    let api = ApiStub::start(vec![verify_request()]);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--scanned-within",
        "yesterday",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{context}");
    assert!(
        stderr.contains("Invalid --scanned-within value 'yesterday'"),
        "{context}"
    );
}

/// The window is meaningless on its own — a pipeline that sets it and forgets
/// the skip flag would silently scan every time.
#[test]
fn the_window_cannot_be_set_without_the_skip_flag() {
    let api = ApiStub::start(Vec::new());
    let project = git_project();
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args(["scan", "blast", "--scanned-within", "1h"]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{context}");
    assert!(
        stderr.contains("--skip-if-commit-scanned-recently"),
        "{context}"
    );
}

/// A backend that predates the `sha` filter answers with the project's scans
/// at every commit; acting on that would skip this commit's scan because a
/// different commit was scanned recently.
#[test]
fn a_scan_of_another_commit_is_never_reused() {
    let project = git_project();
    let other_commit = "ffffffffffffffffffffffffffffffffffffffff";
    let mut plan = blast_upload_plan(&project.sha, false, false);
    plan.insert(
        1,
        commit_lookup(&project.sha, vec![prior_scan(other_commit, &ago(1))]),
    );
    let api = ApiStub::start(plan);
    let (mut command, _home) = cloud_command(&api, project.path());
    command.args([
        "scan",
        "blast",
        "--skip-if-commit-scanned-recently",
        "--project-name",
        PROJECT,
    ]);

    let output = run_with_timeout(command, &api);
    let transcript = api.assert_finished();
    let context = output_context(&output, &transcript);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{context}");
    assert!(stdout.contains("CORGEA_SCAN_SKIPPED=false"), "{context}");
    assert!(stdout.contains("Scanning with BLAST"), "{context}");
}
