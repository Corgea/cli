//! End-to-end tests for `corgea list` repo-URL project resolution (COR-1577).
//! Stubs route on the request-target path PREFIX: `/projects` carries a
//! percent-encoded query, so the full target is not a stable key.

mod common;

use common::{
    projects_empty, projects_match, scans_empty, scans_one, temp_git_repo, temp_plain_dir, Hits,
    Routes, CANON, REMOTE,
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
fn spawn_stub(projects: String, scans: String, issues: String) -> (String, Hits) {
    common::spawn_resolution_stub(Routes {
        projects: Some(projects),
        scans: Some(scans),
        issues: Some(issues),
        ..Default::default()
    })
}

/// Stub serving verify + the SCA listing endpoint only.
fn spawn_sca_stub() -> (String, Hits) {
    common::spawn_resolution_stub(Routes {
        sca_issues: Some(common::sca_issues_empty()),
        ..Default::default()
    })
}

fn run_list(args: &[&str], url: &str, cwd: &Path) -> Output {
    common::run_corgea("list", args, url, cwd)
}

/// True when some request carried `project=<name>` (the `/scans` route
/// percent-encodes via reqwest; `/issues` interpolates the name raw).
fn queried_project(hits: &[String], name: &str) -> bool {
    let encoded = name.replace('/', "%2F");
    hits.iter().any(|h| {
        h.contains(&format!("project={name}")) || h.contains(&format!("project={encoded}"))
    })
}

// --- tests -----------------------------------------------------------------

#[test]
fn list_uses_canonical_name_from_repo() {
    // The checkout is `build-123`, so the canonical name can only have come
    // from resolution — and the assertion is on the query the CLI SENT, since
    // the stub answers every /scans the same way regardless.
    let (url, hits) = spawn_stub(projects_match(), scans_one(CANON), issues_one());
    let (_tmp, repo) = temp_git_repo("build-123", REMOTE);
    let out = run_list(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains(CANON), "stdout: {stdout}");
    assert!(stdout.contains("scan-123"), "stdout: {stdout}");
    let hits = hits.lock().unwrap();
    assert!(
        queried_project(&hits, CANON),
        "the canonical project must drive /scans; hits: {hits:?}"
    );
}

#[test]
fn list_issues_uses_canonical_name_from_repo() {
    let (url, hits) = spawn_stub(projects_match(), scans_one(CANON), issues_one());
    let (_tmp, repo) = temp_git_repo("build-123", REMOTE);
    let out = run_list(&["--issues"], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("issue-abc"), "stdout: {stdout}");
    let hits = hits.lock().unwrap();
    assert!(
        queried_project(&hits, CANON),
        "the canonical project must drive /issues; hits: {hits:?}"
    );
}

#[test]
fn list_resolves_from_a_subdirectory() {
    // Discovery walks up from src/, so the remote — not the `src` basename —
    // drives resolution.
    let (url, hits) = spawn_stub(projects_match(), scans_one(CANON), issues_one());
    let (_tmp, repo) = temp_git_repo("build-123", REMOTE);
    let subdir = repo.join("src");
    std::fs::create_dir(&subdir).expect("create subdir");
    let out = run_list(&[], &url, &subdir);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        queried_project(&hits, CANON),
        "expected resolution from the subdir; hits: {hits:?}"
    );
}

#[test]
fn list_repo_flag_resolves_from_flag_not_remote() {
    // Non-git dir: no remote, so a resolved slug can ONLY have come from --repo.
    let (url, hits) = spawn_stub(projects_match(), scans_one(CANON), issues_one());
    let (_tmp, dir) = temp_plain_dir("unrelated-dir");
    let out = run_list(&["--repo", CANON], &url, &dir);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/projects?repo_url=bohappdev%2Fdotnet-azure-web-tsb")),
        "expected a /projects hit carrying the flag slug; hits: {hits:?}"
    );
}

#[test]
fn list_miss_names_the_repo_and_renders_no_table() {
    // Pre-COR-1577 this silently printed an empty table and exited 0.
    let (url, _hits) = spawn_stub(projects_empty(), scans_empty(), issues_miss());
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&[], &url, &repo);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains(&format!("repo '{CANON}'")),
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
    let (url, _hits) = spawn_stub(projects_match(), scans_empty(), issues_miss());
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
fn list_unconfirmed_falls_back_to_the_legacy_name() {
    // On a /projects soft miss (old or not-yet-onboarded backend) the query
    // must stay what the pre-COR-1577 CLI sent — the repo basename at the
    // worktree root — or a working setup starts missing.
    let (url, hits) = spawn_stub(
        projects_empty(),
        scans_one("dotnet-azure-web-tsb"),
        issues_one(),
    );
    let (_tmp, repo) = temp_git_repo("build-123", REMOTE);
    let out = run_list(&[], &url, &repo);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        queried_project(&hits, "dotnet-azure-web-tsb"),
        "expected the repo basename, not the checkout dir; hits: {hits:?}"
    );
    assert!(
        !queried_project(&hits, "build-123"),
        "the checkout dir name must not be queried; hits: {hits:?}"
    );
}

#[test]
fn list_project_name_override_skips_resolution() {
    let (url, hits) = spawn_stub(projects_empty(), scans_one("some/name"), issues_one());
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
    let hits = hits.lock().unwrap();
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/projects")),
        "an exact name needs no resolution round trip; hits: {hits:?}"
    );
}

#[test]
fn list_issues_percent_encodes_the_project_name() {
    // A project name is user- and server-supplied; interpolated raw, an `&`
    // would split the query and address the project `foo` instead.
    let (url, hits) = spawn_stub(projects_empty(), scans_empty(), issues_one());
    let (_tmp, dir) = temp_plain_dir("whatever");
    let out = run_list(&["--issues", "--project-name", "foo&bar#baz"], &url, &dir);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter().any(|h| h.contains("project=foo%26bar%23baz")),
        "the delimiters must be encoded, not split the query; hits: {hits:?}"
    );
}

#[test]
fn list_sca_issues_scopes_to_an_explicit_project_name() {
    // The flags are offered on every `list` mode, so with --sca-issues they
    // must actually scope the request rather than silently return every
    // project's findings. `list_sca_issues` reads `project`.
    let (url, hits) = spawn_sca_stub();
    let (_tmp, dir) = temp_plain_dir("whatever");
    let out = run_list(&["--sca-issues", "--project-name", "some/name"], &url, &dir);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.starts_with("/api/v1/issues/sca") && h.contains("project=some%2Fname")),
        "the SCA request must carry the named project; hits: {hits:?}"
    );
}

#[test]
fn list_sca_issues_without_a_selector_stays_unscoped() {
    // Unflagged --sca-issues has always returned the company-wide latest scan;
    // adding the flags must not silently narrow it.
    let (url, hits) = spawn_sca_stub();
    let (_tmp, repo) = temp_git_repo("dotnet-azure-web-tsb", REMOTE);
    let out = run_list(&["--sca-issues"], &url, &repo);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = hits.lock().unwrap();
    assert!(
        !hits.iter().any(|h| h.contains("project=")),
        "no selector means no project scope; hits: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/projects")),
        "and no resolution round trip; hits: {hits:?}"
    );
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
    let (url, _hits) = spawn_stub(projects_empty(), scans_empty(), issues_miss());
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
        scan_issues: Some(common::scan_issues_empty()),
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
}
