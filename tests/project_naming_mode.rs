//! End-to-end tests for `--project-naming-mode`.

mod common;

use common::{projects_match, scans_one, temp_git_repo, Hits, Routes, CANON, REMOTE};
use std::path::Path;
use std::process::{Command, Output};

/// `REMOTE`'s default project name plus the one folder the checkout keeps.
const SPARSE_NAME: &str = "dotnet-azure-web-tsb-jsoar-agent";

fn git(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    for (name, _) in std::env::vars() {
        if name.starts_with("GIT_") {
            cmd.env_remove(name);
        }
    }
    assert!(
        cmd.args(args).current_dir(dir).status().unwrap().success(),
        "git {args:?} failed"
    );
}

/// A committed clone of `REMOTE` with a cone sparse checkout of `jsoar-agent`.
fn sparse_repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let (tmp, repo) = temp_git_repo("build-123", REMOTE);
    for dir in ["jsoar-agent", "common"] {
        std::fs::create_dir(repo.join(dir)).unwrap();
        std::fs::write(repo.join(dir).join("app.py"), "x = 1\n").unwrap();
    }
    git(&repo, &["add", "-A"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "init",
        ],
    );
    git(&repo, &["sparse-checkout", "set", "--cone", "jsoar-agent"]);
    (tmp, repo)
}

fn spawn_stub() -> (String, Hits) {
    common::spawn_resolution_stub(Routes {
        projects: Some(projects_match()),
        scans: Some(scans_one(SPARSE_NAME)),
        ..Default::default()
    })
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn list_queries_the_sparse_postfixed_project_directly() {
    let (url, hits) = spawn_stub();
    let (_tmp, repo) = sparse_repo();
    let out = common::run_corgea(
        "list",
        &["--project-naming-mode", "sparse-postfixed"],
        &url,
        &repo,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains(SPARSE_NAME),
        "stderr: {}",
        stderr(&out)
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.contains(&format!("project={SPARSE_NAME}"))),
        "the derived name must drive /scans; hits: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.starts_with("/api/v1/projects")),
        "a derived name is queried as given, not resolved by repo; hits: {hits:?}"
    );
}

#[test]
fn list_outside_a_sparse_checkout_warns_and_resolves_as_usual() {
    let (url, hits) = spawn_stub();
    let (_tmp, repo) = temp_git_repo("build-123", REMOTE);
    let out = common::run_corgea(
        "list",
        &["--project-naming-mode", "sparse-postfixed"],
        &url,
        &repo,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("not a sparse checkout"),
        "stderr: {}",
        stderr(&out)
    );
    let hits = hits.lock().unwrap();
    assert!(
        hits.iter()
            .any(|h| h.contains(&format!("project={}", CANON.replace('/', "%2F")))),
        "the repo-resolved project must drive /scans; hits: {hits:?}"
    );
}

#[test]
fn the_mode_cannot_be_combined_with_an_explicit_project_name() {
    let (_tmp, repo) = sparse_repo();
    for subcommand in ["scan", "upload", "list", "wait"] {
        let out = common::run_corgea(
            subcommand,
            &[
                "--project-naming-mode",
                "sparse-postfixed",
                "--project-name",
                "mine",
            ],
            "http://127.0.0.1:9",
            &repo,
        );
        assert_eq!(out.status.code(), Some(2), "{subcommand}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("cannot be used with"),
            "{subcommand}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn an_unknown_mode_is_rejected_with_the_supported_values() {
    let (_tmp, repo) = sparse_repo();
    let out = common::run_corgea(
        "scan",
        &["--project-naming-mode", "sparse"],
        "http://127.0.0.1:9",
        &repo,
    );
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("sparse-postfixed"),
        "stderr: {}",
        stderr(&out)
    );
}
