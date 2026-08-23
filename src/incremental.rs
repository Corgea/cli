//! `--incremental`: upload the whole project, analyze only what changed.
//!
//! Corgea already runs incremental scans, but it works the diff out server-side
//! by asking the project's SCM integration to compare two commits. That leaves
//! out every project the integration cannot answer for: zip-only projects with
//! no integration at all, self-hosted hosts Corgea cannot reach, and commits
//! that were never pushed. Those projects pay for a full analysis on every run
//! no matter how little moved. This module closes that gap by diffing in the
//! clone the scan is already reading from.
//!
//! Two values travel together and must stay together: the changed-file list and
//! the commit it was measured from. The server carries findings forward for
//! every file *absent* from the list, so if it were to pick a different
//! baseline than the one diffed here, findings in the files that changed
//! between the two baselines would be carried forward stale — reported as
//! current when nobody looked at them. Sending `base_sha` alongside the list
//! lets the server copy from exactly the scan this diff describes, or refuse
//! and scan everything.
//!
//! The archive is unchanged: a full scan still uploads the full project. Fusion
//! reads unchanged files for cross-file context even when it only analyzes the
//! diff, and the server can only carry a finding forward for a file the archive
//! still contains. What shrinks is the analysis, not the upload.
//!
//! Every refusal below scans everything instead. That is the expensive answer,
//! and it is always the correct one, so anything this module cannot prove —
//! a dirty tree, a missing baseline, a base commit this clone does not have —
//! lands there rather than narrowing a scan on a guess.

use crate::config::Config;
use crate::scanners::blast::{classify_scan_status, ScanState};
use crate::utils::api::{self, ScanResponse};
use git2::Repository;
use std::collections::BTreeSet;

/// How many of the project's scans to read at a time, newest first.
const SCAN_LOOKUP_PAGE_SIZE: u16 = 30;

/// Backstop on pages walked looking for a baseline. The newest usable scan is
/// almost always on the first page; this bounds a project whose recent history
/// is all pull-request or dirty-worktree scans.
const SCAN_LOOKUP_MAX_PAGES: u16 = 3;

/// The engine every blast scan carries, whoever started it. An uploaded
/// third-party report describes someone else's analysis and cannot be the
/// baseline for one of ours.
const BLAST_ENGINE: &str = "corgea-blast";

/// Payload guard, not policy. The server applies the real ceiling
/// (`INCREMENTAL_SCAN_MAX_FILES`, 300 by default) and falls back to a full scan
/// above it; this only keeps the CLI from building a multi-megabyte form field
/// for a diff that is obviously going to be refused.
const MAX_CHANGED_FILES: usize = 5_000;

/// A diff the server can turn into an incremental scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalPlan {
    /// The commit this diff was measured from: the scan whose findings the
    /// server carries forward for every file the diff does not name.
    pub base_sha: String,
    /// Repo-relative paths that differ between `base_sha` and the commit being
    /// scanned, including deletions and both sides of a rename.
    pub changed_files: Vec<String>,
}

/// What an incremental scan of this commit would cover, or `None` to scan
/// everything.
pub fn resolve_incremental_plan(
    config: &Config,
    project_name: &str,
    branch: Option<&str>,
    head_sha: Option<&str>,
    worktree_dirty: bool,
) -> Option<IncrementalPlan> {
    // A commit-to-commit diff cannot see edits that were never committed, so a
    // dirty tree would leave modified files out of the list and their old
    // findings copied forward as if current. The server enforces this too; it
    // is repeated here so the run says why before paying for the upload.
    if worktree_dirty {
        explain_full_scan(
            "this worktree has uncommitted changes, and a commit-to-commit diff cannot see them",
        );
        return None;
    }

    let (Some(branch), Some(head_sha)) = (branch, head_sha) else {
        explain_full_scan(
            "this run could not resolve a git branch and commit for the project \
             (a scan started outside the repository root reports neither)",
        );
        return None;
    };

    let Some(base_sha) = find_baseline_sha(config, project_name, branch) else {
        explain_full_scan(&format!(
            "no earlier completed scan of a clean worktree was found for project '{project_name}', \
             so there is nothing to diff against"
        ));
        return None;
    };

    let repo = match Repository::discover(".") {
        Ok(repo) => repo,
        Err(e) => {
            explain_full_scan(&format!("this directory is not a git repository ({e})"));
            return None;
        }
    };

    let changed_files = match changed_files_between(&repo, &base_sha, head_sha) {
        Ok(files) => files,
        Err(reason) => {
            explain_full_scan(&reason);
            return None;
        }
    };

    if changed_files.len() > MAX_CHANGED_FILES {
        explain_full_scan(&format!(
            "{} files changed since {}, which is more than an incremental scan is worth",
            changed_files.len(),
            short_sha(&base_sha)
        ));
        return None;
    }

    match changed_files.len() {
        0 => println!(
            "Incremental scan: nothing changed since commit {}. Corgea will carry every \
             finding forward.",
            short_sha(&base_sha)
        ),
        count => println!(
            "Incremental scan: {} file(s) changed since commit {}. Corgea will analyze those \
             and carry findings forward for the rest.",
            count,
            short_sha(&base_sha)
        ),
    }

    Some(IncrementalPlan {
        base_sha,
        changed_files,
    })
}

/// Say why this run is scanning everything. Never fatal: a full scan is the
/// correct answer, just a slower one, so the run continues.
fn explain_full_scan(reason: &str) {
    println!("Scanning every file: {reason}.");
}

/// The commit of the newest scan this project can be diffed against.
///
/// Prefers the branch being scanned and falls back to the newest usable scan on
/// any branch, mirroring how doghouse orders its own baseline lookup
/// (`ScanManager._try_incremental_scan`). The fallback is what makes the first
/// scan of a feature branch incremental against the trunk instead of full.
fn find_baseline_sha(config: &Config, project_name: &str, branch: &str) -> Option<String> {
    let url = config.get_url();
    let mut any_branch_fallback: Option<String> = None;

    for page in 1..=SCAN_LOOKUP_MAX_PAGES {
        let response = match api::query_scan_list(
            &url,
            Some(project_name),
            Some(page),
            Some(SCAN_LOOKUP_PAGE_SIZE),
        ) {
            Ok(response) => response,
            Err(e) => {
                // A lookup that fails proves nothing about the project's
                // history, so this is a full scan, not an error.
                crate::log::debug(&format!("Baseline scan lookup failed: {e}"));
                return any_branch_fallback;
            }
        };

        let scans = response.scans.unwrap_or_default();
        if scans.is_empty() {
            break;
        }

        // The list is newest first, so the first same-branch match is the best
        // baseline available and no later page can improve on it.
        if let Some(scan) = usable_baselines(&scans)
            .find(|scan| scan.branch.as_deref().is_some_and(|b| b == branch))
        {
            return scan.git_sha.clone();
        }
        if any_branch_fallback.is_none() {
            any_branch_fallback = usable_baselines(&scans)
                .next()
                .and_then(|s| s.git_sha.clone());
        }

        if response
            .total_pages
            .is_some_and(|total| u32::from(page) >= total)
        {
            break;
        }
    }

    any_branch_fallback
}

/// The scans on one page that can serve as a baseline, newest first.
fn usable_baselines(scans: &[ScanResponse]) -> impl Iterator<Item = &ScanResponse> {
    scans.iter().filter(|scan| is_usable_baseline(scan))
}

/// Whether `scan` may be diffed against.
///
/// These are the client-side half of the filter doghouse applies when it picks
/// a baseline itself: a completed blast scan of a whole, clean commit that is
/// not a pull request. `worktree_dirty` must be an explicit `false` — `None`
/// means the scan never reported it, and unknown scope is not a clean tree, so
/// the server would reject it as a baseline anyway.
fn is_usable_baseline(scan: &ScanResponse) -> bool {
    classify_scan_status(&scan.status) == ScanState::Completed
        && scan.engine.eq_ignore_ascii_case(BLAST_ENGINE)
        && scan.pull_request_id.is_none()
        && scan.worktree_dirty == Some(false)
        && scan.git_sha.as_deref().is_some_and(|sha| !sha.is_empty())
}

/// Every repo-relative path that differs between two commits.
///
/// Both sides of every delta are collected, and no status is filtered out,
/// because the list decides which findings are *not* carried forward. A deleted
/// file left off the list keeps its old findings in a tree where the file no
/// longer exists, and a rename is a delete plus an add whose old path needs the
/// same treatment. `--target`'s `git:diff=` selector deliberately does the
/// opposite — it wants paths that still exist on disk to put in an archive —
/// which is why this does not reuse it.
///
/// Files git does not track are not a gap here: an untracked file makes the
/// worktree dirty, and a dirty tree has already refused the incremental scan
/// above.
///
/// A submodule is the one thing this cannot describe. A committed pointer bump
/// is a single gitlink delta naming the submodule directory, while packaging
/// walks into that directory and uploads the files inside it — so the files
/// that actually changed would be missing from the list and keep their old
/// findings. Diffing the two submodule commits would mean opening a repository
/// that may not even be checked out, so this fails closed to a full scan.
fn changed_files_between(
    repo: &Repository,
    base_sha: &str,
    head_sha: &str,
) -> Result<Vec<String>, String> {
    let base_tree = commit_tree(repo, base_sha).map_err(|e| {
        format!(
            "commit {}, the one the last scan covered, is not in this clone ({e}). A shallow \
             clone cannot diff against it — fetch more history (for example `actions/checkout` \
             with `fetch-depth: 0`) to scan incrementally",
            short_sha(base_sha)
        )
    })?;
    let head_tree = commit_tree(repo, head_sha)
        .map_err(|e| format!("commit {} could not be read ({e})", short_sha(head_sha)))?;

    let diff = repo
        .diff_tree_to_tree(Some(&base_tree), Some(&head_tree), None)
        .map_err(|e| format!("the diff against {} failed ({e})", short_sha(base_sha)))?;

    // Sorted and deduplicated: a rename reports one path from each side, and a
    // stable order keeps the uploaded list reproducible for the same two commits.
    let mut files = BTreeSet::new();
    for delta in diff.deltas() {
        if delta.old_file().mode() == git2::FileMode::Commit
            || delta.new_file().mode() == git2::FileMode::Commit
        {
            let name = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|| "a submodule".to_string());
            return Err(format!(
                "submodule {name} moved to a different commit, and the diff names only \
                 the submodule itself rather than the files inside it that this scan \
                 uploads"
            ));
        }
        for file in [delta.old_file(), delta.new_file()] {
            if let Some(path) = file.path() {
                let path = path.to_string_lossy().replace('\\', "/");
                if !path.is_empty() {
                    files.insert(path);
                }
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn commit_tree<'repo>(
    repo: &'repo Repository,
    rev: &str,
) -> Result<git2::Tree<'repo>, git2::Error> {
    repo.revparse_single(rev)?.peel_to_commit()?.tree()
}

fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(7)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn scan(branch: &str, sha: &str) -> ScanResponse {
        ScanResponse {
            id: format!("scan-{sha}"),
            project: "proj".to_string(),
            repo: None,
            branch: Some(branch.to_string()),
            status: "complete".to_string(),
            engine: BLAST_ENGINE.to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            git_sha: Some(sha.to_string()),
            worktree_dirty: Some(false),
            pull_request_id: None,
            metadata: None,
            failed_reason: None,
            scan_errors: Vec::new(),
        }
    }

    #[test]
    fn a_completed_clean_blast_scan_is_a_baseline() {
        assert!(is_usable_baseline(&scan("main", "abc")));
    }

    #[test]
    fn scans_that_cannot_describe_a_whole_clean_commit_are_rejected() {
        // Each of these would make the server refuse the baseline too, so
        // diffing against them would narrow a scan the server then widens.
        let mut running = scan("main", "abc");
        running.status = "processing".to_string();
        assert!(!is_usable_baseline(&running));

        let mut third_party = scan("main", "abc");
        third_party.engine = "semgrep".to_string();
        assert!(!is_usable_baseline(&third_party));

        let mut pr = scan("main", "abc");
        pr.pull_request_id = Some("42".to_string());
        assert!(!is_usable_baseline(&pr));

        let mut dirty = scan("main", "abc");
        dirty.worktree_dirty = Some(true);
        assert!(!is_usable_baseline(&dirty));

        // Never reported is not the same as known clean.
        let mut unknown = scan("main", "abc");
        unknown.worktree_dirty = None;
        assert!(!is_usable_baseline(&unknown));

        let mut no_commit = scan("main", "abc");
        no_commit.git_sha = None;
        assert!(!is_usable_baseline(&no_commit));
    }

    #[test]
    fn the_newest_usable_scan_wins_within_a_page() {
        let scans = vec![scan("main", "newest"), scan("main", "older")];
        assert_eq!(
            usable_baselines(&scans).next().unwrap().git_sha.as_deref(),
            Some("newest")
        );
    }

    /// A repo with two commits: `first.txt`, then a commit that adds, edits and
    /// deletes. Returns `(tempdir, base_sha, head_sha)`.
    fn repo_with_history() -> (tempfile::TempDir, Repository, String, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(dir.path()).expect("init");
        let sig = git2::Signature::now("t", "t@example.com").expect("sig");

        let commit_all =
            |repo: &Repository, message: &str, parent: Option<git2::Oid>| -> git2::Oid {
                let mut index = repo.index().expect("index");
                index
                    .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
                    .expect("add");
                index.write().expect("write index");
                let tree = repo
                    .find_tree(index.write_tree().expect("tree"))
                    .expect("find tree");
                let parents: Vec<git2::Commit> = parent
                    .map(|oid| vec![repo.find_commit(oid).expect("parent")])
                    .unwrap_or_default();
                let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
                repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
                    .expect("commit")
            };

        let write = |name: &str, body: &str| {
            fs::write(dir.path().join(name), body).expect("write file");
        };

        write("keep.txt", "same");
        write("edit.txt", "before");
        write("gone.txt", "doomed");
        let base = commit_all(&repo, "base", None);

        write("edit.txt", "after");
        write("added.txt", "new");
        fs::remove_file(dir.path().join("gone.txt")).expect("remove");
        // add_all does not stage a deletion on its own.
        let mut index = repo.index().expect("index");
        index
            .remove_path(Path::new("gone.txt"))
            .expect("stage delete");
        index.write().expect("write index");
        let head = commit_all(&repo, "head", Some(base));

        (dir, repo, base.to_string(), head.to_string())
    }

    #[test]
    fn the_diff_names_added_edited_and_deleted_files_but_not_untouched_ones() {
        let (_dir, repo, base, head) = repo_with_history();
        let files = changed_files_between(&repo, &base, &head).expect("diff");
        // A deleted file must be listed: leaving it out would carry its old
        // findings into a scan of a tree that no longer contains it.
        assert_eq!(files, vec!["added.txt", "edit.txt", "gone.txt"]);
    }

    #[test]
    fn a_commit_diffed_against_itself_reports_nothing_changed() {
        let (_dir, repo, _base, head) = repo_with_history();
        assert!(changed_files_between(&repo, &head, &head)
            .expect("diff")
            .is_empty());
    }

    /// A commit whose tree carries a `vendor` gitlink pointing at `target`.
    fn commit_with_gitlink(repo: &Repository, parent: git2::Oid, target: git2::Oid) -> git2::Oid {
        let sig = git2::Signature::now("t", "t@example.com").expect("sig");
        let parent_commit = repo.find_commit(parent).expect("parent");
        let mut builder = repo
            .treebuilder(Some(&parent_commit.tree().expect("parent tree")))
            .expect("treebuilder");
        builder
            .insert("vendor", target, i32::from(git2::FileMode::Commit))
            .expect("insert gitlink");
        let tree_oid = builder.write().expect("write tree");
        let tree = repo.find_tree(tree_oid).expect("find tree");
        repo.commit(None, &sig, &sig, "gitlink", &tree, &[&parent_commit])
            .expect("commit")
    }

    #[test]
    fn a_moved_submodule_pointer_refuses_the_diff() {
        // Packaging walks into the submodule and uploads the files inside it,
        // but the diff names only `vendor`, so those files would keep findings
        // nothing re-examined.
        let (_dir, repo, base, head) = repo_with_history();
        let base_oid = git2::Oid::from_str(&base).expect("base oid");
        let head_oid = git2::Oid::from_str(&head).expect("head oid");
        let before = commit_with_gitlink(&repo, base_oid, base_oid);
        let after = commit_with_gitlink(&repo, before, head_oid);

        let err = changed_files_between(&repo, &before.to_string(), &after.to_string())
            .expect_err("a moved submodule must refuse the diff");

        assert!(err.contains("submodule vendor"), "{err}");
    }

    #[test]
    fn a_base_commit_this_clone_does_not_have_is_reported_not_panicked() {
        let (_dir, repo, _base, head) = repo_with_history();
        let err = changed_files_between(&repo, &"0".repeat(40), &head)
            .expect_err("unknown base must fail");
        assert!(err.contains("shallow clone"), "{err}");
    }
}
