//! Incremental scans: upload whole project, analyze only what changed.
//!
//! The server already does this, but it derives the diff through the project's
//! SCM integration, which leaves out every project that integration cannot
//! answer for: zip-only projects, unreachable self-hosted hosts, unpushed
//! commits. This module diffs in the clone the scan already reads from.
//!
//! Runs by default, so it must be safe on a repo never set up for it. Every
//! refusal falls through to the full scan that run would have done anyway.
//! `--disable-incremental` forces it.
//!
//! `base_sha` travels with the file list because the server carries findings
//! forward for every file the list omits. Copy from a different baseline than
//! the one diffed here and files changed between the two keep stale findings,
//! reported as current. The server copies from exactly this scan, or refuses.
//!
//! The archive is unchanged. Fusion reads unchanged files for cross-file
//! context, and a finding can only carry forward for a file the archive still
//! holds. Analysis shrinks, not the upload.

use crate::config::Config;
use crate::scanners::blast::{classify_scan_status, ScanState};
use crate::utils::api::{self, ScanResponse};
use git2::Repository;
use std::collections::BTreeSet;

/// How many of the project's scans to read at a time, newest first.
const SCAN_LOOKUP_PAGE_SIZE: u16 = 30;

/// Backstop on pages walked looking for a baseline.
///
/// The server filters out scans that cannot be a baseline, so the answer is
/// normally the first entry of page one and this never iterates. Kept for a
/// backend predating those filters: it ignores unknown parameters and returns
/// scans of every kind, so heavy pull-request traffic can fill a page with
/// nothing usable.
const SCAN_LOOKUP_MAX_PAGES: u16 = 3;

/// Engine every blast scan carries. An uploaded third-party report describes
/// someone else's analysis and cannot be a baseline for ours.
const BLAST_ENGINE: &str = "corgea-blast";

/// Payload guard, not policy. The server applies the real ceiling
/// (`INCREMENTAL_SCAN_MAX_FILES`, 300) and falls back to a full scan above it.
/// This only avoids building a multi-megabyte form field to be refused.
const MAX_CHANGED_FILES: usize = 5_000;

/// A diff the server can turn into an incremental scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalPlan {
    /// Commit this diff was measured from. The server carries its findings
    /// forward for every file the diff does not name.
    pub base_sha: String,
    /// Repo-relative paths differing between `base_sha` and the commit being
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
    // A commit-to-commit diff cannot see uncommitted edits, so a dirty tree
    // leaves modified files off the list and their old findings copied forward
    // as current. The server enforces this too; repeated here so the run says
    // why before paying for the upload.
    if worktree_dirty {
        explain_full_scan(
            "this worktree has uncommitted changes, and a commit-to-commit diff cannot see them",
        );
        return None;
    }

    // Nothing to diff from. Covers a non-git directory, a repo with no commit,
    // a detached HEAD, and a scan started below the repo root — none of which
    // report RepoInfo to the upload either.
    let (Some(branch), Some(head_sha)) = (branch, head_sha) else {
        explain_full_scan(
            "no git branch and commit to diff from (not a git repository, no commit \
             yet, a detached HEAD, or a scan started below the repository root)",
        );
        return None;
    };

    let base_sha = match find_baseline_sha(config, project_name, branch) {
        Baseline::Found(sha) => sha,
        Baseline::NotFound => {
            explain_full_scan(&format!(
                "no earlier completed scan of a clean worktree was found for project \
                 '{project_name}', so there is nothing to diff against"
            ));
            return None;
        }
        Baseline::LookupFailed => {
            explain_full_scan(&format!(
                "the earlier scans of project '{project_name}' could not be looked up, \
                 so there is nothing to diff against. Run with --verbose for the error"
            ));
            return None;
        }
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

/// Say why this run scans everything. Never fatal — a full scan is correct,
/// only slower, so the run continues.
fn explain_full_scan(reason: &str) {
    println!("Scanning every file: {reason}.");
}

/// Outcome of looking for a scan to diff against.
///
/// `NotFound` and `LookupFailed` both mean a full scan, but they are different
/// things to tell someone: one says this project has no scan history to build
/// on, the other says we could not read the history it may well have.
#[derive(Debug, PartialEq, Eq)]
enum Baseline {
    Found(String),
    NotFound,
    LookupFailed,
}

/// Commit of the newest scan this project can be diffed against.
///
/// Prefers the branch being scanned, falls back to the newest usable scan on
/// any branch, mirroring doghouse's own baseline order
/// (`ScanManager._try_incremental_scan`). That fallback is what makes a feature
/// branch's first scan incremental against trunk instead of full.
fn find_baseline_sha(config: &Config, project_name: &str, branch: &str) -> Baseline {
    let url = config.get_url();
    let mut any_branch_fallback: Option<String> = None;

    for page in 1..=SCAN_LOOKUP_MAX_PAGES {
        let response = match api::query_baseline_scans(
            &url,
            project_name,
            BLAST_ENGINE,
            page,
            SCAN_LOOKUP_PAGE_SIZE,
        ) {
            Ok(response) => response,
            Err(e) => {
                // A failed lookup proves nothing about the project's history,
                // so it means full scan, not error. An earlier page that did
                // answer still counts: that scan is a real baseline.
                crate::log::debug(&format!("Baseline scan lookup failed: {e}"));
                return match any_branch_fallback {
                    Some(sha) => Baseline::Found(sha),
                    None => Baseline::LookupFailed,
                };
            }
        };

        let scans = response.scans.unwrap_or_default();
        if scans.is_empty() {
            break;
        }

        // Newest first, so the first same-branch match is the best available
        // and no later page can improve on it.
        if let Some(sha) = same_branch_baseline(&scans, branch) {
            return Baseline::Found(sha);
        }
        if any_branch_fallback.is_none() {
            any_branch_fallback = any_branch_baseline(&scans);
        }

        if response
            .total_pages
            .is_some_and(|total| u32::from(page) >= total)
        {
            break;
        }
    }

    match any_branch_fallback {
        Some(sha) => Baseline::Found(sha),
        None => Baseline::NotFound,
    }
}

/// Newest usable scan of `branch` on this page.
fn same_branch_baseline(scans: &[ScanResponse], branch: &str) -> Option<String> {
    usable_baselines(scans)
        .find(|scan| scan.branch.as_deref() == Some(branch))
        .and_then(|scan| scan.git_sha.clone())
}

/// Newest usable scan on this page, whatever branch it ran on.
fn any_branch_baseline(scans: &[ScanResponse]) -> Option<String> {
    usable_baselines(scans)
        .next()
        .and_then(|scan| scan.git_sha.clone())
}

/// Scans on one page that can serve as a baseline, newest first.
fn usable_baselines(scans: &[ScanResponse]) -> impl Iterator<Item = &ScanResponse> {
    scans.iter().filter(|scan| is_usable_baseline(scan))
}

/// Whether `scan` may be diffed against.
///
/// Client-side half of the filter doghouse applies picking a baseline itself: a
/// completed blast scan of a whole, clean, non-pull-request commit.
/// `worktree_dirty` must be an explicit `false` — `None` means never reported,
/// and unknown scope is not clean, so the server rejects it as a baseline too.
///
/// `query_baseline_scans` asks the server for exactly these, which keeps the
/// page walk from iterating. This stays because a backend predating those
/// parameters ignores them, and a dirty or pull-request scan's commit would
/// diff against the wrong tree.
fn is_usable_baseline(scan: &ScanResponse) -> bool {
    classify_scan_status(&scan.status) == ScanState::Completed
        && scan.engine.eq_ignore_ascii_case(BLAST_ENGINE)
        && scan.pull_request_id.is_none()
        && scan.worktree_dirty == Some(false)
        && scan.git_sha.as_deref().is_some_and(|sha| !sha.is_empty())
}

/// Every repo-relative path differing between two commits.
///
/// Both sides of every delta, no status filtered out, because the list decides
/// which findings are *not* carried forward. A deleted file left off keeps its
/// findings in a tree no longer holding it; a rename is a delete plus an add
/// whose old path needs the same. `--target`'s `git:diff=` selector wants the
/// opposite — paths still on disk, to archive — hence no reuse.
///
/// Untracked files are not a gap: they make the worktree dirty, already
/// refused above.
///
/// Submodules are the one thing this cannot describe. A committed pointer bump
/// is one gitlink delta naming the submodule directory, while packaging walks
/// into it and uploads the files inside, so those files would be missing from
/// the list and keep old findings. Diffing the two submodule commits means
/// opening a repo that may not be checked out, so this fails closed.
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

    // Sorted and deduplicated: a rename reports one path per side, and stable
    // order keeps the uploaded list reproducible for the same two commits.
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
                // Byte-for-byte. Git stores `/` as its separator on every
                // platform, so a backslash here is part of the filename, and
                // translating it would name a file that did not change.
                let path = path.to_string_lossy().into_owned();
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

/// First 7 characters, by char boundary rather than byte index. The value comes
/// from the API, so a non-ASCII one must shorten, not panic mid-scan.
fn short_sha(sha: &str) -> &str {
    match sha.char_indices().nth(7) {
        Some((byte, _)) => &sha[..byte],
        None => sha,
    }
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
    fn short_sha_shortens_a_non_ascii_value_instead_of_panicking() {
        // The API supplies git_sha; a malformed one must not kill the scan.
        assert_eq!(short_sha("0123456789abcdef"), "0123456");
        assert_eq!(short_sha("abc"), "abc");
        assert_eq!(short_sha(""), "");
        assert_eq!(short_sha("ααααααααα"), "ααααααα");
    }

    #[test]
    fn a_completed_clean_blast_scan_is_a_baseline() {
        assert!(is_usable_baseline(&scan("main", "abc")));
    }

    #[test]
    fn scans_that_cannot_describe_a_whole_clean_commit_are_rejected() {
        // The server refuses each of these too, so diffing against them narrows
        // a scan the server then widens.
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

        // Never reported is not known clean.
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
        assert_eq!(any_branch_baseline(&scans).as_deref(), Some("newest"));
    }

    #[test]
    fn the_branch_being_scanned_is_preferred_over_a_newer_one_elsewhere() {
        let scans = vec![scan("main", "newer-on-main"), scan("feature", "on-feature")];
        assert_eq!(
            same_branch_baseline(&scans, "feature").as_deref(),
            Some("on-feature")
        );
    }

    #[test]
    fn a_branch_with_no_scan_of_its_own_falls_back_to_any_branch() {
        // A feature branch's first scan diffs against trunk rather than going
        // full, which is the whole point of the fallback.
        let scans = vec![scan("main", "on-main")];
        assert_eq!(same_branch_baseline(&scans, "feature"), None);
        assert_eq!(any_branch_baseline(&scans).as_deref(), Some("on-main"));
    }

    #[test]
    fn unusable_scans_are_skipped_when_picking_a_fallback() {
        let mut dirty = scan("main", "dirty");
        dirty.worktree_dirty = Some(true);
        let scans = vec![dirty, scan("main", "clean")];
        assert_eq!(any_branch_baseline(&scans).as_deref(), Some("clean"));
        assert_eq!(
            same_branch_baseline(&scans, "main").as_deref(),
            Some("clean")
        );
    }

    #[test]
    fn a_page_of_nothing_usable_yields_no_baseline() {
        let mut pr = scan("main", "pr");
        pr.pull_request_id = Some("42".to_string());
        let scans = vec![pr];
        assert_eq!(same_branch_baseline(&scans, "main"), None);
        assert_eq!(any_branch_baseline(&scans), None);
    }

    /// Two commits: three files, then one that adds, edits and deletes.
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
        // Deleted file must be listed, else its findings carry into a tree that
        // no longer holds it.
        assert_eq!(files, vec!["added.txt", "edit.txt", "gone.txt"]);
    }

    #[test]
    fn a_commit_diffed_against_itself_reports_nothing_changed() {
        let (_dir, repo, _base, head) = repo_with_history();
        assert!(changed_files_between(&repo, &head, &head)
            .expect("diff")
            .is_empty());
    }

    /// Commit whose tree carries a `vendor` gitlink pointing at `target`.
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
        // Packaging uploads the files inside the submodule, but the diff names
        // only `vendor`, so those files would keep unexamined findings.
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
