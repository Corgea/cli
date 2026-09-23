//! Incremental scans: upload whole project, analyze only what changed.
//!
//! The server already does this, but it derives the diff through the project's
//! SCM integration, which leaves out every project that integration cannot
//! answer for: zip-only projects, unreachable self-hosted hosts, unpushed
//! commits. This module works the diff out where the scan is run.
//!
//! Finding what to diff *against* is the same in both directions: ask the
//! server for the newest completed scan of this branch, then of trunk if this
//! branch has never been scanned. What changed since it can then be measured
//! two ways.
//!
//! The first is the file checksums that scan uploaded, fetched and subtracted
//! from this run's. It needs no git history, so it is the only one that works
//! in a shallow clone, on a detached HEAD, or in a directory unpacked from a
//! tarball — the cases that used to analyze every file on every run, forever.
//! It also measures the right thing: the archive, not the repository, so
//! ignored paths, excluded globs and uncommitted edits cannot make the list
//! disagree with what the scanner will read.
//!
//! The second is `git diff` against the baseline's commit. It is the fallback,
//! for a baseline scan predating manifests or one whose manifest cannot be
//! read, and it needs the history a shallow clone does not have.
//!
//! That difference is what decides an `--exclude` run. Its archive is the whole
//! project under one more glob, which the checksums describe exactly, so they
//! diff it like any other. A git diff describes the repository instead: every
//! excluded file it finds unchanged is left off the list, and the server copies
//! that file's findings forward though this upload does not contain it. So an
//! `--exclude` run diffs its checksums or scans everything.
//!
//! Runs by default, so it must be safe on a repo never set up for it. Every
//! refusal falls through to the full scan that run would have done anyway.
//! `--disable-incremental` forces it.
//!
//! The baseline travels with the file list because the server carries findings
//! forward for every file the list omits. Copy from a different baseline than
//! the one diffed here and files changed between the two keep stale findings,
//! reported as current. The server copies from exactly this scan, or refuses.
//!
//! The archive is unchanged. Fusion reads unchanged files for cross-file
//! context, and a finding can only carry forward for a file the archive still
//! holds. Analysis shrinks, not the upload.

use crate::config::Config;
use crate::manifest::{Manifest, MANIFEST_VERSION};
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

/// How an upload names the scan its diff was measured from.
///
/// Two forms because the two diffs know different things. A git diff is
/// measured from a commit and says so. A checksum diff is measured from one
/// specific scan's stored manifest, and that scan is what has to be copied
/// from — it may have been uploaded with no commit at all, and where several
/// scans share a commit, naming it would leave the server to pick between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineRef {
    Commit(String),
    Scan(String),
}

/// A diff the server can turn into an incremental scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalPlan {
    /// The scan this diff was measured from. The server carries its findings
    /// forward for every file the diff does not name.
    pub base: BaselineRef,
    /// Repo-relative paths differing from the baseline, including deletions
    /// and both sides of a rename.
    pub changed_files: Vec<String>,
    /// Whether the diff measured the working tree rather than a commit. The
    /// server refuses a dirty upload otherwise, because a commit-to-commit diff
    /// cannot describe one.
    pub covers_worktree: bool,
}

impl IncrementalPlan {
    /// Add force-included files to what the server will analyze.
    ///
    /// The server carries findings forward for every file the diff omits, so a
    /// force-included file that has not changed would never be looked at — and
    /// the reason to add an include rule is precisely that the file was never
    /// scanned before, so there is nothing to carry forward. Returns `None`
    /// when the combined list outgrows an incremental scan, which falls back to
    /// scanning everything.
    pub fn including(mut self, forced: &[String]) -> Option<Self> {
        let mut listed: BTreeSet<String> = self.changed_files.iter().cloned().collect();
        let additions: Vec<String> = forced
            .iter()
            .filter(|path| listed.insert((*path).clone()))
            .cloned()
            .collect();
        if additions.is_empty() {
            return Some(self);
        }
        if self.changed_files.len() + additions.len() > MAX_CHANGED_FILES {
            println!(
                "Scanning every file: the include rules cover more files than an incremental scan is worth."
            );
            return None;
        }
        match additions.len() {
            1 => println!("Incremental scan: also analyzing 1 force-included file."),
            count => println!("Incremental scan: also analyzing {count} force-included files."),
        }
        self.changed_files.extend(additions);
        self.changed_files.sort();
        Some(self)
    }
}

/// What this run can measure a diff with.
///
/// Grouped rather than passed alongside each other, because three of these are
/// booleans and a caller listing them positionally can swap two without the
/// compiler noticing — which would quietly change how the scan is scoped.
pub struct DiffSources<'a> {
    /// Branch the upload reports. Names where a baseline may come from, and
    /// the git diff needs it to have one at all.
    pub branch: Option<&'a str>,
    /// Commit the upload reports, the near side of a git diff.
    pub head_sha: Option<&'a str>,
    /// Whether the worktree holds edits a commit-to-commit diff cannot see.
    pub worktree_dirty: bool,
    /// `--ignore-dirty-worktree`: move the far side of the git diff to the
    /// working tree rather than refusing to measure one.
    pub ignore_dirty_worktree: bool,
    /// `--exclude` held files back from the archive, so only the checksums
    /// can account for what it actually contains.
    pub exclude_narrowed: bool,
    /// This archive's checksums, absent when the archive is not the whole
    /// project.
    pub manifest: Option<&'a Manifest>,
}

/// What an incremental scan of this upload would cover.
///
/// Prints one line either way: the scope it resolved to, or why the scan is
/// analyzing everything.
pub fn resolve_incremental_plan(
    config: &Config,
    project_name: &str,
    sources: DiffSources<'_>,
) -> Option<IncrementalPlan> {
    match plan_diff(config, project_name, &sources) {
        Ok((plan, summary)) => {
            println!("{summary}");
            Some(plan)
        }
        // Never fatal — a full scan is correct, only slower, so the run
        // continues and only says why.
        Err(reason) => {
            println!("Scanning every file: {reason}.");
            None
        }
    }
}

/// The diff and a line describing it, or why there is no diff to send.
fn plan_diff(
    config: &Config,
    project_name: &str,
    sources: &DiffSources<'_>,
) -> Result<(IncrementalPlan, String), String> {
    // Optional, because a checksum diff needs no repository. Only the git diff
    // below does, and it reports its absence by its real name.
    let repo = Repository::discover(".").ok();
    // Branch names are only meaningful where there is a clone to read them
    // from. Without one, take the project's newest usable scan whatever branch
    // it names -- including none, which is what a scan uploaded from a
    // directory with no git records, and so what the earlier runs of *this*
    // pipeline recorded.
    let candidates = repo
        .as_ref()
        .map(|repo| baseline_branches(repo, sources.branch.filter(|name| !name.is_empty())));

    let lookup = find_baseline(
        config,
        project_name,
        candidates.as_deref(),
        sources.manifest.is_some(),
    );
    let baseline = match lookup {
        BaselineLookup::Found(scan) => scan,
        BaselineLookup::NotFound => {
            return Err(format!(
                "project '{project_name}' has no completed scan {} that could be diffed \
                 against, so there is nothing to compare this one to",
                match &candidates {
                    Some(candidates) => format!("on {}", join_or(candidates)),
                    None => "of its whole state".to_string(),
                }
            ))
        }
        BaselineLookup::LookupFailed => {
            return Err(format!(
                "the earlier scans of project '{project_name}' could not be looked up, \
                 so there is nothing to diff against. Run with --verbose for the error"
            ))
        }
    };

    // Checksums first. They describe the archive rather than the repository, so
    // they are exact where a git diff has to be argued about, and they work in
    // a clone that cannot reach the baseline commit — or has no commits.
    let checksum_refusal = match sources.manifest {
        Some(local) => match changed_files_against(config, &baseline, local) {
            Ok(changed_files) => {
                let summary = summarize(&changed_files, &format!("the {}", baseline.describe()))?;
                return Ok((
                    IncrementalPlan {
                        // Checksums are taken over the files as they sit on
                        // disk, so uncommitted edits are named in the list like
                        // any other change rather than missing from it.
                        base: BaselineRef::Scan(baseline.id),
                        changed_files,
                        covers_worktree: true,
                    },
                    summary,
                ));
            }
            // Not fatal on its own: git may still be able to answer, and this
            // is the expected path for a baseline that predates manifests.
            Err(reason) => {
                crate::log::debug(&format!("{reason}. Trying git."));
                Some(reason)
            }
        },
        None => None,
    };

    // Whichever way this run would have preferred to measure the diff, what it
    // ends up reporting has to name every reason it could not. Printing only
    // git's leaves someone looking at a full scan they expected to be
    // incremental with no idea the checksums were tried at all, let alone why
    // they did not apply.
    plan_git_diff(&baseline, repo.as_ref(), sources).map_err(|reason| match &checksum_refusal {
        Some(refusal) => format!("{refusal}, and {reason}"),
        None => reason,
    })
}

/// The diff `git` can measure from the baseline's commit, and a line describing
/// it. The fallback, for a baseline predating checksums or one whose checksums
/// could not be read.
fn plan_git_diff(
    baseline: &BaselineScan,
    repo: Option<&Repository>,
    sources: &DiffSources<'_>,
) -> Result<(IncrementalPlan, String), String> {
    // git diffs the repository, and --exclude means the archive is not it. An
    // excluded file git reports unchanged is left off the list, so the server
    // copies its findings forward over a file this upload does not contain --
    // and no later run under the same --exclude will look at it either. First,
    // because these runs report dirty whatever the worktree holds, so the check
    // below would otherwise answer for a tree with nothing uncommitted in it.
    if sources.exclude_narrowed {
        return Err(
            "--exclude held files back from this archive, so a git diff of the repository \
             would not describe it (its stored file checksums would, on the next run)"
                .to_string(),
        );
    }

    // A commit-to-commit diff cannot see uncommitted edits, so on a dirty tree
    // it leaves modified files off the list and their old findings are copied
    // forward as current. --ignore-dirty-worktree does not paper over that; it
    // switches the diff to measure the working tree, so those files are named
    // and rescanned like any other change.
    let covers_worktree = sources.worktree_dirty;
    if sources.worktree_dirty && !sources.ignore_dirty_worktree {
        return Err(
            "this worktree has uncommitted changes that a commit-to-commit diff cannot \
             see. Pass --ignore-dirty-worktree to diff the working tree instead"
                .to_string(),
        );
    }

    // Nothing to diff from. Covers a non-git directory, a repo with no commit,
    // a detached HEAD, and a scan started below the repo root — none of which
    // report RepoInfo to the upload either.
    let (Some(_branch), Some(head_sha), Some(repo), Some(base_sha)) = (
        sources.branch,
        sources.head_sha,
        repo,
        baseline.sha.as_deref(),
    ) else {
        return Err(
            "there is no git branch and commit to diff from either (not a git \
             repository, no commit yet, a detached HEAD, or a scan started below the \
             repository root)"
                .to_string(),
        );
    };

    let changed_files = changed_files_since(repo, base_sha, head_sha, covers_worktree)?;
    let since = if covers_worktree {
        format!(
            "commit {} and your uncommitted changes",
            short_sha(base_sha)
        )
    } else {
        format!("commit {}", short_sha(base_sha))
    };
    let summary = summarize(&changed_files, &since)?;

    Ok((
        IncrementalPlan {
            base: BaselineRef::Commit(base_sha.to_string()),
            changed_files,
            covers_worktree,
        },
        summary,
    ))
}

/// One line for a diff of this size, or why it is too big to be worth sending.
fn summarize(changed_files: &[String], since: &str) -> Result<String, String> {
    if changed_files.len() > MAX_CHANGED_FILES {
        return Err(format!(
            "{} files changed since {since}, which is more than an incremental scan \
             is worth",
            changed_files.len()
        ));
    }
    Ok(match changed_files.len() {
        0 => format!("Incremental scan: nothing changed since {since}."),
        1 => format!("Incremental scan: 1 file changed since {since}."),
        count => format!("Incremental scan: {count} files changed since {since}."),
    })
}

/// Files differing from the checksums `baseline` stored, by fetching them.
///
/// Every refusal names the baseline and reads as a whole clause, because it is
/// what the run prints when git cannot answer either. "It stored none" is the
/// ordinary one and is not a fault: it is what every scan uploaded before
/// checksums existed says, and what a deployment that does not store them yet
/// says about all of them.
fn changed_files_against(
    config: &Config,
    baseline: &BaselineScan,
    local: &Manifest,
) -> Result<Vec<String>, String> {
    let what = baseline.describe();
    let Some(root) = baseline.manifest_root.as_deref() else {
        return Err(format!(
            "the {what} stored no file checksums to diff against"
        ));
    };
    // A manifest is only comparable to one written the same way. Rather than
    // guess at a format a later client introduced, leave it to git.
    if baseline.manifest_version.as_deref() != Some(MANIFEST_VERSION) {
        return Err(format!(
            "the file checksums of the {what} are version {}, which this client does \
             not read (it reads version {MANIFEST_VERSION})",
            baseline.manifest_version.as_deref().unwrap_or("unknown")
        ));
    }
    let body = api::download_scan_file_manifest(&config.get_url(), &baseline.id)
        .map_err(|e| format!("the file checksums of the {what} could not be downloaded ({e})"))?;
    let decoded = Manifest::decode(&body, root)
        .map_err(|e| format!("the file checksums of the {what} could not be read ({e})"))?;
    Ok(decoded.changed_paths(local))
}

/// A scan that can be diffed against, and what it offers to diff with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BaselineScan {
    /// What the upload names when the diff came from this scan's checksums.
    id: String,
    /// Commit it covered, which the git diff measures from. `None` for a scan
    /// uploaded without git, which only a checksum diff can use.
    sha: Option<String>,
    /// Branch it ran on, for saying what this run is being compared to.
    branch: Option<String>,
    /// Digest of the file manifest it stored, `None` when it stored none.
    manifest_root: Option<String>,
    manifest_version: Option<String>,
}

impl BaselineScan {
    /// How to refer to this scan in the one line the run prints.
    fn describe(&self) -> String {
        let what = match &self.branch {
            Some(branch) => format!("last scan of {branch}"),
            None => "last scan of this project".to_string(),
        };
        match &self.sha {
            Some(sha) => format!("{what} ({})", short_sha(sha)),
            None => what,
        }
    }
}

/// Outcome of looking for a scan to diff against.
///
/// `NotFound` and `LookupFailed` both mean a full scan, but they are different
/// things to tell someone: one says this project has no scan history to build
/// on, the other says we could not read the history it may well have.
#[derive(Debug, PartialEq, Eq)]
enum BaselineLookup {
    Found(BaselineScan),
    NotFound,
    LookupFailed,
}

/// The branches a baseline may come from, best first.
///
/// The branch being scanned leads. Its last scan is the nearest ancestor of
/// this one that exists, so the diff against it is the smallest honest one and
/// the findings carried forward are this branch's own. A long-lived branch that
/// has diverged from trunk gets the biggest reduction: against trunk every file
/// it has touched since it forked is "changed", against its own last scan only
/// what moved since that scan is.
///
/// Trunk follows, because a branch on its first scan has no history of its own
/// and trunk is the line it descends from. *Other* branches never qualify: a
/// scan of someone else's feature branch is a baseline whose contents nobody
/// can predict, and the findings copied forward would be that branch's.
///
/// `origin/HEAD` records what the remote advertised as its default when this
/// clone was made. It is absent from single-branch and `actions/checkout`
/// checkouts and is never refreshed after a rename, so `main` and `master`
/// follow it rather than replace it. Scanning trunk itself is the ordinary
/// case, and there the first entry already is trunk, so nothing repeats.
fn baseline_branches(repo: &Repository, scanning: Option<&str>) -> Vec<String> {
    let mut branches: Vec<String> = scanning.map(str::to_string).into_iter().collect();
    let trunks = default_branch(repo)
        .into_iter()
        .chain(fallback_trunks().iter().cloned());
    for trunk in trunks {
        if !branches.contains(&trunk) {
            branches.push(trunk);
        }
    }
    branches
}

/// Trunk names to try when this clone cannot say which one it descends from,
/// including when there is no clone to ask.
fn fallback_trunks() -> &'static [String; 2] {
    static TRUNKS: std::sync::OnceLock<[String; 2]> = std::sync::OnceLock::new();
    TRUNKS.get_or_init(|| ["main".to_string(), "master".to_string()])
}

/// Default branch this clone recorded, or None when it recorded none.
fn default_branch(repo: &Repository) -> Option<String> {
    let reference = repo.find_reference("refs/remotes/origin/HEAD").ok()?;
    let name = reference
        .symbolic_target()
        .ok()
        .flatten()?
        .strip_prefix("refs/remotes/origin/")?;
    (!name.is_empty() && name != "HEAD").then(|| name.to_string())
}

fn join_or(branches: &[String]) -> String {
    match branches.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => "any branch".to_string(),
    }
}

/// The newest scan that can be diffed against, on the first candidate branch
/// that has one.
///
/// One query per branch, because the branch filter is server-side: a project
/// with heavy feature-branch traffic can push the branch's newest scan far past
/// any page limit, and asking for it directly cannot miss it that way.
///
/// `branches` is `None` when this clone can name no branch at all, which makes
/// it one query for the project's newest usable scan on any branch.
fn find_baseline(
    config: &Config,
    project_name: &str,
    branches: Option<&[String]>,
    checksums_usable: bool,
) -> BaselineLookup {
    let searches: Vec<Option<&str>> = match branches {
        Some(branches) => branches.iter().map(|b| Some(b.as_str())).collect(),
        None => vec![None],
    };

    // Pass one will take a baseline of either kind, so it cannot ask the server
    // to drop what is not known-clean: that is how a git-less scan reports
    // itself, and those are the ones carrying checksums.
    let found = search_baseline(config, project_name, &searches, checksums_usable, false);
    if !checksums_usable || branches.is_none() || !matches!(found, BaselineLookup::NotFound) {
        return found;
    }

    // Nothing usable came back unfiltered. A project can have more dirty trunk
    // scans than the page budget covers -- every project does, in the window
    // before any of its scans has stored checksums -- and a clean one behind
    // them is a baseline this would otherwise report as not existing. A
    // checksum baseline is already ruled out, so nothing is left for the
    // filter to wrongly exclude.
    search_baseline(config, project_name, &searches, checksums_usable, true)
}

/// One walk of the project's scans, newest first, over `searches` in order.
fn search_baseline(
    config: &Config,
    project_name: &str,
    searches: &[Option<&str>],
    checksums_usable: bool,
    require_clean: bool,
) -> BaselineLookup {
    let url = config.get_url();
    // Shared, so a project whose first candidate has pages of unusable scans
    // cannot make this walk the whole history -- but never smaller than the
    // candidate list, or the last branch in it would be one this asks about
    // only when the earlier ones answered in fewer pages than they were
    // allowed.
    let mut budget = SCAN_LOOKUP_MAX_PAGES.max(searches.len().try_into().unwrap_or(u16::MAX));

    for &branch in searches {
        let mut page = 1;
        while budget > 0 {
            budget -= 1;
            let response = match api::query_baseline_scans(
                &url,
                project_name,
                BLAST_ENGINE,
                branch,
                require_clean,
                page,
                SCAN_LOOKUP_PAGE_SIZE,
            ) {
                Ok(response) => response,
                Err(e) => {
                    // Proves nothing about this project's history, so it is a
                    // full scan rather than an error -- but it is a different
                    // answer from "trunk has no scan", so say which it was.
                    // Whatever failed is the endpoint, not the branch, so the
                    // remaining candidates would fail the same way.
                    crate::log::debug(&format!("Baseline scan lookup failed: {e}"));
                    return BaselineLookup::LookupFailed;
                }
            };

            let scans = response.scans.unwrap_or_default();
            if scans.is_empty() {
                break;
            }
            // Newest first, so the first match on this branch is the best
            // available and no later page can improve on it. Matched
            // client-side too: a backend that ignored the branch filter would
            // otherwise hand back another branch's scan.
            if let Some(scan) = branch_baseline(&scans, branch, checksums_usable) {
                return BaselineLookup::Found(scan);
            }
            if response
                .total_pages
                .is_some_and(|total| u32::from(page) >= total)
            {
                break;
            }
            page += 1;
        }
    }

    BaselineLookup::NotFound
}

/// Newest usable scan of `branch` on this page, or of any branch when `branch`
/// is `None`.
///
/// Checksums win over recency. The two kinds of baseline are not
/// interchangeable: a scan with stored checksums can be diffed against from any
/// clone, while one with only a commit needs history this clone may not have.
/// Taking whichever is newest lets a manifest-less scan from an hour ago hide
/// one from yesterday that has a manifest, and the shallow checkout that the
/// manifest was there for then falls back to a git diff it cannot run. The
/// older baseline costs a few extra files in the diff; the newer one costs the
/// whole scan.
///
/// Within the page, not across the walk: a page that offers any baseline
/// answers with one rather than reading the whole history to find out whether
/// something further back has checksums, which every scan would then pay for.
fn branch_baseline(
    scans: &[ScanResponse],
    branch: Option<&str>,
    checksums_usable: bool,
) -> Option<BaselineScan> {
    let mut usable = scans
        .iter()
        .filter(|scan| is_usable_baseline(scan, checksums_usable))
        .filter(|scan| branch.is_none_or(|branch| scan.branch.as_deref() == Some(branch)))
        .peekable();
    // Peeked, not consumed, so the search for checksums starts here too.
    let newest = usable.peek().copied();
    let scan = if checksums_usable {
        usable
            .find(|scan| has_readable_checksums(scan))
            .or(newest)?
    } else {
        newest?
    };
    Some(BaselineScan {
        id: scan.id.clone(),
        sha: scan.git_sha.clone().filter(|sha| !sha.is_empty()),
        branch: scan.branch.clone(),
        manifest_root: scan
            .file_manifest_root
            .clone()
            .filter(|root| !root.is_empty()),
        manifest_version: scan.file_manifest_version.clone(),
    })
}

/// Whether `scan` may be diffed against, given what this run can diff with.
///
/// Client-side half of the filter doghouse applies picking a baseline itself,
/// and `query_baseline_scans` asks the server for exactly these, which keeps
/// the page walk from iterating. This stays because a backend predating those
/// parameters ignores them.
///
/// Three requirements are unconditional: completed, this engine's own analysis,
/// and not a pull request. The other two depend on how the diff will be
/// measured.
///
/// A git diff is measured from the scan's *commit*, so the scan needs one, and
/// it needs to have been clean — a dirty scan's commit does not describe what
/// that scan actually analyzed, so files it had edited but not committed would
/// keep findings taken from content in neither tree. `worktree_dirty` must be
/// an explicit `false`, since never-reported is not known-clean.
///
/// A checksum diff is measured from the scan's *contents*, which is what its
/// manifest records. Neither requirement survives that: a commit is not needed
/// because nothing is looked up by one, and dirtiness does not matter because
/// the manifest describes the files as they were scanned however they got that
/// way. Insisting on either would rule out every scan uploaded without git,
/// which reports no commit, no branch and no dirty flag — the scans this
/// exists to diff against.
fn is_usable_baseline(scan: &ScanResponse, checksums_usable: bool) -> bool {
    if classify_scan_status(&scan.status) != ScanState::Completed
        || !scan.engine.eq_ignore_ascii_case(BLAST_ENGINE)
        || scan.pull_request_id.is_some()
    {
        return false;
    }
    if checksums_usable && has_readable_checksums(scan) {
        return true;
    }
    scan.worktree_dirty == Some(false) && scan.git_sha.as_deref().is_some_and(|sha| !sha.is_empty())
}

/// Whether `scan` stored checksums this client can read.
fn has_readable_checksums(scan: &ScanResponse) -> bool {
    scan.file_manifest_root
        .as_deref()
        .is_some_and(|root| !root.is_empty())
        && scan.file_manifest_version.as_deref() == Some(MANIFEST_VERSION)
}

/// Every repo-relative path differing from the baseline commit.
///
/// `include_worktree` decides what the far side of the diff is. False compares
/// two commits, which is exact when the tree is clean. True compares the
/// baseline against the index and working tree, which is what makes a dirty
/// tree scannable: a file edited but not committed differs from the baseline
/// and has to be named, or its old findings would be carried forward over
/// content nothing analyzed. Untracked files count for the same reason — the
/// archive contains them.
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
fn changed_files_since(
    repo: &Repository,
    base_sha: &str,
    head_sha: &str,
    include_worktree: bool,
) -> Result<Vec<String>, String> {
    let base_tree = commit_tree(repo, base_sha).map_err(|e| {
        format!(
            "commit {}, the one the last scan covered, is not in this clone ({e}). A shallow \
             clone cannot diff against it — fetch more history (for example `actions/checkout` \
             with `fetch-depth: 0`) to scan incrementally",
            short_sha(base_sha)
        )
    })?;

    let diff = if include_worktree {
        let mut options = git2::DiffOptions::new();
        options.include_untracked(true).recurse_untracked_dirs(true);
        repo.diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
    } else {
        let head_tree = commit_tree(repo, head_sha)
            .map_err(|e| format!("commit {} could not be read ({e})", short_sha(head_sha)))?;
        repo.diff_tree_to_tree(Some(&base_tree), Some(&head_tree), None)
    }
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
            file_manifest_root: None,
            file_manifest_version: None,
        }
    }

    /// A scan uploaded with no git at all: no branch, no commit, no dirty
    /// flag. Only its stored checksums make it a baseline.
    fn scan_without_git(id: &str) -> ScanResponse {
        let mut scan = scan("main", "unused");
        scan.id = id.to_string();
        scan.branch = None;
        scan.git_sha = None;
        scan.worktree_dirty = None;
        with_checksums(scan)
    }

    fn with_checksums(mut scan: ScanResponse) -> ScanResponse {
        scan.file_manifest_root = Some("a".repeat(64));
        scan.file_manifest_version = Some(MANIFEST_VERSION.to_string());
        scan
    }

    /// The sha of the scan `branch_baseline` picked, for the cases that only
    /// care which one it was. Checksums off, so this is the git-diff rule.
    fn baseline_sha(scans: &[ScanResponse], branch: &str) -> Option<String> {
        branch_baseline(scans, Some(branch), false).and_then(|scan| scan.sha)
    }

    #[test]
    fn short_sha_shortens_a_non_ascii_value_instead_of_panicking() {
        // The API supplies git_sha; a malformed one must not kill the scan.
        assert_eq!(short_sha("0123456789abcdef"), "0123456");
        assert_eq!(short_sha("abc"), "abc");
        assert_eq!(short_sha(""), "");
        assert_eq!(short_sha("ααααααααα"), "ααααααα");
    }

    fn plan(changed: &[&str]) -> IncrementalPlan {
        IncrementalPlan {
            base: BaselineRef::Commit("abc123".to_string()),
            changed_files: changed.iter().map(|f| f.to_string()).collect(),
            covers_worktree: false,
        }
    }

    #[test]
    fn including_adds_force_included_files_the_diff_left_out() {
        let forced = vec![
            "src/app.py".to_string(),
            "vendor/mylib/Payments.java".to_string(),
        ];

        let widened = plan(&["src/app.py"])
            .including(&forced)
            .expect("still worth it");

        assert_eq!(
            widened.changed_files,
            vec![
                "src/app.py".to_string(),
                "vendor/mylib/Payments.java".to_string()
            ]
        );
    }

    #[test]
    fn including_nothing_new_leaves_the_plan_alone() {
        let original = plan(&["src/app.py"]);
        assert_eq!(
            original.clone().including(&["src/app.py".to_string()]),
            Some(original)
        );
    }

    #[test]
    fn including_too_many_files_falls_back_to_a_full_scan() {
        let forced: Vec<String> = (0..=MAX_CHANGED_FILES)
            .map(|i| format!("v/{i}.js"))
            .collect();
        assert_eq!(plan(&["src/app.py"]).including(&forced), None);
    }

    #[test]
    fn a_completed_clean_blast_scan_is_a_baseline_for_either_kind_of_diff() {
        assert!(is_usable_baseline(&scan("main", "abc"), false));
        assert!(is_usable_baseline(&scan("main", "abc"), true));
    }

    #[test]
    fn what_no_diff_can_use_is_rejected_whichever_one_is_available() {
        // The server refuses each of these too, so diffing against them narrows
        // a scan the server then widens.
        let mut running = with_checksums(scan("main", "abc"));
        running.status = "processing".to_string();

        let mut third_party = with_checksums(scan("main", "abc"));
        third_party.engine = "semgrep".to_string();

        let mut pr = with_checksums(scan("main", "abc"));
        pr.pull_request_id = Some("42".to_string());

        for rejected in [running, third_party, pr] {
            assert!(!is_usable_baseline(&rejected, false));
            assert!(!is_usable_baseline(&rejected, true));
        }
    }

    #[test]
    fn a_git_diff_needs_a_commit_that_was_clean_when_it_was_scanned() {
        // A dirty scan's commit does not describe what it analyzed, so files it
        // had edited but not committed would keep findings taken from content
        // in neither tree.
        let mut dirty = scan("main", "abc");
        dirty.worktree_dirty = Some(true);
        assert!(!is_usable_baseline(&dirty, false));

        // Never reported is not known clean.
        let mut unknown = scan("main", "abc");
        unknown.worktree_dirty = None;
        assert!(!is_usable_baseline(&unknown, false));

        let mut no_commit = scan("main", "abc");
        no_commit.git_sha = None;
        assert!(!is_usable_baseline(&no_commit, false));
    }

    #[test]
    fn a_checksum_diff_needs_neither_a_commit_nor_a_clean_one() {
        // Its manifest records the files as they were scanned, so how they came
        // to be that way changes nothing -- and insisting otherwise would rule
        // out every scan uploaded without git, which is what this is for.
        let mut dirty = with_checksums(scan("main", "abc"));
        dirty.worktree_dirty = Some(true);
        assert!(is_usable_baseline(&dirty, true));
        assert!(!is_usable_baseline(&dirty, false));

        assert!(is_usable_baseline(&scan_without_git("no-git"), true));
        assert!(!is_usable_baseline(&scan_without_git("no-git"), false));
    }

    #[test]
    fn checksums_this_client_cannot_read_do_not_make_a_scan_a_baseline() {
        let mut future = scan_without_git("no-git");
        future.file_manifest_version = Some("99".to_string());
        assert!(!is_usable_baseline(&future, true));

        let mut empty_root = scan_without_git("no-git");
        empty_root.file_manifest_root = Some(String::new());
        assert!(!is_usable_baseline(&empty_root, true));
    }

    #[test]
    fn a_clone_with_no_trunk_to_name_accepts_a_scan_that_names_no_branch() {
        // Every scan of a project with no git records no branch, so asking for
        // one would rule out the whole project's history.
        let scans = vec![scan_without_git("newest"), scan_without_git("older")];

        let picked = branch_baseline(&scans, None, true).expect("a baseline");

        assert_eq!(picked.id, "newest");
        assert_eq!(picked.sha, None);
        assert_eq!(picked.describe(), "last scan of this project");
    }

    #[test]
    fn the_newest_usable_scan_on_the_branch_wins() {
        let scans = vec![scan("main", "newest"), scan("main", "older")];
        assert_eq!(baseline_sha(&scans, "main").as_deref(), Some("newest"));
    }

    /// The two kinds of baseline are not interchangeable. A scan with stored
    /// checksums can be diffed against from any clone; one with only a commit
    /// needs history this clone may not have. Taking whichever is newest lets a
    /// manifest-less scan hide one that has a manifest, and the shallow
    /// checkout the manifest was there for then falls back to a git diff it
    /// cannot run.
    #[test]
    fn a_baseline_with_checksums_beats_a_newer_one_without() {
        let scans = vec![
            scan("main", "newest"),
            with_checksums(scan("main", "has-checksums")),
            scan("main", "oldest"),
        ];

        let picked = branch_baseline(&scans, Some("main"), true).expect("a baseline");

        assert_eq!(picked.sha.as_deref(), Some("has-checksums"));
    }

    #[test]
    fn with_no_checksums_anywhere_the_newest_scan_is_still_taken() {
        // Nothing to prefer, and refusing here would cost a git diff that this
        // clone may well be able to run.
        let scans = vec![scan("main", "newest"), scan("main", "older")];

        let picked = branch_baseline(&scans, Some("main"), true).expect("a baseline");

        assert_eq!(picked.sha.as_deref(), Some("newest"));
    }

    #[test]
    fn a_scan_on_another_branch_is_never_the_baseline() {
        // A backend that ignored the branch filter would otherwise hand back a
        // feature branch's scan as trunk's.
        let scans = vec![scan("feature", "on-feature")];
        assert_eq!(baseline_sha(&scans, "main"), None);
    }

    #[test]
    fn unusable_scans_on_the_branch_are_skipped() {
        let mut dirty = scan("main", "dirty");
        dirty.worktree_dirty = Some(true);
        let scans = vec![dirty, scan("main", "clean")];
        assert_eq!(baseline_sha(&scans, "main").as_deref(), Some("clean"));
    }

    #[test]
    fn a_page_of_nothing_usable_yields_no_baseline() {
        let mut pr = scan("main", "pr");
        pr.pull_request_id = Some("42".to_string());
        assert_eq!(baseline_sha(&[pr], "main"), None);
    }

    #[test]
    fn trunk_candidates_fall_back_to_main_then_master() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(dir.path()).expect("init");
        // No origin/HEAD: single-branch and actions/checkout clones have none.
        assert_eq!(default_branch(&repo), None);
        assert_eq!(baseline_branches(&repo, None), vec!["main", "master"]);
    }

    #[test]
    fn the_branch_being_scanned_is_asked_about_before_trunk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(dir.path()).expect("init");
        assert_eq!(
            baseline_branches(&repo, Some("release/24.4")),
            vec!["release/24.4", "main", "master"]
        );
    }

    /// The ordinary case: scanning trunk itself, where the branch being scanned
    /// and the branch we would fall back to are the same one.
    #[test]
    fn scanning_trunk_does_not_ask_about_it_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(dir.path()).expect("init");
        assert_eq!(
            baseline_branches(&repo, Some("main")),
            vec!["main", "master"]
        );
        assert_eq!(
            baseline_branches(&repo, Some("master")),
            vec!["master", "main"]
        );
    }

    #[test]
    fn a_recorded_default_branch_leads_and_is_not_repeated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(dir.path()).expect("init");
        repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/trunk",
            true,
            "test",
        )
        .expect("set origin/HEAD");

        assert_eq!(default_branch(&repo).as_deref(), Some("trunk"));
        assert_eq!(
            baseline_branches(&repo, None),
            vec!["trunk", "main", "master"]
        );
        assert_eq!(
            baseline_branches(&repo, Some("trunk")),
            vec!["trunk", "main", "master"]
        );
        assert_eq!(
            baseline_branches(&repo, Some("feature")),
            vec!["feature", "trunk", "main", "master"]
        );

        repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
            true,
            "test",
        )
        .expect("set origin/HEAD");
        assert_eq!(baseline_branches(&repo, None), vec!["main", "master"]);
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
        let files = changed_files_since(&repo, &base, &head, false).expect("diff");
        // Deleted file must be listed, else its findings carry into a tree that
        // no longer holds it.
        assert_eq!(files, vec!["added.txt", "edit.txt", "gone.txt"]);
    }

    #[test]
    fn a_commit_diffed_against_itself_reports_nothing_changed() {
        let (_dir, repo, _base, head) = repo_with_history();
        assert!(changed_files_since(&repo, &head, &head, false)
            .expect("diff")
            .is_empty());
    }

    #[test]
    fn a_commit_range_diff_cannot_see_uncommitted_work() {
        // Why a dirty tree may not use one: keep.txt differs from what will be
        // uploaded, yet the diff does not name it, so its findings would be
        // carried forward over content nothing analyzed.
        let (dir, repo, _base, head) = repo_with_history();
        fs::write(dir.path().join("keep.txt"), "edited").expect("edit");
        fs::write(dir.path().join("brand-new.txt"), "new").expect("add");

        let committed = changed_files_since(&repo, &head, &head, false).expect("diff");
        assert!(committed.is_empty());
    }

    #[test]
    fn a_worktree_diff_names_edited_and_untracked_files() {
        let (dir, repo, _base, head) = repo_with_history();
        fs::write(dir.path().join("keep.txt"), "edited").expect("edit");
        fs::write(dir.path().join("brand-new.txt"), "new").expect("add");

        let files = changed_files_since(&repo, &head, &head, true).expect("diff");

        assert_eq!(files, vec!["brand-new.txt", "keep.txt"]);
    }

    #[test]
    fn a_worktree_diff_still_spans_the_commits_behind_it() {
        // The baseline is a commit, so committed changes since it count too --
        // the working tree is the far side of the diff, not the whole of it.
        let (dir, repo, base, _head) = repo_with_history();
        fs::write(dir.path().join("keep.txt"), "edited").expect("edit");

        let files = changed_files_since(&repo, &base, "unused", true).expect("diff");

        assert_eq!(files, vec!["added.txt", "edit.txt", "gone.txt", "keep.txt"]);
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

        let err = changed_files_since(&repo, &before.to_string(), &after.to_string(), false)
            .expect_err("a moved submodule must refuse the diff");

        assert!(err.contains("submodule vendor"), "{err}");
    }

    #[test]
    fn a_base_commit_this_clone_does_not_have_is_reported_not_panicked() {
        let (_dir, repo, _base, head) = repo_with_history();
        let err = changed_files_since(&repo, &"0".repeat(40), &head, false)
            .expect_err("unknown base must fail");
        assert!(err.contains("shallow clone"), "{err}");
    }
}
