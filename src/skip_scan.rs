//! `--skip-if-commit-scanned-recently`: reuse a recent scan of the current
//! commit instead of starting a duplicate one.
//!
//! Pipelines that re-run on an unchanged commit (a retried stage, a manual
//! re-run, a promotion job) pay for a full scan that can only produce the
//! results the previous run already produced. Skipping the scan itself is only
//! half the job: the run still has to gate on `--block-on` and still has to
//! emit `--out-file`, so the reused scan takes the new scan's place for the
//! rest of the command rather than short-circuiting it.
//!
//! Recency is a policy, not a technicality — the same commit scanned last week
//! predates whatever advisories landed since, so a scan is only reusable
//! inside the window (24h by default). `--ignore-dirty-worktree` is the
//! explicit override for reuse only: a dirty current tree, or a prior scan
//! that recorded `worktree_dirty=true`, can still stand in for this commit.
//! A prior scan that never reported the flag (`None`) is still rejected —
//! unknown scope is not dirtiness. A new scan still reports the real dirty
//! status.
//!
//! One scan may only stand in for another when it answers the same question,
//! which is a stricter test than "same commit". Doghouse already settled what
//! that means for its own server-side dedupe (`ScanManager._find_reusable_scan`):
//! same commit, not a pull-request scan, an explicitly clean worktree, and
//! matching scan configuration and policies. The checks here are the client-side
//! half of that rule, and where the API cannot yet prove the match — the scan's
//! configured scan types and target policies are not exposed on any read
//! endpoint — the flag refuses the run rather than guessing (see `main.rs`,
//! where `--scan-type`/`--policy` conflict with it).
//!
//! `--exclude` is the one narrowing flag that only warns. It is typically a
//! fixed line in a pipeline template rather than a per-run choice, and reusing a
//! wider scan can only over-report, never miss a finding — so the run continues
//! and says which files the gate may cover after all.

use crate::config::Config;
use crate::scanners::blast::{classify_scan_status, format_scan_warnings, ScanState};
use crate::utils;
use crate::utils::api::ScanResponse;
use chrono::{DateTime, Utc};
use std::time::Duration;

/// How far back a prior scan may have run and still be reused.
pub const DEFAULT_WINDOW: &str = "24h";

/// How many of the commit's scans to read at a time, newest first.
const SCAN_LOOKUP_PAGE_SIZE: u16 = 30;

/// Backstop on pages walked. The window normally ends the search first (the
/// list is newest first, so an out-of-window page tail means there is nothing
/// left to find); this bounds the remaining case of one commit with more scans
/// inside the window than fit on a page.
const SCAN_LOOKUP_MAX_PAGES: u16 = 3;

/// The engine every blast scan carries, whoever started it — CLI, platform
/// integration, or scheduled run. An uploaded third-party report carries its
/// own scanner's name and cannot stand in for `corgea scan blast`.
const BLAST_ENGINE: &str = "corgea-blast";

/// Grep-able signal for pipelines: printed exactly once per run whenever the
/// flag is on, so a step can branch on whether a scan actually happened.
const SKIPPED_MARKER: &str = "CORGEA_SCAN_SKIPPED";

/// The `--skip-if-commit-scanned-recently` request, with the window already
/// validated.
#[derive(Debug, Clone)]
pub struct SkipRecentScan {
    window: Duration,
    /// The window as the user wrote it, so messages echo their own units.
    label: String,
}

impl SkipRecentScan {
    /// Build from the raw `--scanned-within` value, defaulting when absent.
    pub fn new(scanned_within: Option<&str>) -> Result<Self, String> {
        let label = scanned_within.unwrap_or(DEFAULT_WINDOW).trim().to_string();
        Ok(Self {
            window: parse_window(&label)?,
            label,
        })
    }
}

/// Parse a `--scanned-within` value: `90s`, `30m`, `24h`, `7d`. A bare number
/// is read as hours, matching the unit the default is expressed in.
pub fn parse_window(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    let invalid = || {
        format!(
            "Invalid --scanned-within value '{}'. Expected a positive duration such as 30m, 24h, or 7d.",
            raw
        )
    };
    let (digits, seconds_per_unit) = match raw.chars().last() {
        Some('s') => (&raw[..raw.len() - 1], 1),
        Some('m') => (&raw[..raw.len() - 1], 60),
        Some('h') => (&raw[..raw.len() - 1], 60 * 60),
        Some('d') => (&raw[..raw.len() - 1], 24 * 60 * 60),
        Some(c) if c.is_ascii_digit() => (raw, 60 * 60),
        _ => return Err(invalid()),
    };
    let amount: u64 = digits.parse().map_err(|_| invalid())?;
    if amount == 0 {
        return Err(invalid());
    }
    amount
        .checked_mul(seconds_per_unit)
        .map(Duration::from_secs)
        .ok_or_else(invalid)
}

/// The scan to report on instead of starting a new one, or `None` to scan.
///
/// Every `None` is a decision to do the more expensive, more correct thing, so
/// a lookup failure, an unreadable timestamp, or a dirty worktree all land
/// here rather than skipping a scan on incomplete information. `--ignore-dirty-worktree`
/// is the exception for known dirtiness: a dirty current tree, or a prior scan
/// that recorded `worktree_dirty=true`, can still be reused. `None` is still
/// rejected. The one hard
/// failure is an unresolvable commit: the flag asks a question about the
/// commit, and without one there is no question to answer.
pub fn resolve_reusable_scan(
    config: &Config,
    project_name: &str,
    skip: &SkipRecentScan,
    exclude: Option<&str>,
    ignore_dirty_worktree: bool,
) -> Option<ScanResponse> {
    // Dirtiness here is what `git status` reports, the same signal the upload
    // sends and the same one the user can check for themselves before asking
    // why a scan ran.
    let commit = utils::generic::get_repo_info_for_scan("./")
        .ok()
        .flatten()
        .and_then(|info| Some((info.sha?, info.dirty)));
    let Some((sha, worktree_dirty)) = commit else {
        log::error!(
            "--skip-if-commit-scanned-recently needs the commit that is being scanned, but no git commit could be resolved here.\n\
             Run it from the root of a git repository with at least one commit, or drop the flag."
        );
        std::process::exit(1);
    };
    let short = short_sha(&sha);

    if worktree_dirty {
        if ignore_dirty_worktree {
            println!(
                "Ignoring dirty worktree (--ignore-dirty-worktree); treating this as a scan of commit {}.",
                short
            );
        } else {
            println!(
                "Working tree does not match commit {} exactly (git status reports uncommitted changes), so no scan of that commit describes what would be scanned here - running a new scan.",
                short
            );
            print_skipped_marker(None);
            return None;
        }
    }

    println!(
        "Checking Corgea for a scan of commit {} in project '{}' from the last {}...",
        short, project_name, skip.label
    );

    let found = match find_reusable_scan(
        config,
        project_name,
        &sha,
        skip.window,
        Utc::now(),
        ignore_dirty_worktree,
    ) {
        Ok(found) => found,
        Err(e) => {
            log::warn!(
                "Could not check whether commit {} was already scanned: {}. Running a new scan.",
                short,
                e
            );
            print_skipped_marker(None);
            return None;
        }
    };

    let Some((scan, age)) = found else {
        println!(
            "No reusable scan of commit {} in the last {}; running a new scan.",
            short, skip.label
        );
        print_skipped_marker(None);
        return None;
    };

    if let Err(reason) = confirm_reusable_scan(config, &scan.id) {
        log::warn!(
            "Not reusing scan {}: {}. Running a new scan.",
            scan.id,
            reason
        );
        print_skipped_marker(None);
        return None;
    }

    println!(
        "Skipping scan: commit {} was already scanned {} ago by scan {}.",
        short, age, scan.id
    );
    println!("Reporting on that scan instead - blocking rules and report output are unchanged.");
    // A reusable scan is one of the whole commit, and an `--exclude` upload is
    // recorded dirty, so a reused scan was never narrowed the way this run asks.
    // The gate below can therefore fail on a file this command line excludes,
    // which is worth saying out loud rather than leaving to be discovered.
    if let Some(exclude) = exclude {
        log::warn!(
            "Scan {} covers the whole commit, so it was not narrowed by --exclude '{}'. The results and gate below can include files this run would have skipped.",
            scan.id,
            exclude
        );
    }
    print_skipped_marker(Some(&scan.id));
    Some(scan)
}

/// Walk the commit's scans, newest first, for one that can stand in for a fresh
/// scan. `Err` is a lookup failure, `Ok(None)` a clean miss.
fn find_reusable_scan(
    config: &Config,
    project_name: &str,
    sha: &str,
    window: Duration,
    now: DateTime<Utc>,
    ignore_dirty_worktree: bool,
) -> Result<Option<(ScanResponse, String)>, String> {
    let mut page = 1;
    loop {
        let response = utils::api::query_scans_for_commit(
            &config.get_url(),
            project_name,
            sha,
            page,
            SCAN_LOOKUP_PAGE_SIZE,
        )
        .map_err(|e| e.to_string())?;
        let scans = response.scans.unwrap_or_default();
        if scans.is_empty() {
            return Ok(None);
        }
        if let Some(reusable) =
            select_reusable_scan(&scans, sha, now, window, ignore_dirty_worktree)
        {
            return Ok(Some((reusable.scan.clone(), reusable.age)));
        }
        // Newest first, so a page that ends outside the window is the end of the
        // search: everything after it is older still.
        if page_ends_outside_window(&scans, now, window) {
            return Ok(None);
        }
        // A page holding no scan of this commit means the server is not
        // filtering on `sha` (a backend predating that parameter answers with
        // the whole project), so further pages only read other commits' scans.
        if !scans.iter().any(|scan| scan_matches_commit(scan, sha)) {
            return Ok(None);
        }
        if page >= response.total_pages.unwrap_or(1) as u16 || page >= SCAN_LOOKUP_MAX_PAGES {
            return Ok(None);
        }
        page += 1;
    }
}

/// Confirm the scan we intend to reuse against `GET /scan/{id}`.
///
/// The scan list carries no `scan_errors`, so there a scan that finished with a
/// scanner's results missing is indistinguishable from a clean one. A fresh scan
/// says so out loud and the operator can weigh it; a reused one would gate
/// silently on findings it has no reason to believe are complete. Since the
/// alternative here is simply to scan — which may also clear a transient failure
/// — a degraded scan is not reused at all.
///
/// One read, on the one scan we mean to reuse: a candidate rejected here sends
/// the run to a real scan rather than to the next-oldest scan, because a commit
/// whose recent scans are all degraded wants a fresh scan anyway.
fn confirm_reusable_scan(config: &Config, scan_id: &str) -> Result<(), String> {
    let scan = utils::api::get_scan(&config.get_url(), scan_id, None).map_err(|e| e.to_string())?;
    if classify_scan_status(&scan.status) != ScanState::Completed {
        return Err(format!("its status is now '{}'", scan.status));
    }
    if let Some(warnings) = format_scan_warnings(&scan) {
        return Err(format!("it is missing some scanner results.\n{}", warnings));
    }
    Ok(())
}

/// `CORGEA_SCAN_SKIPPED=true|false`, plus the reused scan id when there is one.
/// Shell-assignment shaped so a pipeline can `eval` or `grep` it.
fn print_skipped_marker(reused_scan_id: Option<&str>) {
    match reused_scan_id {
        Some(scan_id) => {
            println!("{}=true", SKIPPED_MARKER);
            println!("CORGEA_SCAN_ID={}", scan_id);
        }
        None => println!("{}=false", SKIPPED_MARKER),
    }
}

pub struct ReusableScan<'a> {
    pub scan: &'a ScanResponse,
    /// How long ago it ran, already formatted for the terminal.
    pub age: String,
}

/// The newest scan that can stand in for a fresh scan of `sha`.
///
/// `scans` arrive newest first and are already filtered server-side, but the
/// checks are repeated here: a backend that predates the `sha` filter answers
/// with the project's scans at every commit, and acting on that would skip a
/// scan of one commit because a different commit was scanned.
pub fn select_reusable_scan<'a>(
    scans: &'a [ScanResponse],
    sha: &str,
    now: DateTime<Utc>,
    window: Duration,
    ignore_dirty_worktree: bool,
) -> Option<ReusableScan<'a>> {
    for scan in scans {
        match scan_age_if_reusable(scan, sha, now, window, ignore_dirty_worktree) {
            Ok(age) => {
                return Some(ReusableScan {
                    scan,
                    age: format_age(age),
                })
            }
            Err(reason) => log::debug!("Not reusing scan {}: {}", scan.id, reason),
        }
    }
    None
}

/// True when `scan` records exactly the commit being scanned.
fn scan_matches_commit(scan: &ScanResponse, sha: &str) -> bool {
    scan.git_sha
        .as_deref()
        .is_some_and(|scan_sha| scan_sha.eq_ignore_ascii_case(sha))
}

/// How long ago `scan` ran, or why it cannot stand in for a new scan.
fn scan_age_if_reusable(
    scan: &ScanResponse,
    sha: &str,
    now: DateTime<Utc>,
    window: Duration,
    ignore_dirty_worktree: bool,
) -> Result<Duration, String> {
    if !scan_matches_commit(scan, sha) {
        return match scan.git_sha.as_deref() {
            Some(scan_sha) => Err(format!("it scanned commit {}", short_sha(scan_sha))),
            None => Err("it records no commit".to_string()),
        };
    }
    // A scan that failed has no results to gate on, and one still running has
    // none yet; both mean this run has to do the scan itself.
    if classify_scan_status(&scan.status) != ScanState::Completed {
        return Err(format!("its status is '{}'", scan.status));
    }
    if !scan.engine.eq_ignore_ascii_case(BLAST_ENGINE) {
        return Err(format!("it came from the '{}' engine", scan.engine));
    }
    // A pull-request scan answers a question about a proposed merge, and may be
    // scoped to the diff; doghouse draws the same line for its own dedupe and
    // for "which scan represents full project state".
    if let Some(pull_request_id) = scan.pull_request_id.as_deref() {
        return Err(format!("it scanned pull request {}", pull_request_id));
    }
    // Only an explicit `false` is a clean tree. `None` means the scan never
    // reported the flag, and unknown is not clean: doghouse applies the same
    // rule to its own dedupe ("only explicit clean may dedupe on SHA/PR"),
    // platform and scheduled scans do record `false`, and the scans that do not
    // include the partial `--target`/`--exclude` uploads of older CLIs — which
    // this run has no way to tell apart from whole-commit ones.
    // `--ignore-dirty-worktree` may reuse a known-dirty scan (`Some(true)`),
    // but not `None`: unknown scope is not dirtiness.
    match scan.worktree_dirty {
        Some(false) => {}
        Some(true) if ignore_dirty_worktree => {}
        Some(true) => {
            return Err("it scanned a worktree with uncommitted changes".to_string());
        }
        None => {
            return Err("it did not report whether its worktree was clean".to_string());
        }
    }
    let created_at = parse_timestamp(&scan.created_at)
        .ok_or_else(|| format!("its timestamp '{}' could not be read", scan.created_at))?;
    let age = age_since(created_at, now);
    if age > window {
        return Err(format!(
            "it ran {} ago, outside the window",
            format_age(age)
        ));
    }
    Ok(age)
}

/// Whether this page's oldest scan already falls outside the window, which — the
/// list being newest first — means no later page can hold a reusable scan.
/// An unreadable timestamp proves nothing, so it does not end the walk.
fn page_ends_outside_window(scans: &[ScanResponse], now: DateTime<Utc>, window: Duration) -> bool {
    scans
        .last()
        .and_then(|scan| parse_timestamp(&scan.created_at))
        .is_some_and(|created_at| age_since(created_at, now) > window)
}

/// How long ago `created_at` was. A timestamp in the future is clock skew, not
/// an old scan, so it reads as brand new rather than underflowing.
fn age_since(created_at: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    now.signed_duration_since(created_at)
        .to_std()
        .unwrap_or(Duration::ZERO)
}

/// Timestamps arrive as RFC 3339 from the scan list, but Django can also
/// serialize a naive datetime, which the RFC 3339 parser rejects.
fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
        return Some(parsed.with_timezone(&Utc));
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, format) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
        }
    }
    None
}

/// Two units at most: `3d 4h`, `2h 30m`, `45m`, `12s`.
fn format_age(age: Duration) -> String {
    let seconds = age.as_secs();
    let (days, hours, minutes) = (
        seconds / 86_400,
        (seconds % 86_400) / 3600,
        (seconds % 3600) / 60,
    );
    if days > 0 {
        return format!("{}d {}h", days, hours);
    }
    if hours > 0 {
        return format!("{}h {}m", hours, minutes);
    }
    if minutes > 0 {
        return format!("{}m", minutes);
    }
    format!("{}s", seconds)
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

    fn scan(id: &str, status: &str, sha: Option<&str>, created_at: &str) -> ScanResponse {
        ScanResponse {
            id: id.to_string(),
            project: "proj".to_string(),
            repo: None,
            branch: None,
            status: status.to_string(),
            engine: "corgea-blast".to_string(),
            created_at: created_at.to_string(),
            git_sha: sha.map(|s| s.to_string()),
            worktree_dirty: Some(false),
            pull_request_id: None,
            metadata: None,
            failed_reason: None,
            scan_errors: vec![],
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    const SHA: &str = "1a2b3c4d5e6f70819293a4b5c6d7e8f901234567";
    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    #[test]
    fn window_accepts_each_unit_and_defaults_a_bare_number_to_hours() {
        assert_eq!(parse_window("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_window("30m").unwrap(), Duration::from_secs(1_800));
        assert_eq!(parse_window("24h").unwrap(), DAY);
        assert_eq!(parse_window("7d").unwrap(), Duration::from_secs(7 * 86_400));
        assert_eq!(
            parse_window(" 12 ").unwrap(),
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(parse_window(DEFAULT_WINDOW).unwrap(), DAY);
    }

    #[test]
    fn window_rejects_values_that_would_silently_disable_the_check() {
        // A zero or unparseable window must not read as "reuse anything" or
        // "reuse nothing"; the user gets told instead.
        for raw in ["0h", "0", "", "h", "-1h", "1.5h", "24 hours", "abc"] {
            assert!(parse_window(raw).is_err(), "{raw} should be rejected");
        }
    }

    #[test]
    fn reuses_the_newest_completed_scan_of_this_commit() {
        let scans = vec![
            scan("newer", "complete", Some(SHA), "2026-01-01T21:00:00Z"),
            scan("older", "complete", Some(SHA), "2026-01-01T12:00:00Z"),
        ];
        let reusable =
            select_reusable_scan(&scans, SHA, now(), DAY, false).expect("expected a reuse");
        assert_eq!(reusable.scan.id, "newer");
        assert_eq!(reusable.age, "3h 0m");
    }

    #[test]
    fn falls_through_to_an_older_scan_when_the_newest_cannot_be_reused() {
        // A retried pipeline whose newest attempt failed still has the earlier
        // good scan to report on.
        let scans = vec![
            scan("failed", "incomplete", Some(SHA), "2026-01-01T23:00:00Z"),
            scan("good", "complete", Some(SHA), "2026-01-01T22:00:00Z"),
        ];
        let reusable =
            select_reusable_scan(&scans, SHA, now(), DAY, false).expect("expected a reuse");
        assert_eq!(reusable.scan.id, "good");
    }

    #[test]
    fn running_and_failed_scans_are_not_reusable() {
        for status in ["processing", "scanning", "incomplete", "failed", ""] {
            let scans = vec![scan("s", status, Some(SHA), "2026-01-01T23:00:00Z")];
            assert!(
                select_reusable_scan(&scans, SHA, now(), DAY, false).is_none(),
                "status {status} must not be reused"
            );
        }
    }

    #[test]
    fn scans_of_another_commit_are_never_reused() {
        // The guard that matters against a backend that ignores ?sha= and
        // answers with every scan of the project.
        let other = "ffffffffffffffffffffffffffffffffffffffff";
        let scans = vec![
            scan(
                "other-commit",
                "complete",
                Some(other),
                "2026-01-01T23:00:00Z",
            ),
            scan("no-commit", "complete", None, "2026-01-01T23:00:00Z"),
        ];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY, false).is_none());
    }

    #[test]
    fn commit_comparison_ignores_sha_casing() {
        let scans = vec![scan(
            "s",
            "complete",
            Some(&SHA.to_uppercase()),
            "2026-01-01T23:00:00Z",
        )];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY, false).is_some());
    }

    #[test]
    fn scans_outside_the_window_are_not_reused() {
        // The point of the window: the code is unchanged, but the advisories
        // it is scanned against are not.
        let scans = vec![scan("stale", "complete", Some(SHA), "2025-12-30T00:00:00Z")];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY, false).is_none());
        // A shorter window is what makes a scan from this morning stale.
        let scans = vec![scan(
            "morning",
            "complete",
            Some(SHA),
            "2026-01-01T20:00:00Z",
        )];
        assert!(
            select_reusable_scan(&scans, SHA, now(), Duration::from_secs(3_600), false).is_none()
        );
    }

    #[test]
    fn a_scan_exactly_at_the_window_edge_is_still_reusable() {
        let scans = vec![scan("edge", "complete", Some(SHA), "2026-01-01T00:00:00Z")];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY, false).is_some());
    }

    #[test]
    fn scans_of_a_dirty_worktree_are_not_reused() {
        // Those results describe someone's uncommitted edits, not this commit.
        let mut dirty = scan("dirty", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        dirty.worktree_dirty = Some(true);
        assert!(select_reusable_scan(&[dirty], SHA, now(), DAY, false).is_none());
    }

    #[test]
    fn ignore_dirty_worktree_reuses_a_dirty_prior_scan() {
        let mut dirty = scan("dirty", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        dirty.worktree_dirty = Some(true);
        assert!(select_reusable_scan(&[dirty], SHA, now(), DAY, true).is_some());
    }

    #[test]
    fn ignore_dirty_worktree_still_rejects_a_scan_that_never_reported_dirtiness() {
        // `None` is unknown scope (legacy / partial uploads), not known dirty.
        let mut unknown = scan("unknown", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        unknown.worktree_dirty = None;
        assert!(select_reusable_scan(&[unknown], SHA, now(), DAY, true).is_none());
    }

    #[test]
    fn scans_that_never_reported_dirtiness_are_not_reused() {
        // `None` says the client did not report, not that the tree was clean.
        // Platform and scheduled scans do record `false`, so what this rejects
        // is mainly the partial `--target` uploads of older CLIs, which are
        // indistinguishable from whole-commit ones from here.
        let mut unknown = scan("unknown", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        unknown.worktree_dirty = None;
        assert!(select_reusable_scan(&[unknown], SHA, now(), DAY, false).is_none());
    }

    #[test]
    fn pull_request_scans_are_not_reused() {
        // A PR scan answers a question about a proposed merge and may be scoped
        // to the diff, so it cannot stand in for a branch build of the commit.
        let mut pr_scan = scan("pr", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        pr_scan.pull_request_id = Some("42".to_string());
        assert!(select_reusable_scan(&[pr_scan], SHA, now(), DAY, false).is_none());
    }

    #[test]
    fn scans_from_another_engine_are_not_reused() {
        // An uploaded third-party report covers whatever that scanner found,
        // which is not what `corgea scan blast` was asked to produce.
        let mut semgrep = scan("semgrep", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        semgrep.engine = "semgrep".to_string();
        assert!(select_reusable_scan(&[semgrep], SHA, now(), DAY, false).is_none());
        // Every blast scan carries this engine, whoever started it.
        let mut blast = scan("blast", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        blast.engine = BLAST_ENGINE.to_uppercase();
        assert!(select_reusable_scan(&[blast], SHA, now(), DAY, false).is_some());
    }

    #[test]
    fn unreadable_timestamps_do_not_skip_the_scan() {
        let scans = vec![scan("bad-time", "complete", Some(SHA), "not a timestamp")];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY, false).is_none());
    }

    #[test]
    fn timestamps_parse_in_every_shape_the_api_emits() {
        for raw in [
            "2026-01-01T23:00:00Z",
            "2026-01-01T23:00:00.123456Z",
            "2026-01-01T23:00:00+00:00",
            "2026-01-01T18:00:00-05:00",
            "2026-01-01T23:00:00",
            "2026-01-01 23:00:00",
        ] {
            let scans = vec![scan("s", "complete", Some(SHA), raw)];
            assert!(
                select_reusable_scan(&scans, SHA, now(), DAY, false).is_some(),
                "{raw} should parse"
            );
        }
    }

    #[test]
    fn a_scan_stamped_in_the_future_reads_as_brand_new() {
        // Clock skew between the runner and the platform must not underflow
        // into an age older than any window.
        let scans = vec![scan(
            "skewed",
            "complete",
            Some(SHA),
            "2026-01-02T01:00:00Z",
        )];
        let reusable =
            select_reusable_scan(&scans, SHA, now(), DAY, false).expect("expected a reuse");
        assert_eq!(reusable.age, "0s");
    }

    #[test]
    fn empty_scan_list_reuses_nothing() {
        assert!(select_reusable_scan(&[], SHA, now(), DAY, false).is_none());
    }

    #[test]
    fn a_page_ending_inside_the_window_leaves_more_to_search() {
        // Newest first: while the page's oldest scan is still inside the window,
        // a reusable scan can sit on the next page. Anything else would make a
        // commit with more than a page of scans quietly unreusable.
        let scans = vec![
            scan("a", "incomplete", Some(SHA), "2026-01-01T23:00:00Z"),
            scan("b", "incomplete", Some(SHA), "2026-01-01T22:00:00Z"),
        ];
        assert!(!page_ends_outside_window(&scans, now(), DAY));
    }

    #[test]
    fn a_page_ending_outside_the_window_ends_the_search() {
        let scans = vec![
            scan("a", "incomplete", Some(SHA), "2026-01-01T23:00:00Z"),
            scan("b", "incomplete", Some(SHA), "2025-12-30T00:00:00Z"),
        ];
        assert!(page_ends_outside_window(&scans, now(), DAY));
    }

    #[test]
    fn an_unreadable_tail_timestamp_does_not_end_the_search() {
        // It proves nothing about what follows, and stopping on it would drop
        // reusable scans on later pages.
        let scans = vec![scan("a", "incomplete", Some(SHA), "not a timestamp")];
        assert!(!page_ends_outside_window(&scans, now(), DAY));
        assert!(!page_ends_outside_window(&[], now(), DAY));
    }

    #[test]
    fn age_formats_to_two_units() {
        assert_eq!(format_age(Duration::from_secs(45)), "45s");
        assert_eq!(format_age(Duration::from_secs(90)), "1m");
        assert_eq!(
            format_age(Duration::from_secs(3 * 3600 + 12 * 60)),
            "3h 12m"
        );
        assert_eq!(format_age(Duration::from_secs(2 * 86_400 + 3600)), "2d 1h");
    }
}
