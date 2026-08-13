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
//! inside the window (24h by default).

use crate::config::Config;
use crate::scanners::blast::{classify_scan_status, ScanState};
use crate::utils;
use crate::utils::api::ScanResponse;
use chrono::{DateTime, Utc};
use std::time::Duration;

/// How far back a prior scan may have run and still be reused.
pub const DEFAULT_WINDOW: &str = "24h";

/// How many of the commit's scans to consider. They arrive newest first, and
/// only the newest reusable one is wanted, so this is a ceiling on re-runs of
/// one commit rather than a page to walk.
const SCAN_LOOKUP_PAGE_SIZE: u16 = 30;

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
/// here rather than skipping a scan on incomplete information. The one hard
/// failure is an unresolvable commit: the flag asks a question about the
/// commit, and without one there is no question to answer.
pub fn resolve_reusable_scan(
    config: &Config,
    project_name: &str,
    skip: &SkipRecentScan,
) -> Option<ScanResponse> {
    let commit = utils::generic::get_repo_info_for_scan("./")
        .ok()
        .flatten()
        .and_then(|info| Some((info.sha?, info.status_dirty)));
    let Some((sha, status_dirty)) = commit else {
        log::error!(
            "--skip-if-commit-scanned-recently needs the commit that is being scanned, but no git commit could be resolved here.\n\
             Run it from the root of a git repository with at least one commit, or drop the flag."
        );
        std::process::exit(1);
    };
    let short = short_sha(&sha);

    if status_dirty {
        println!(
            "Working tree has uncommitted changes, so commit {} does not describe what would be scanned - running a new scan.",
            short
        );
        print_skipped_marker(None);
        return None;
    }

    println!(
        "Checking Corgea for a scan of commit {} in project '{}' from the last {}...",
        short, project_name, skip.label
    );

    let scans = match utils::api::query_scans_for_commit(
        &config.get_url(),
        project_name,
        &sha,
        SCAN_LOOKUP_PAGE_SIZE,
    ) {
        Ok(response) => response.scans.unwrap_or_default(),
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

    match select_reusable_scan(&scans, &sha, Utc::now(), skip.window) {
        Some(reusable) => {
            println!(
                "Skipping scan: commit {} was already scanned {} ago by scan {}.",
                short, reusable.age, reusable.scan.id
            );
            println!(
                "Reporting on that scan instead - blocking rules and report output are unchanged."
            );
            print_skipped_marker(Some(&reusable.scan.id));
            Some(reusable.scan.clone())
        }
        None => {
            println!(
                "No completed scan of commit {} in the last {}; running a new scan.",
                short, skip.label
            );
            print_skipped_marker(None);
            None
        }
    }
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
) -> Option<ReusableScan<'a>> {
    for scan in scans {
        match scan_age_if_reusable(scan, sha, now, window) {
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

/// How long ago `scan` ran, or why it cannot stand in for a new scan.
fn scan_age_if_reusable(
    scan: &ScanResponse,
    sha: &str,
    now: DateTime<Utc>,
    window: Duration,
) -> Result<Duration, String> {
    match scan.git_sha.as_deref() {
        Some(scan_sha) if scan_sha.eq_ignore_ascii_case(sha) => {}
        Some(scan_sha) => return Err(format!("it scanned commit {}", short_sha(scan_sha))),
        None => return Err("it records no commit".to_string()),
    }
    // A scan that failed has no results to gate on, and one still running has
    // none yet; both mean this run has to do the scan itself.
    if classify_scan_status(&scan.status) != ScanState::Completed {
        return Err(format!("its status is '{}'", scan.status));
    }
    // Only a known-dirty tree disqualifies. A scan that never reported the
    // flag (an older CLI, or a platform integration that scans the commit
    // directly) is not evidence of local edits.
    if scan.worktree_dirty == Some(true) {
        return Err("it scanned a worktree with uncommitted changes".to_string());
    }
    let created_at = parse_timestamp(&scan.created_at)
        .ok_or_else(|| format!("its timestamp '{}' could not be read", scan.created_at))?;
    let age = now
        .signed_duration_since(created_at)
        .to_std()
        // A scan stamped in the future is a clock skew, not an old scan; treat
        // it as brand new rather than letting the subtraction underflow.
        .unwrap_or(Duration::ZERO);
    if age > window {
        return Err(format!(
            "it ran {} ago, outside the window",
            format_age(age)
        ));
    }
    Ok(age)
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

fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(7)]
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
        let reusable = select_reusable_scan(&scans, SHA, now(), DAY).expect("expected a reuse");
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
        let reusable = select_reusable_scan(&scans, SHA, now(), DAY).expect("expected a reuse");
        assert_eq!(reusable.scan.id, "good");
    }

    #[test]
    fn running_and_failed_scans_are_not_reusable() {
        for status in ["processing", "scanning", "incomplete", "failed", ""] {
            let scans = vec![scan("s", status, Some(SHA), "2026-01-01T23:00:00Z")];
            assert!(
                select_reusable_scan(&scans, SHA, now(), DAY).is_none(),
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
        assert!(select_reusable_scan(&scans, SHA, now(), DAY).is_none());
    }

    #[test]
    fn commit_comparison_ignores_sha_casing() {
        let scans = vec![scan(
            "s",
            "complete",
            Some(&SHA.to_uppercase()),
            "2026-01-01T23:00:00Z",
        )];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY).is_some());
    }

    #[test]
    fn scans_outside_the_window_are_not_reused() {
        // The point of the window: the code is unchanged, but the advisories
        // it is scanned against are not.
        let scans = vec![scan("stale", "complete", Some(SHA), "2025-12-30T00:00:00Z")];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY).is_none());
        // A shorter window is what makes a scan from this morning stale.
        let scans = vec![scan(
            "morning",
            "complete",
            Some(SHA),
            "2026-01-01T20:00:00Z",
        )];
        assert!(select_reusable_scan(&scans, SHA, now(), Duration::from_secs(3_600)).is_none());
    }

    #[test]
    fn a_scan_exactly_at_the_window_edge_is_still_reusable() {
        let scans = vec![scan("edge", "complete", Some(SHA), "2026-01-01T00:00:00Z")];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY).is_some());
    }

    #[test]
    fn scans_of_a_dirty_worktree_are_not_reused() {
        // Those results describe someone's uncommitted edits, not this commit.
        let mut dirty = scan("dirty", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        dirty.worktree_dirty = Some(true);
        assert!(select_reusable_scan(&[dirty], SHA, now(), DAY).is_none());
    }

    #[test]
    fn scans_that_never_reported_dirtiness_are_still_reusable() {
        // Older CLIs and platform integrations omit the flag; treating that as
        // dirty would make the flag useless against existing scan history.
        let mut unknown = scan("unknown", "complete", Some(SHA), "2026-01-01T23:00:00Z");
        unknown.worktree_dirty = None;
        assert!(select_reusable_scan(&[unknown], SHA, now(), DAY).is_some());
    }

    #[test]
    fn unreadable_timestamps_do_not_skip_the_scan() {
        let scans = vec![scan("bad-time", "complete", Some(SHA), "not a timestamp")];
        assert!(select_reusable_scan(&scans, SHA, now(), DAY).is_none());
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
                select_reusable_scan(&scans, SHA, now(), DAY).is_some(),
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
        let reusable = select_reusable_scan(&scans, SHA, now(), DAY).expect("expected a reuse");
        assert_eq!(reusable.age, "0s");
    }

    #[test]
    fn empty_scan_list_reuses_nothing() {
        assert!(select_reusable_scan(&[], SHA, now(), DAY).is_none());
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
