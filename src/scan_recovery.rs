//! Finding the scan an upload registered when its answer never arrived.
//!
//! The chunk completing an archive is the request that registers the scan,
//! and doghouse registers it inline: it validates the archive, creates the
//! scan, copies the previous scan's findings forward for an incremental scan,
//! and only then answers with the scan id. On a large project that runs past
//! the proxy in front of Corgea, which answers the CLI with a gateway error
//! (Cloudflare's 524 after 100 seconds) while the server carries on and
//! registers the scan anyway. A pipeline that failed there got no report for
//! a scan that went on to complete.
//!
//! The chunk cannot be sent again: the server would register a second scan.
//! What it can do is look for the first one. The scan row is created early in
//! that request, before the slow copy, and the scan list shows it from then
//! on, by project and commit, with its status still `scanning`. So the CLI
//! reads the project's scans of this commit, takes the newest one registered
//! after the upload began, and waits on it as it would have on the id the
//! answer should have carried.
//!
//! Only an upload with a commit can be recovered: the commit is what ties a
//! listed scan to this upload. Several pipeline jobs uploading the same commit
//! at once may each pick the same scan, or each other's; they uploaded the
//! same bytes, so any of those scans answers the question each job asked.

use crate::config::Config;
use crate::scanners::blast::{classify_scan_status, ScanState};
use crate::utils;
use crate::utils::api::ScanResponse;
use chrono::{DateTime, Utc};
use std::thread;
use std::time::{Duration, Instant};

/// How long the lookup keeps asking for a scan of the commit before giving
/// up. The row exists before the proxy times out, so one read normally finds
/// it; the rest covers a list that lags the write, or a read that fails.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(120);

const LOOKUP_INTERVAL: Duration = Duration::from_secs(5);

/// How far before the upload began a scan may be stamped and still count as
/// this upload's: the server's clock and this machine's need not agree.
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::from_secs(300);

/// Scans of the commit read per lookup, newest first. A pipeline burst
/// registers a few dozen scans of one commit at most.
const LOOKUP_PAGE_SIZE: u16 = 50;

/// The engine every blast scan carries. A report uploaded for the same commit
/// through `corgea upload` is another engine's scan, not this upload's.
const BLAST_ENGINE: &str = "corgea-blast";

/// The scan the server registered for this upload, found through the scan
/// list, or why none could be.
///
/// `cause` is what the upload got instead of an answer, for the messages.
pub fn recover_registered_scan(
    config: &Config,
    project_name: &str,
    sha: Option<&str>,
    started_at: DateTime<Utc>,
    cause: &str,
) -> Result<ScanResponse, String> {
    let Some(sha) = sha.filter(|sha| !sha.trim().is_empty()) else {
        return Err(format!(
            "The upload completed, but the request registering the scan went unanswered: {cause}.\n\
             Corgea may still have registered the scan, but this upload carries no commit to find it by, \
             so it cannot be told apart from the project's other scans.\n\
             Check the project's scans at {}/project/{project_name} before running the scan again.",
            config.get_url()
        ));
    };
    log::warn!(
        "\nThe upload completed, but the request registering the scan went unanswered: {cause}.\n\
         Corgea registers the scan while that request runs, so looking for the scan of commit {} \
         in project '{}' instead of starting another...",
        short_sha(sha),
        project_name
    );

    let deadline = Instant::now() + LOOKUP_TIMEOUT;
    let mut last_failure: Option<String>;
    loop {
        match utils::api::query_scans_for_commit(
            &config.get_url(),
            project_name,
            sha,
            1,
            LOOKUP_PAGE_SIZE,
        ) {
            Ok(response) => {
                let scans = response.scans.unwrap_or_default();
                if let Some(scan) = select_registered_scan(&scans, sha, started_at) {
                    println!(
                        "Corgea registered scan {} for commit {} after this upload began; waiting on it.",
                        scan.id,
                        short_sha(sha)
                    );
                    return Ok(scan.clone());
                }
                last_failure = None;
            }
            Err(e) => {
                log::debug!("Scan lookup for commit {} failed: {}", short_sha(sha), e);
                last_failure = Some(e.to_string());
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(LOOKUP_INTERVAL);
    }

    let why = match last_failure {
        Some(e) => format!("the scan list could not be read ({e})"),
        None => format!(
            "no scan of commit {} registered after this upload began appeared within {} seconds",
            short_sha(sha),
            LOOKUP_TIMEOUT.as_secs()
        ),
    };
    Err(format!(
        "The upload completed, but the request registering the scan went unanswered: {cause}.\n\
         Looked for the scan Corgea registered for it, but {why}.\n\
         Corgea may still register the scan after this run ends. Check the project's scans at \
         {}/project/{project_name} before running the scan again.",
        config.get_url()
    ))
}

/// The newest scan on the page that this upload can have registered: a blast
/// scan of `sha`, stamped no earlier than `started_at` less the clock skew
/// allowance, and not already failed. The list is newest first, so the first
/// match is the newest.
///
/// A scan still `scanning` is the expected find: the server stamps the row
/// before the work that outlasted the proxy. A failed one is skipped because
/// waiting on it would only report the failure of a scan this upload may not
/// own, when a sibling may have registered a sound one.
pub fn select_registered_scan<'a>(
    scans: &'a [ScanResponse],
    sha: &str,
    started_at: DateTime<Utc>,
) -> Option<&'a ScanResponse> {
    let earliest = started_at - chrono::Duration::from_std(CLOCK_SKEW_ALLOWANCE).ok()?;
    scans.iter().find(|scan| {
        scan.git_sha
            .as_deref()
            .is_some_and(|scan_sha| scan_sha.eq_ignore_ascii_case(sha))
            && scan.engine.eq_ignore_ascii_case(BLAST_ENGINE)
            && classify_scan_status(&scan.status) != ScanState::Failed
            && parse_timestamp(&scan.created_at).is_some_and(|created_at| created_at >= earliest)
    })
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

fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(7)]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "b598b378a3d18ee6076ba724ae999badc235aaaa";

    fn scan(id: &str, status: &str, sha: Option<&str>, created_at: &str) -> ScanResponse {
        ScanResponse {
            id: id.to_string(),
            project: "onetru_spark_jre11_jars".to_string(),
            project_id: Some("4174".to_string()),
            repo: None,
            branch: Some("feature/x".to_string()),
            status: status.to_string(),
            engine: BLAST_ENGINE.to_string(),
            created_at: created_at.to_string(),
            git_sha: sha.map(str::to_string),
            worktree_dirty: Some(true),
            metadata: None,
            failed_reason: None,
            scan_errors: vec![],
            pull_request_id: None,
            file_manifest_root: None,
            file_manifest_version: None,
            ignore_paths: None,
        }
    }

    fn started() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-30T09:13:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn picks_the_newest_scan_of_the_commit_registered_after_the_upload_began() {
        let scans = vec![
            scan(
                "other-commit",
                "scanning",
                Some("deadbeef"),
                "2026-10-30T09:13:50Z",
            ),
            scan("newest", "scanning", Some(SHA), "2026-10-30T09:13:44Z"),
            scan("older", "scanning", Some(SHA), "2026-10-30T09:13:06Z"),
            scan("yesterday", "complete", Some(SHA), "2026-10-29T04:43:05Z"),
        ];
        let found = select_registered_scan(&scans, SHA, started()).unwrap();
        assert_eq!(found.id, "newest");
    }

    #[test]
    fn a_scan_from_before_the_upload_is_not_this_uploads() {
        // Older than the upload by more than the skew allowance: a previous
        // run's scan, which may be stale or still running for its own reasons.
        let scans = vec![scan(
            "previous-run",
            "scanning",
            Some(SHA),
            "2026-10-30T09:00:00Z",
        )];
        assert!(select_registered_scan(&scans, SHA, started()).is_none());
    }

    #[test]
    fn clock_skew_within_the_allowance_still_matches() {
        // The server stamped the row a minute before this machine thinks the
        // upload started.
        let scans = vec![scan(
            "skewed",
            "scanning",
            Some(SHA),
            "2026-10-30T09:12:00Z",
        )];
        assert!(select_registered_scan(&scans, SHA, started()).is_some());
    }

    #[test]
    fn a_failed_scan_is_skipped_for_a_live_sibling() {
        let scans = vec![
            scan("failed", "incomplete", Some(SHA), "2026-10-30T09:13:50Z"),
            scan("live", "scanning", Some(SHA), "2026-10-30T09:13:44Z"),
        ];
        assert_eq!(
            select_registered_scan(&scans, SHA, started()).unwrap().id,
            "live"
        );
    }

    #[test]
    fn a_completed_scan_of_the_commit_counts() {
        // The server may finish registering and even scanning a small
        // project before the lookup runs.
        let scans = vec![scan("done", "complete", Some(SHA), "2026-10-30T09:13:44Z")];
        assert!(select_registered_scan(&scans, SHA, started()).is_some());
    }

    #[test]
    fn another_engines_scan_and_a_scan_without_a_commit_are_not_matches() {
        let mut report = scan("report", "scanning", Some(SHA), "2026-10-30T09:13:44Z");
        report.engine = "semgrep".to_string();
        let no_commit = scan("no-commit", "scanning", None, "2026-10-30T09:13:44Z");
        assert!(select_registered_scan(&[report, no_commit], SHA, started()).is_none());
    }

    #[test]
    fn commit_comparison_ignores_case_and_naive_timestamps_parse() {
        let scans = vec![scan(
            "upper",
            "scanning",
            Some(&SHA.to_uppercase()),
            "2026-10-30T09:13:44.123456",
        )];
        assert!(select_registered_scan(&scans, SHA, started()).is_some());
    }
}
