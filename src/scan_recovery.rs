//! Finding the scan an upload registered when its answer never arrived.
//!
//! The chunk completing an archive is the request that registers the scan,
//! and doghouse registers it inline: it validates the archive, creates the
//! scan, stores its file manifest, copies the previous scan's findings
//! forward for an incremental scan, and only then answers with the scan id.
//! On a large project that runs past the proxy in front of Corgea, which
//! answers the CLI with a gateway error (Cloudflare's 524 after 100 seconds)
//! while the server carries on and registers the scan anyway. A pipeline
//! that failed there got no report for a scan that went on to complete.
//!
//! The chunk cannot be sent again: the server would register a second scan.
//! What it can do is look for the first one. The scan row is created early in
//! that request, before the slow copy, and the scan list shows it from then
//! on, by project and commit, with its status still `scanning`. So the CLI
//! reads the project's scans of this commit, takes the newest one that this
//! upload can have registered, and waits on it as it would have on the id the
//! answer should have carried.
//!
//! What ties a listed scan to this upload is what the server stored from it,
//! carried on the [`UnansweredRegistration`]: the commit, the dirty flag, and
//! the root digest of the file manifest, which separates this upload's scan
//! from a `--only-uncommitted` partial scan of the same commit, or from a
//! sibling job's scan of the same commit with different uncommitted changes.
//! Jobs that uploaded the very same bytes may still each pick the same scan,
//! or each other's; any of those scans answers the question each job asked.

use crate::scanners::blast::{classify_scan_status, ScanState};
use crate::skip_scan::{parse_timestamp, scan_matches_commit, short_sha, BLAST_ENGINE};
use crate::utils;
use crate::utils::api::{ScanResponse, UnansweredRegistration};
use std::thread;
use std::time::{Duration, Instant};

/// How long the lookup keeps asking for a scan of the commit before giving
/// up. The row exists before the proxy times out, so one read normally finds
/// it; the rest covers a list that lags the write, or a read that fails.
#[cfg(not(test))]
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(test)]
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(100);

#[cfg(not(test))]
const LOOKUP_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
const LOOKUP_INTERVAL: Duration = Duration::from_millis(10);

/// Scans of the commit read per lookup, newest first. A pipeline burst
/// registers a few dozen scans of one commit at most.
const LOOKUP_PAGE_SIZE: u16 = 50;

/// The scan the server registered for this upload, found through the scan
/// list, or why none could be.
pub fn recover_registered_scan(
    url: &str,
    project_name: &str,
    unanswered: &UnansweredRegistration,
) -> Result<ScanResponse, String> {
    let Some(sha) = unanswered
        .sha
        .as_deref()
        .filter(|sha| !sha.trim().is_empty())
    else {
        return Err(format!(
            "{unanswered}.\n\
             Corgea may still have registered the scan, but this upload carries no commit to find it by, \
             so it cannot be told apart from the project's other scans.\n\
             Check the project's scans at {url}/project/{project_name} before running the scan again."
        ));
    };
    log::warn!(
        "\n{unanswered}.\n\
         Corgea registers the scan while that request runs, so looking for the scan of commit {} \
         in project '{}' instead of starting another...",
        short_sha(sha),
        project_name
    );

    let deadline = Instant::now() + LOOKUP_TIMEOUT;
    let mut last_failure: Option<String>;
    loop {
        match utils::api::query_scans_for_commit(url, project_name, sha, 1, LOOKUP_PAGE_SIZE) {
            Ok(response) => {
                let scans = response.scans.unwrap_or_default();
                if let Some(scan) = select_registered_scan(&scans, sha, unanswered) {
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
        "{unanswered}.\n\
         Looked for the scan Corgea registered for it, but {why}.\n\
         Corgea may still register the scan after this run ends. Check the project's scans at \
         {url}/project/{project_name} before running the scan again."
    ))
}

/// The newest scan on the page that this upload can have registered: a blast
/// scan of `sha` with its manifest and dirty flag, stamped no earlier than
/// the upload opened, and not already failed. The list is newest first, so
/// the first match is the newest.
///
/// A scan still `scanning` is the expected find: the server stamps the row
/// before the work that outlasted the proxy. A failed one is skipped because
/// waiting on it would only report the failure of a scan this upload may not
/// own, when a sibling may have registered a sound one.
fn select_registered_scan<'a>(
    scans: &'a [ScanResponse],
    sha: &str,
    unanswered: &UnansweredRegistration,
) -> Option<&'a ScanResponse> {
    scans.iter().find(|scan| {
        scan_matches_commit(scan, sha)
            && scan.engine.eq_ignore_ascii_case(BLAST_ENGINE)
            && classify_scan_status(&scan.status) != ScanState::Failed
            // A server too old to record the flag lists `None`, which rules
            // nothing out.
            && scan.worktree_dirty != Some(!unanswered.worktree_dirty)
            && scan.file_manifest_root == unanswered.manifest_root
            && parse_timestamp(&scan.created_at)
                .is_some_and(|created_at| created_at >= unanswered.registered_no_earlier_than)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const SHA: &str = "b598b378a3d18ee6076ba724ae999badc235aaaa";
    const ROOT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A full, clean upload of `SHA` whose registering request went
    /// unanswered; it opened at 09:13, on a clock allowed five minutes.
    fn unanswered() -> UnansweredRegistration {
        UnansweredRegistration {
            cause: "524 (test)".to_string(),
            sha: Some(SHA.to_string()),
            worktree_dirty: false,
            manifest_root: Some(ROOT.to_string()),
            registered_no_earlier_than: at("2026-10-30T09:08:00Z"),
        }
    }

    /// A clean blast scan of `sha` carrying `ROOT`, as the list shows it.
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
            worktree_dirty: Some(false),
            metadata: None,
            failed_reason: None,
            scan_errors: vec![],
            pull_request_id: None,
            file_manifest_root: Some(ROOT.to_string()),
            file_manifest_version: Some("1".to_string()),
            ignore_paths: None,
        }
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
        let found = select_registered_scan(&scans, SHA, &unanswered()).unwrap();
        assert_eq!(found.id, "newest");
    }

    #[test]
    fn a_scan_from_before_the_upload_is_not_this_uploads() {
        // A previous run's scan, which may be stale or still running for its
        // own reasons.
        let scans = vec![scan(
            "previous-run",
            "scanning",
            Some(SHA),
            "2026-10-30T09:00:00Z",
        )];
        assert!(select_registered_scan(&scans, SHA, &unanswered()).is_none());
    }

    #[test]
    fn a_failed_scan_is_skipped_for_a_live_sibling() {
        let scans = vec![
            scan("failed", "incomplete", Some(SHA), "2026-10-30T09:13:50Z"),
            scan("live", "scanning", Some(SHA), "2026-10-30T09:13:44Z"),
        ];
        assert_eq!(
            select_registered_scan(&scans, SHA, &unanswered())
                .unwrap()
                .id,
            "live"
        );
    }

    #[test]
    fn a_completed_scan_of_the_commit_counts() {
        // The server may finish registering and even scanning a small
        // project before the lookup runs.
        let scans = vec![scan("done", "complete", Some(SHA), "2026-10-30T09:13:44Z")];
        assert!(select_registered_scan(&scans, SHA, &unanswered()).is_some());
    }

    #[test]
    fn another_engines_scan_and_a_scan_without_a_commit_are_not_matches() {
        let mut report = scan("report", "scanning", Some(SHA), "2026-10-30T09:13:44Z");
        report.engine = "semgrep".to_string();
        let no_commit = scan("no-commit", "scanning", None, "2026-10-30T09:13:44Z");
        assert!(select_registered_scan(&[report, no_commit], SHA, &unanswered()).is_none());
    }

    #[test]
    fn a_scan_of_other_bytes_at_the_same_commit_is_not_this_uploads() {
        // A sibling job uploaded the same commit with different uncommitted
        // changes, and a pre-commit hook registered a partial scan of it,
        // which the server stores no manifest for. Neither is what this
        // upload sent.
        let mut sibling = scan("sibling", "scanning", Some(SHA), "2026-10-30T09:13:50Z");
        sibling.file_manifest_root = Some("2".repeat(64));
        let mut partial = scan("partial", "scanning", Some(SHA), "2026-10-30T09:13:48Z");
        partial.file_manifest_root = None;
        let own = scan("own", "scanning", Some(SHA), "2026-10-30T09:13:44Z");
        let scans = vec![sibling, partial, own];
        assert_eq!(
            select_registered_scan(&scans, SHA, &unanswered())
                .unwrap()
                .id,
            "own"
        );

        // And the partial upload's own recovery finds the partial scan.
        let partial_upload = UnansweredRegistration {
            manifest_root: None,
            ..unanswered()
        };
        assert_eq!(
            select_registered_scan(&scans, SHA, &partial_upload)
                .unwrap()
                .id,
            "partial"
        );
    }

    #[test]
    fn the_dirty_flag_must_agree_unless_the_server_never_recorded_it() {
        let mut dirty = scan("dirty", "scanning", Some(SHA), "2026-10-30T09:13:50Z");
        dirty.worktree_dirty = Some(true);
        let mut unknown = scan("unknown", "scanning", Some(SHA), "2026-10-30T09:13:44Z");
        unknown.worktree_dirty = None;
        let scans = vec![dirty, unknown];
        assert_eq!(
            select_registered_scan(&scans, SHA, &unanswered())
                .unwrap()
                .id,
            "unknown"
        );
    }

    #[test]
    fn commit_comparison_ignores_case_and_naive_timestamps_parse() {
        let scans = vec![scan(
            "upper",
            "scanning",
            Some(&SHA.to_uppercase()),
            "2026-10-30T09:13:44.123456",
        )];
        assert!(select_registered_scan(&scans, SHA, &unanswered()).is_some());
    }

    /// A doghouse whose scan list answers every request with `status_line`
    /// and `body`, counting the requests.
    fn spawn_scan_list_stub(
        status_line: &'static str,
        body: String,
    ) -> (String, Arc<Mutex<usize>>) {
        let requests = Arc::new(Mutex::new(0));
        let seen = Arc::clone(&requests);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = corgea::vuln_api_stub::read_http_request(&mut stream);
                *seen.lock().unwrap() += 1;
                let response = corgea::vuln_api_stub::http_response(status_line, "", &body);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (base, requests)
    }

    fn scans_json(scans: &[ScanResponse]) -> String {
        serde_json::json!({
            "status": "ok",
            "page": 1,
            "total_pages": 1,
            "scans": scans,
        })
        .to_string()
    }

    #[test]
    fn an_upload_without_a_commit_is_not_looked_for() {
        let without_commit = UnansweredRegistration {
            sha: None,
            ..unanswered()
        };
        let err =
            recover_registered_scan("http://127.0.0.1:1", "proj", &without_commit).unwrap_err();
        assert!(err.starts_with("The upload completed, but"), "{err}");
        assert!(err.contains("carries no commit"), "{err}");
        assert!(err.contains("http://127.0.0.1:1/project/proj"), "{err}");
    }

    #[test]
    fn the_registered_scan_is_found_on_the_first_read() {
        let registered = scan("own", "scanning", Some(SHA), "2026-10-30T09:13:44Z");
        let (base, requests) = spawn_scan_list_stub("200 OK", scans_json(&[registered]));

        let found = recover_registered_scan(&base, "proj", &unanswered()).unwrap();

        assert_eq!(found.id, "own");
        assert_eq!(*requests.lock().unwrap(), 1);
    }

    #[test]
    fn gives_up_when_no_scan_of_the_commit_appears() {
        let (base, requests) = spawn_scan_list_stub("200 OK", scans_json(&[]));

        let err = recover_registered_scan(&base, "proj", &unanswered()).unwrap_err();

        assert!(err.contains("no scan of commit b598b37"), "{err}");
        assert!(err.contains(&format!("{base}/project/proj")), "{err}");
        assert!(
            *requests.lock().unwrap() > 1,
            "the list is read again until the deadline"
        );
    }

    #[test]
    fn reports_a_scan_list_that_cannot_be_read() {
        let (base, _) = spawn_scan_list_stub("500 Internal Server Error", "boom".to_string());

        let err = recover_registered_scan(&base, "proj", &unanswered()).unwrap_err();

        assert!(err.contains("the scan list could not be read"), "{err}");
        assert!(err.contains("500"), "{err}");
    }
}
