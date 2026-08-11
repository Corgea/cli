//! End-to-end coverage for how `corgea wait` handles terminal scan states.
//!
//! The CLI's terminal check was `status == "complete"`, so `incomplete` fell
//! through to the still-running branch of an untimed loop and a failed scan
//! polled forever. These tests drive the real binary against a stubbed scan API
//! and kill it if it outlives `MAX_RUNTIME`, so a hang fails a test instead of
//! stalling the suite.

mod common;

use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SCAN_ID: &str = "5ba108cb-fc2e-4f2e-a3ba-d5e4fbfe77ac";

/// Bound every run: a hang is the bug under test, so exceeding this is failure.
const MAX_RUNTIME: Duration = Duration::from_secs(30);

fn scan_json(status: &str, failed_reason: &str, scan_errors: &str) -> String {
    let reason = if failed_reason.is_empty() {
        String::from("null")
    } else {
        format!("\"{}\"", failed_reason)
    };
    // The API sends `null`, not `[]`, when a scan has no problems to report.
    let errors = if scan_errors.is_empty() {
        String::from("null")
    } else {
        format!("[{}]", scan_errors)
    };
    format!(
        r#"{{"id":"{SCAN_ID}","project":"proj","repo":null,"branch":"main",
           "status":"{status}","engine":"corgea-blast",
           "created_at":"2026-08-01T15:16:31Z","time_taken":480,
           "git_sha":"abc123","metadata":null,
           "failed_reason":{reason},"scan_errors":{errors}}}"#
    )
}

fn issues_json() -> String {
    String::from(r#"{"status":"ok","issues":[],"page":1,"total_pages":1,"total_issues":0}"#)
}

/// Stub the scan API, walking `statuses` one entry per scan read and holding on
/// the last, so one stub can model a scan that is already terminal or one that
/// turns terminal mid-poll.
///
/// The issues route must be matched first: it lives under `/api/v1/scan/<id>`.
fn spawn_scan_api(
    statuses: &'static [&'static str],
    reason: &'static str,
    errors: &'static str,
) -> String {
    let reads = Arc::new(AtomicUsize::new(0));
    common::spawn_http_stub(move |path| {
        if path.contains("/issues") {
            return ("200 OK", issues_json());
        }
        if path.starts_with("/api/v1/scan/") {
            let read = reads.fetch_add(1, Ordering::SeqCst);
            let status = statuses[read.min(statuses.len() - 1)];
            return ("200 OK", scan_json(status, reason, errors));
        }
        ("200 OK", String::from(r#"{"status":"ok"}"#))
    })
}

/// Run `corgea wait <SCAN_ID>` against `url`, failing rather than blocking
/// forever if the command does not exit within `MAX_RUNTIME`.
fn run_wait(url: &str, env: &[(&str, &str)]) -> (Option<i32>, String) {
    let (mut cmd, _home) = common::corgea_isolated();
    cmd.env("CORGEA_URL", url)
        .env("CORGEA_TOKEN", "test-token")
        .args(["wait", SCAN_ID])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("run corgea wait");
    let deadline = Instant::now() + MAX_RUNTIME;
    let status = loop {
        match child.try_wait().expect("poll corgea wait") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("`corgea wait` did not exit within {MAX_RUNTIME:?} — it is hanging again");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    let out = child
        .wait_with_output()
        .expect("collect corgea wait output");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (status.code(), combined)
}

const SCA_FAILURE: &str = r#"{"scan_type":"sca","level":"error","location":"Project-wide",
    "message":"Could not read dependency metadata from the package registry."}"#;

#[test]
fn wait_on_already_failed_scan_exits_nonzero() {
    let url = spawn_scan_api(
        &["incomplete"],
        "Dependency Analysis did not finish.",
        SCA_FAILURE,
    );

    let (code, output) = run_wait(&url, &[]);

    assert_eq!(
        code,
        Some(1),
        "a failed scan must fail the command: {output}"
    );
    assert!(
        output.contains("Dependency Analysis did not finish."),
        "failure reason must reach the user: {output}"
    );
    assert!(
        output.contains("Could not read dependency metadata from the package registry."),
        "scanner error must reach the user: {output}"
    );
    assert!(
        !output.contains("Scan Completed Successfully"),
        "a failed scan must never print the success banner: {output}"
    );
}

#[test]
fn failed_scan_without_scanner_errors_still_reports_the_reason() {
    // A failed scan with nothing per-scanner to report carries
    // `"scan_errors": null`. Rejecting that shape while parsing would turn the
    // failure into a generic read error and lose the reason entirely.
    let url = spawn_scan_api(&["incomplete"], "The scan worker ran out of memory.", "");

    let (code, output) = run_wait(&url, &[]);

    assert_eq!(
        code,
        Some(1),
        "a failed scan must fail the command: {output}"
    );
    assert!(
        output.contains("The scan worker ran out of memory."),
        "failure reason must reach the user: {output}"
    );
}

#[test]
fn scan_that_fails_while_being_polled_exits_nonzero() {
    // The reported shape: still running at first and `incomplete` later, so the
    // terminal check inside the poll loop is the one that matters.
    let url = spawn_scan_api(
        &["processing", "incomplete"],
        "Dependency Analysis did not finish.",
        SCA_FAILURE,
    );

    let (code, output) = run_wait(&url, &[]);

    assert_eq!(
        code,
        Some(1),
        "a scan that fails mid-poll must fail the command: {output}"
    );
    assert!(
        output.contains("Dependency Analysis did not finish."),
        "failure reason must reach the user: {output}"
    );
}

#[test]
fn wait_on_completed_scan_succeeds() {
    let url = spawn_scan_api(&["complete"], "", "");

    let (code, output) = run_wait(&url, &[]);

    assert_eq!(code, Some(0), "a clean scan must succeed: {output}");
    assert!(
        !output.contains("may be missing results"),
        "a clean scan must not warn: {output}"
    );
}

const DEGRADED: &str = r#"{"scan_type":"sca","level":"error","location":"Project-wide",
    "message":"Dependency Analysis did not finish, so those results are missing."}"#;

/// The warning is the only place the user learns coverage dropped, and it is
/// raised from two places: whichever of the two reads sees `complete` first.
#[test]
fn completed_scan_reports_missing_scanner_results() {
    // Complete on the second read, so the poll loop raises it.
    let url = spawn_scan_api(&["processing", "complete"], "", DEGRADED);

    let (code, output) = run_wait(&url, &[]);

    assert_eq!(code, Some(0), "a degraded scan still succeeds: {output}");
    assert!(
        output.contains("Dependency Analysis did not finish, so those results are missing."),
        "degraded coverage must be reported: {output}"
    );
}

#[test]
fn already_completed_scan_reports_missing_scanner_results() {
    // Complete on the first read, so the wait returns without ever polling.
    let url = spawn_scan_api(&["complete"], "", DEGRADED);

    let (code, output) = run_wait(&url, &[]);

    assert_eq!(code, Some(0), "a degraded scan still succeeds: {output}");
    assert!(
        output.contains("Dependency Analysis did not finish, so those results are missing."),
        "degraded coverage must be reported without polling: {output}"
    );
}

#[test]
fn wait_stops_polling_a_scan_that_never_finishes() {
    // Guards the timeout: without it, a scan stuck in a non-terminal status
    // polls forever.
    let url = spawn_scan_api(&["processing"], "", "");

    let (code, output) = run_wait(&url, &[("CORGEA_SCAN_TIMEOUT_SECONDS", "3")]);

    assert_eq!(code, Some(1), "a timeout must fail the command: {output}");
    assert!(
        output.contains("Stopped waiting"),
        "timeout must explain itself: {output}"
    );
}

#[test]
fn wait_budget_covers_the_first_status_read() {
    // `corgea wait` reads the scan once before it starts polling. That read
    // shares the same budget, so a server that accepts the connection and never
    // answers cannot spend the client's 150s timeout on top of the wait.
    let url = common::spawn_http_stub(|path| {
        if path.starts_with("/api/v1/scan/") {
            std::thread::sleep(Duration::from_secs(60));
        }
        ("200 OK", String::from(r#"{"status":"ok"}"#))
    });

    let started = Instant::now();
    let (code, output) = run_wait(&url, &[("CORGEA_SCAN_TIMEOUT_SECONDS", "3")]);
    let elapsed = started.elapsed();

    assert_eq!(
        code,
        Some(1),
        "an unanswered read must fail the command: {output}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "waited {elapsed:?} on a 3s budget: {output}"
    );
}

#[test]
fn wait_honors_the_timeout_when_a_status_read_stalls() {
    // The budget has to bound the whole wait, not just the gaps between reads.
    // Each read carries the client's 150s timeout, so a server that accepts the
    // connection and never answers used to hold the CLI far past the budget.
    let reads = Arc::new(AtomicUsize::new(0));
    let url = common::spawn_http_stub(move |path| {
        if path.starts_with("/api/v1/scan/") {
            if reads.fetch_add(1, Ordering::SeqCst) > 0 {
                // Outlasts MAX_RUNTIME: reaching this read must not mean waiting
                // for it.
                std::thread::sleep(Duration::from_secs(60));
            }
            return ("200 OK", scan_json("processing", "", ""));
        }
        ("200 OK", String::from(r#"{"status":"ok"}"#))
    });

    let started = Instant::now();
    let (code, output) = run_wait(&url, &[("CORGEA_SCAN_TIMEOUT_SECONDS", "3")]);
    let elapsed = started.elapsed();

    assert_eq!(code, Some(1), "a timeout must fail the command: {output}");
    assert!(
        output.contains("Stopped waiting"),
        "a stalled read must be reported as a timeout, not a broken connection: {output}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "waited {elapsed:?} on a 3s budget: {output}"
    );
}
