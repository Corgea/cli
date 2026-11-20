//! Hermetic e2e tests for the install-gate vuln-api verdict
//! (`corgea pip install …` with public/authenticated `CORGEA_VULN_API_URL`
//! stubs).
//!
//! Composes the `cli_install.rs` harness pattern (fake package manager on a
//! private PATH + local pypi registry stub) with the in-crate vuln-api stub —
//! the shared `common::pip_harness`. Every package is published in 2020, so
//! recency never blocks here — every block in this file is the verdict's
//! doing.

#![cfg(unix)]

mod common;

use common::{key, malicious_body, pip_harness, vulnerable_body};
use corgea::vuln_api_stub::{header_value, spawn_capturing_vuln_api_stub};
use std::collections::HashMap;

#[test]
fn vulnerable_pin_blocks_without_running_install() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        h.recorded_argv(),
        None,
        "pip must not run on a vulnerable verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CVE-2024-0001"), "stdout: {stdout}");
    assert!(stdout.contains("critical"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force"),
        "block message must name --force"
    );
}

#[test]
fn alternate_pypi_spelling_hits_canonical_verdict() {
    // Advisories are keyed by lowercase(canonical) — the server does NOT
    // apply PEP 503. `pip install Flask_Cors` must still block on the
    // `flask-cors` row: resolution adopts the registry's canonical
    // spelling (`info.name`, like real PyPI, which answers any PEP 503-
    // equivalent request) and the verdict checks that.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "flask-cors", "1.0.0"),
        vulnerable_body("pypi", "flask-cors", "1.0.0", "GHSA-TEST-0001", None),
    );
    // Model real PyPI: serve the alternate request spelling, echo the
    // canonical name in info.name.
    let registry = common::spawn_http_stub(|path| match path {
        "/pypi/Flask_Cors/json" | "/pypi/flask-cors/json" => (
            "200 OK",
            common::pypi_release_json("Flask-Cors", "1.0.0", common::OLD_TS),
        ),
        _ => ("404 Not Found", common::NOT_FOUND_JSON.to_string()),
    });
    // Like `pip_harness` (public mode): the tree dry-run exits 2 (old pip,
    // no --report), so the block is the named verdict's doing and a
    // recorded argv would mean the real install ran.
    let mut h = common::GateHarness::new()
        .fake_tree_pm("pip", common::RESOLUTION_FAILS, 0)
        .registry_env("CORGEA_PYPI_REGISTRY", &registry)
        .vuln_checks(checks)
        .build();
    let out = h
        .cmd
        .args(["pip", "install", "Flask_Cors==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "alternate spelling must not bypass the gate"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GHSA-TEST-0001"), "stdout: {stdout}");
}

#[test]
fn force_overrides_vulnerable_block_and_propagates_exit_code() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 7);
    let out = h
        .cmd
        .args(["pip", "--force", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(7),
        "manager exit code must propagate under --force"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("CVE-2024-0001"),
        "findings must still print under --force: {stdout}"
    );
}

#[test]
fn force_after_the_verb_is_forwarded_not_consumed_and_block_explains_placement() {
    // `--force` typed after the install verb is swallowed by clap's
    // trailing-var-arg and forwarded to pip, so the gate never sees it and the
    // block stands. The refusal must say why and show the placement that works.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0", "--force"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "--force after the verb does not reach the gate; block stands"
    );
    assert_eq!(
        h.recorded_argv(),
        None,
        "pip must not run — the gate still blocked"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("`--force` after the verb was passed to pip, not corgea"),
        "block must explain the swallowed flag: {stderr}"
    );
    assert!(
        stderr.contains("corgea pip --force install oldpkg==1.0.0"),
        "block must show the working placement: {stderr}"
    );
}

#[test]
fn vulnerable_named_pin_blocks_install() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a vulnerable verdict blocks the install"
    );
    assert_eq!(h.recorded_argv(), None);
}

#[test]
fn verdict_503_warns_and_fails_open() {
    let mut checks = HashMap::new();
    checks.insert(key("pypi", "oldpkg", "1.0.0"), "{}".to_string());
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    let mut h = pip_harness(checks, statuses, None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a 503 verdict must fail open in public mode; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not be verified"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("CVE check unavailable; continuing because public mode is fail-open"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn resolution_error_fails_closed_when_authenticated() {
    // The wildcard registry stub only knows version 1.0.0, so `==2.0.0`
    // is a resolution error: no verdict was obtained, and authenticated
    // mode must block — otherwise a registry outage bypasses the gate.
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("test-token"), 0);
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "nosuchpkg==2.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a resolution error must fail closed in authenticated mode"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 errors"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--force"),
        "block message must name --force"
    );
}

#[test]
fn verdict_503_fails_closed_when_authenticated() {
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    let mut h = pip_harness(HashMap::new(), statuses, Some("test-token"), 0);
    h.cmd.env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "authenticated unverifiable must block (fail-closed)"
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not be verified"), "stdout: {stdout}");
}

#[test]
fn tokenless_public_check_discloses_mode() {
    // No token still runs public CVE checks; the hint names what login adds.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("using public CVE checks"),
        "tokenless mode must disclose public CVE checks: {stderr}"
    );
    assert!(
        stderr.contains("authenticated enforcement")
            && stderr.contains("private Corgea intelligence"),
        "tokenless warning must name the authenticated benefit: {stderr}"
    );
}

#[test]
fn withheld_token_discloses_public_mode_and_names_opt_in() {
    // The cohort this PR creates: a token exists, but it is not sent to this
    // vuln-api, so verdicts stay public and lookup failures warn. The old hint
    // keyed off "has a token" and went silent here.
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), Some("opaque-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("your token is not sent to this vuln-api"),
        "a withheld token must be disclosed, not silently downgraded: {stderr}"
    );
    assert!(
        stderr.contains("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL"),
        "withheld-token warning must name the opt-in: {stderr}"
    );
    assert!(
        !stderr.contains("login enables"),
        "a logged-in user must not be told to log in: {stderr}"
    );
}

#[test]
fn withheld_token_reports_public_verdict_mode_in_json() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), Some("opaque-token"), 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["verdict_mode"], "public");
}

#[test]
fn custom_vuln_api_url_with_token_does_not_send_token_by_default() {
    let (base_url, requests) = spawn_capturing_vuln_api_stub();
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
    h.cmd.env("CORGEA_VULN_API_URL", &base_url);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    let captured = requests.lock().unwrap();
    let request = captured.first().expect("one vuln-api request");
    assert!(header_value(request, "Authorization").is_none());
    assert!(header_value(request, "CORGEA-TOKEN").is_none());
}

#[test]
fn custom_vuln_api_url_sends_token_only_with_opt_in() {
    let (base_url, requests) = spawn_capturing_vuln_api_stub();
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
    h.cmd
        .env("CORGEA_VULN_API_URL", &base_url)
        .env("CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL", "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    // The opt-in puts the gate in authenticated mode, and pip_harness's tree
    // pass degrades to named-only, so the install fails closed (exit 1) — but
    // the named target's verdict request is still made first, which is what
    // this test asserts: with the opt-in, the token IS sent to the custom URL.
    assert_eq!(out.status.code(), Some(1));
    let captured = requests.lock().unwrap();
    let request = captured.first().expect("one vuln-api request");
    assert_eq!(
        header_value(request, "CORGEA-TOKEN").as_deref(),
        Some("opaque-token")
    );
    assert!(header_value(request, "Authorization").is_none());
}

#[test]
fn json_carries_verdict_object_and_mode() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-0001", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["verdict_mode"], "public");
    assert_eq!(parsed["results"][0]["verdict"]["status"], "vulnerable");
    assert_eq!(
        parsed["results"][0]["verdict"]["matches"][0]["advisory_id"],
        "CVE-2024-0001"
    );
    assert_eq!(
        parsed["results"][0]["verdict"]["matches"][0]["fixed_version"],
        "2.0.0"
    );
    assert_eq!(parsed["summary"]["named"]["vulnerable"], 1);
}

#[test]
fn vuln_api_outage_warns_but_installs() {
    let mut h = pip_harness(HashMap::new(), HashMap::new(), None, 0);
    // Point the gate at a dead vuln-api: connection refused on every check.
    h.cmd.env("CORGEA_VULN_API_URL", "http://127.0.0.1:1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "public lookup outage must fail open"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("CVE check unavailable; continuing because public mode is fail-open"),
        "stderr: {stderr}"
    );
}

#[test]
fn malicious_pin_blocks_with_distinct_message() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evilpkg", "1.0.0"),
        malicious_body("pypi", "evilpkg", "1.0.0", "MAL-2024-9999", None),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "evilpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        h.recorded_argv(),
        None,
        "pip must not run on a malicious verdict"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("known malicious:"), "stdout: {stdout}");
    assert!(stdout.contains("1 malicious"), "summary segment: {stdout}");
    assert!(stdout.contains("MAL-2024-9999"), "stdout: {stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "Refusing to run install: known MALICIOUS package(s) detected. Pass --force only if you are certain."
        ),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("corgea pip --force install"),
        "escape hint must still spell the bypass: {stderr}"
    );
}

#[test]
fn force_overrides_malicious_block_and_propagates_exit_code() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evilpkg", "1.0.0"),
        malicious_body("pypi", "evilpkg", "1.0.0", "MAL-2024-9999", None),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 7);
    let out = h
        .cmd
        .args(["pip", "--force", "install", "evilpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(7),
        "manager exit code must propagate under --force"
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install evilpkg==1.0.0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("known malicious:"),
        "findings must still print under --force: {stdout}"
    );
}

#[test]
fn merely_vulnerable_output_never_says_malicious() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-4242", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1), "still blocks as vulnerable");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !all.to_lowercase().contains("malicious"),
        "a merely-vulnerable package must never be labeled malicious: {all}"
    );
}

#[test]
fn json_malicious_status_flag_and_counts_under_schema_v2() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evilpkg", "1.0.0"),
        malicious_body("pypi", "evilpkg", "1.0.0", "MAL-2024-9999", None),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "evilpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["schema_version"], 2);
    assert_eq!(parsed["results"][0]["verdict"]["status"], "malicious");
    assert_eq!(
        parsed["results"][0]["verdict"]["matches"][0]["malware"],
        true
    );
    assert_eq!(parsed["summary"]["named"]["malicious"], 1);
    assert_eq!(
        parsed["summary"]["named"]["vulnerable"], 0,
        "malicious is tallied separately, not double-counted as vulnerable"
    );
}

/// Mixed report — one malicious target and one merely-vulnerable target:
/// both labels render, tallies stay separate (no double-count), and the
/// Malware refusal wins over the generic Findings copy (resolved Q2 top
/// precedence at the E2E level).
#[test]
fn mixed_targets_tally_separately_and_malicious_refusal_wins() {
    let mut checks = HashMap::new();
    checks.insert(
        key("pypi", "evilpkg", "1.0.0"),
        malicious_body("pypi", "evilpkg", "1.0.0", "MAL-2024-9999", None),
    );
    checks.insert(
        key("pypi", "oldpkg", "1.0.0"),
        vulnerable_body("pypi", "oldpkg", "1.0.0", "CVE-2024-4242", Some("2.0.0")),
    );
    let mut h = pip_harness(checks, HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "evilpkg==1.0.0", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("known malicious:"), "stdout: {stdout}");
    assert!(stdout.contains("known vulnerable:"), "stdout: {stdout}");
    assert!(
        stdout.contains("1 malicious, 1 vulnerable"),
        "separate summary tallies, no double-count: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("known MALICIOUS package(s) detected"),
        "Malware refusal must beat the generic Findings copy: {stderr}"
    );
}

#[test]
fn small_set_emits_resolve_and_verdict_progress_on_stderr() {
    // A 2-package set (≤ the old `>8` gate) must still narrate its phases on
    // stderr — the reported "looks like a hang" symptom. Empty `checks` ⇒ the
    // vuln-api stub answers clean, so the install proceeds and pip runs.
    let mut h = pip_harness(HashMap::new(), HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "install", "pkga==1.0.0", "pkgb==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "two clean pins proceed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        h.recorded_argv().as_deref(),
        Some("install pkga==1.0.0 pkgb==1.0.0")
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("resolving named package targets"),
        "stderr must narrate named resolution: {stderr}"
    );
    assert!(
        stderr.contains("resolving the would-install dependency tree"),
        "stderr must narrate tree resolution: {stderr}"
    );
    assert!(
        stderr.contains("checking 2 packages against Corgea vuln-api"),
        "stderr must narrate the verdict pass for a small set: {stderr}"
    );
}

#[test]
fn small_set_progress_keeps_json_stdout_clean() {
    // Under --json the same stderr trail must appear while stdout stays exactly
    // one parseable Corgea document.
    let mut h = pip_harness(HashMap::new(), HashMap::new(), None, 0);
    let out = h
        .cmd
        .args(["pip", "--json", "install", "pkga==1.0.0", "pkgb==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("resolving named package targets"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("checking 2 packages against Corgea vuln-api"),
        "stderr: {stderr}"
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be exactly one JSON document");
    assert_eq!(parsed["schema_version"], 2);
}

// --- install_gate_fail_closed: fail closed without sending a token ---------

const FAIL_CLOSED_ENV: &str = "CORGEA_INSTALL_GATE_FAIL_CLOSED";

/// Public mode (no token) with a full pip tree, where vuln-api answers 503
/// for the named `oldpkg`. The tree pass succeeds, so a block here is the
/// unverifiable verdict's doing, not a degraded tree.
fn named_503_full_tree() -> common::GateHarness {
    let mut statuses = HashMap::new();
    statuses.insert(key("pypi", "oldpkg", "1.0.0"), 503u16);
    common::tree_harness("pip", HashMap::new(), statuses, common::TREE_REPORT)
}

/// Point `h` at a fresh HOME whose `~/.corgea/config.toml` holds `extra`
/// on top of the required fields. Returns the dir to keep it alive.
fn with_config_file(h: &mut common::GateHarness, extra: &str) -> tempfile::TempDir {
    let home = tempfile::TempDir::new().expect("temp HOME");
    let dir = home.path().join(".corgea");
    std::fs::create_dir_all(&dir).expect("mkdir .corgea");
    std::fs::write(
        dir.join("config.toml"),
        format!("url = \"https://www.corgea.app\"\ndebug = 0\ntoken = \"\"\n{extra}\n"),
    )
    .expect("write config.toml");
    h.cmd
        .env("HOME", home.path())
        .env("USERPROFILE", home.path());
    home
}

#[test]
fn fail_closed_setting_blocks_unverifiable_verdict_without_token() {
    let mut h = named_503_full_tree();
    h.cmd.env(FAIL_CLOSED_ENV, "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the setting must fail closed on a 503 without a token; stderr: {stderr}"
    );
    assert_eq!(h.recorded_argv(), None, "pip must not run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not be verified"), "stdout: {stdout}");
    assert!(
        stderr.contains("--force"),
        "block must name --force: {stderr}"
    );
    assert!(
        !stderr.contains("fail-open") && !stderr.contains("continuing"),
        "a fail-closed run must not claim it continues: {stderr}"
    );
    assert!(
        !stderr.contains("login enables authenticated enforcement"),
        "enforcement is already on; the hint must not offer it: {stderr}"
    );
}

#[test]
fn fail_closed_setting_blocks_resolution_error_without_token() {
    // `==2.0.0` is unknown to the wildcard registry (it serves 1.0.0 only):
    // a resolution error. The pip tree pass succeeds, so only the error can
    // block.
    let mut h = common::GateHarness::new()
        .fake_tree_pm("pip", common::TREE_REPORT, 0)
        .wildcard_pypi_registry()
        .build();
    h.cmd.env(FAIL_CLOSED_ENV, "true");
    let out = h
        .cmd
        .args(["pip", "install", "nosuchpkg==2.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "the setting must fail closed on a resolution error; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv(), None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 errors"), "stdout: {stdout}");
    assert!(
        !stdout.contains("ungated"),
        "a blocked target is gated; output must not say otherwise: {stdout}"
    );
}

#[test]
fn fail_closed_setting_with_custom_url_blocks_and_never_sends_the_token() {
    // Token + custom vuln-api URL + no send-token opt-in: public mode. The
    // setting makes it fail closed (pip_harness's tree pass degrades to
    // named-only, which a manager with a resolver blocks on) without sending
    // the token anywhere.
    let (base_url, requests) = spawn_capturing_vuln_api_stub();
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
    h.cmd
        .env("CORGEA_VULN_API_URL", &base_url)
        .env(FAIL_CLOSED_ENV, "1");
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert_eq!(h.recorded_argv(), None);
    let captured = requests.lock().unwrap();
    assert!(
        !captured.is_empty(),
        "the named verdict must still be looked up"
    );
    for request in captured.iter() {
        assert!(header_value(request, "Authorization").is_none());
        assert!(header_value(request, "CORGEA-TOKEN").is_none());
    }
    assert!(
        stderr.contains("your token is not sent to this vuln-api"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("warn instead of blocking"),
        "with the setting on, failures block: {stderr}"
    );
}

#[test]
fn fail_closed_setting_yields_to_force() {
    let mut h = named_503_full_tree();
    h.cmd.env(FAIL_CLOSED_ENV, "1");
    let out = h
        .cmd
        .args(["pip", "--force", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--force must proceed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.recorded_argv().as_deref(), Some("install oldpkg==1.0.0"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("public mode is fail-open"),
        "it proceeds because of --force, not fail-open: {stderr}"
    );
    assert!(
        stderr.contains("continuing under --force"),
        "stderr must say why it proceeds: {stderr}"
    );
    let hint = stderr
        .lines()
        .find(|l| l.contains("using public CVE checks"))
        .unwrap_or_else(|| panic!("public-mode hint missing: {stderr}"));
    assert!(
        hint.contains("unless --force"),
        "a forced run proceeds, so the hint must not say failures simply block: {hint}"
    );
}

#[test]
fn fail_closed_setting_reads_config_file_and_env_overrides_it_both_ways() {
    // (config file line, env value, expected exit). Exit 1 = blocked.
    let cases = [
        ("install_gate_fail_closed = true", None, 1),
        ("install_gate_fail_closed = true", Some("0"), 0),
        ("install_gate_fail_closed = false", Some("1"), 1),
        ("install_gate_fail_closed = false", None, 0),
        // A config written before the field existed loads with it off.
        ("", None, 0),
    ];
    for (line, env, expected) in cases {
        let mut h = named_503_full_tree();
        let _home = with_config_file(&mut h, line);
        if let Some(v) = env {
            h.cmd.env(FAIL_CLOSED_ENV, v);
        }
        let out = h
            .cmd
            .args(["pip", "install", "oldpkg==1.0.0"])
            .output()
            .expect("run corgea");
        assert_eq!(
            out.status.code(),
            Some(expected),
            "config {line:?}, env {env:?}; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn json_reports_fail_closed_alongside_unchanged_verdict_mode() {
    for (env, expected) in [(None, false), (Some("1"), true)] {
        let mut h = named_503_full_tree();
        if let Some(v) = env {
            h.cmd.env(FAIL_CLOSED_ENV, v);
        }
        let out = h
            .cmd
            .args(["pip", "--json", "install", "oldpkg==1.0.0"])
            .output()
            .expect("run corgea");
        let parsed: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
        assert_eq!(parsed["verdict_mode"], "public", "the token-send mode");
        assert_eq!(parsed["fail_closed"], expected, "env {env:?}");
    }
}

#[test]
fn withheld_token_hint_names_the_fail_closed_setting() {
    // Setting off: the warning must offer the token-free way to enforce.
    let mut h = pip_harness(HashMap::new(), HashMap::new(), Some("opaque-token"), 0);
    let out = h
        .cmd
        .args(["pip", "install", "oldpkg==1.0.0"])
        .output()
        .expect("run corgea");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(FAIL_CLOSED_ENV), "stderr: {stderr}");
}
