#![cfg(unix)]
mod common;

use corgea::vuln_api_stub::{self, key};
use std::collections::HashMap;

/// Run `corgea advisories check <args>` against `stub_url` in an isolated env.
fn advisories_check(stub_url: &str, args: &[&str]) -> std::process::Output {
    let (mut cmd, _home) = common::corgea_isolated();
    cmd.env("CORGEA_VULN_API_URL", stub_url)
        .arg("advisories")
        .arg("check")
        .args(args);
    cmd.output().expect("run corgea advisories")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn vulnerable_version_exits_1_with_advisory_lines() {
    let body = vuln_api_stub::vulnerable_body(
        "npm",
        "leftpad",
        "1.0.0",
        "GHSA-aaaa-bbbb-cccc",
        Some("2.0.0"),
    );
    let stub = vuln_api_stub::spawn_with_statuses(
        HashMap::from([(key("npm", "leftpad", "1.0.0"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "leftpad@1.0.0"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("GHSA-aaaa-bbbb-cccc"), "stdout: {s}");
    assert!(s.contains("critical"), "stdout: {s}");
    assert!(s.contains("fixed in 2.0.0"), "stdout: {s}");
    assert!(s.contains("→ safe version: leftpad@2.0.0"), "stdout: {s}");
}

#[test]
fn clean_version_exits_0() {
    // Unscripted key → stub default clean 200.
    let stub = vuln_api_stub::spawn_with_statuses(HashMap::new(), HashMap::new());
    let out = advisories_check(&stub.base_url, &["npm", "leftpad@1.0.0"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("clean"), "stdout: {}", stdout(&out));
}

#[test]
fn scoped_npm_spec_parses() {
    // Scripted scoped key proves the last-`@` split reached the wire correctly.
    let body =
        vuln_api_stub::vulnerable_body("npm", "@scope/pkg", "1.0.0", "GHSA-scope", Some("1.2.0"));
    let stub = vuln_api_stub::spawn_with_statuses(
        HashMap::from([(key("npm", "@scope/pkg", "1.0.0"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "@scope/pkg@1.0.0"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("GHSA-scope"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn server_error_exits_2() {
    let stub = vuln_api_stub::spawn_with_statuses(
        HashMap::new(),
        HashMap::from([(key("npm", "leftpad", "1.0.0"), 500u16)]),
    );
    let out = advisories_check(&stub.base_url, &["npm", "leftpad@1.0.0"]);
    assert_eq!(out.status.code(), Some(2), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("vuln-api unavailable"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn auth_required_exits_2() {
    // 401 with no token in the isolated env: tokenless user gets a clear
    // error, not a false clean.
    let stub = vuln_api_stub::spawn_with_statuses(
        HashMap::new(),
        HashMap::from([(key("npm", "leftpad", "1.0.0"), 401u16)]),
    );
    let out = advisories_check(&stub.base_url, &["npm", "leftpad@1.0.0"]);
    assert_eq!(out.status.code(), Some(2), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("vuln-api requires authentication"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn bad_args_exit_2_without_network() {
    // Dead port proves parsing fails before any dial.
    let dead = "http://127.0.0.1:9";
    for args in [
        vec!["rubygems", "foo@1.0.0"], // unknown ecosystem
        vec!["npm", "foo@"],           // trailing @
        vec!["npm", "foo@^1.0"],       // range
    ] {
        let out = advisories_check(dead, &args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "args {args:?} should exit 2; stdout: {}",
            stdout(&out)
        );
        assert!(
            !stderr(&out).is_empty(),
            "args {args:?} should print a stderr message"
        );
    }
}

#[test]
fn json_vulnerable_document() {
    let body = vuln_api_stub::vulnerable_body(
        "npm",
        "leftpad",
        "1.0.0",
        "GHSA-aaaa-bbbb-cccc",
        Some("2.0.0"),
    );
    let stub = vuln_api_stub::spawn_with_statuses(
        HashMap::from([(key("npm", "leftpad", "1.0.0"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "leftpad@1.0.0", "--json"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["ecosystem"], "npm");
    assert_eq!(doc["package"], "leftpad");
    assert_eq!(doc["version"], "1.0.0");
    assert_eq!(doc["verdict"]["status"], "vulnerable");
    assert_eq!(
        doc["verdict"]["matches"][0]["advisory_id"],
        "GHSA-aaaa-bbbb-cccc"
    );
    assert_eq!(doc["verdict"]["matches"][0]["fixed_version"], "2.0.0");
    assert_eq!(doc["verdict"]["remediation"], "2.0.0");
}

#[test]
fn json_clean_document() {
    let stub = vuln_api_stub::spawn_with_statuses(HashMap::new(), HashMap::new());
    let out = advisories_check(&stub.base_url, &["npm", "leftpad@1.0.0", "--json"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["verdict"]["status"], "clean");
    assert!(
        doc["verdict"].get("matches").is_none(),
        "clean verdict has no matches key: {doc}"
    );
}

#[test]
fn json_error_document_on_500() {
    let stub = vuln_api_stub::spawn_with_statuses(
        HashMap::new(),
        HashMap::from([(key("npm", "leftpad", "1.0.0"), 500u16)]),
    );
    let out = advisories_check(&stub.base_url, &["npm", "leftpad@1.0.0", "--json"]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["schema_version"], 1);
    assert!(
        doc["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unavailable"),
        "error document: {doc}"
    );
}

#[test]
fn json_error_document_on_bad_spec() {
    let dead = "http://127.0.0.1:9";
    let out = advisories_check(dead, &["npm", "foo@", "--json"]);
    assert_eq!(out.status.code(), Some(2), "stdout: {}", stdout(&out));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["schema_version"], 1);
    assert!(doc["error"].is_string(), "error document: {doc}");
}

#[test]
fn json_stdout_is_exactly_one_document() {
    // The strongest purity assertion: parsing the ENTIRE stdout as one json
    // value fails on any trailing junk.
    let body = vuln_api_stub::vulnerable_body(
        "npm",
        "leftpad",
        "1.0.0",
        "GHSA-aaaa-bbbb-cccc",
        Some("2.0.0"),
    );
    let stub = vuln_api_stub::spawn_with_statuses(
        HashMap::from([(key("npm", "leftpad", "1.0.0"), body)]),
        HashMap::new(),
    );
    for args in [
        vec!["npm", "leftpad@1.0.0", "--json"], // vulnerable
        vec!["npm", "other@1.0.0", "--json"],   // clean (unscripted key)
    ] {
        let out = advisories_check(&stub.base_url, &args);
        serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .unwrap_or_else(|e| panic!("args {args:?}: stdout not one json document: {e}"));
    }
}

// ---- unversioned form (package profile listing) ----

const TWO_ADVISORIES: &str = r#"[{"id":"GHSA-aaaa-bbbb-cccc","severity":"high","cvss_score":7.5,"tier":1},
        {"id":"MAL-2024-0001","severity":"critical","malware":true}]"#;

#[test]
fn package_with_advisories_exits_1() {
    let body = vuln_api_stub::profile_body("npm", "axios", TWO_ADVISORIES);
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "axios"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "axios"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("GHSA-aaaa-bbbb-cccc"), "stdout: {s}");
    assert!(s.contains("MAL-2024-0001"), "stdout: {s}");
    assert!(s.contains("high"), "stdout: {s}");
    assert!(s.contains("[malware]"), "stdout: {s}");
}

#[test]
fn package_with_advisories_json() {
    let body = vuln_api_stub::profile_body("npm", "axios", TWO_ADVISORIES);
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "axios"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "axios", "--json"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["ecosystem"], "npm");
    assert_eq!(doc["package"], "axios");
    assert_eq!(doc["found"], true);
    assert_eq!(doc["advisories"].as_array().unwrap().len(), 2);
    assert_eq!(doc["advisories"][0]["id"], "GHSA-aaaa-bbbb-cccc");
    assert_eq!(doc["possibly_truncated"], false);
}

#[test]
fn package_with_no_advisories_exits_0() {
    let body = vuln_api_stub::profile_body("npm", "axios", "[]");
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "axios"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "axios"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("no known advisories"),
        "stdout: {}",
        stdout(&out)
    );

    let out = advisories_check(&stub.base_url, &["npm", "axios", "--json"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["found"], true);
    assert_eq!(doc["advisories"].as_array().unwrap().len(), 0);
}

#[test]
fn unknown_package_exits_0_with_note() {
    // Unscripted profile key → 404 → Ok(None), a legitimate "clean" answer.
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "no-such-pkg"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("not found in the advisory database"),
        "stdout: {}",
        stdout(&out)
    );

    let out = advisories_check(&stub.base_url, &["npm", "no-such-pkg", "--json"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["found"], false);
    assert_eq!(doc["advisories"].as_array().unwrap().len(), 0);
}

#[test]
fn profile_generic_404_exits_2() {
    // A 404 without the worker's package-miss sentinel (wrong host, older
    // deployment, proxy/CDN) is an error, not a clean "no advisories" answer.
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "axios"), 404u16)]),
    );
    let out = advisories_check(&stub.base_url, &["npm", "axios"]);
    assert_eq!(out.status.code(), Some(2), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("CORGEA_VULN_API_URL"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn profile_identity_mismatch_exits_2() {
    let body = vuln_api_stub::profile_body("npm", "left-pad", "[]");
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "axios"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "axios"]);
    assert_eq!(out.status.code(), Some(2), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("does not match request"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn profile_server_error_exits_2() {
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "axios"), 500u16)]),
    );
    let out = advisories_check(&stub.base_url, &["npm", "axios"]);
    assert_eq!(out.status.code(), Some(2), "stdout: {}", stdout(&out));
    assert!(
        stderr(&out).contains("vuln-api unavailable"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn exactly_100_advisories_flags_possible_truncation() {
    let advisories: Vec<String> = (0..100)
        .map(|i| format!(r#"{{"id":"GHSA-{i:04}","severity":"high"}}"#))
        .collect();
    let arr = format!("[{}]", advisories.join(","));
    let body = vuln_api_stub::profile_body("npm", "axios", &arr);
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "axios"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "axios"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("listing capped at 100; more may exist"),
        "stdout: {}",
        stdout(&out)
    );

    let out = advisories_check(&stub.base_url, &["npm", "axios", "--json"]);
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["possibly_truncated"], true);

    // A 2-advisory case must NOT flag truncation.
    let body = vuln_api_stub::profile_body("npm", "small", TWO_ADVISORIES);
    let stub = vuln_api_stub::spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(vuln_api_stub::profile_key("npm", "small"), body)]),
        HashMap::new(),
    );
    let out = advisories_check(&stub.base_url, &["npm", "small", "--json"]);
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is a single json document");
    assert_eq!(doc["possibly_truncated"], false);
}
