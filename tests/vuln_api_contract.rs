//! Contract tests for the vuln-api client over the full HTTP path.
//!
//! Two backends, one contract:
//!   * the in-process stub (hermetic, always on), serving the committed
//!     fixture bodies so the stub can't drift from the real serialization;
//!   * the staging worker (`#[ignore]`d — network), asserting the
//!     deterministic targets documented in `tests/fixtures/vuln_api/README.md`.
//!
//! Run the staging half with:
//!   cargo test --test vuln_api_contract -- --ignored
//!
//! The hermetic stub backend runs in the default `./harness ci` gate. The
//! `#[ignore]`d staging backend runs out-of-band on a schedule (non-blocking)
//! via `.github/workflows/staging-contract.yml`, so endpoint/schema/seed
//! drift in the live worker is caught instead of shipping undetected.

mod common;

use corgea::vuln_api::{
    check_package_version, fetch_package_profile, http_client, Ecosystem, PackageProfile,
    VulnCheckResponse,
};
use corgea::vuln_api_stub::{
    key, profile_key, spawn_with_profiles, spawn_with_statuses, vulnerable_body,
};
use std::collections::HashMap;

const STAGING_URL: &str = "https://cve-worker-staging.corgea.workers.dev";

fn check(
    base_url: &str,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
    let client = http_client().expect("client");
    // Contract tests run the public (tokenless) mode.
    check_package_version(&client, base_url, None, ecosystem, name, version)
}

fn fixture_body(name: &str) -> String {
    std::fs::read_to_string(common::fixture(&format!("vuln_api/{name}"))).expect("read fixture")
}

// ---- stub-backed (hermetic) ----

#[test]
fn stub_vulnerable_verdict_roundtrip() {
    let stub = spawn_with_statuses(
        HashMap::from([(
            key("npm", "axios", "0.21.0"),
            vulnerable_body("npm", "axios", "0.21.0", "CVE-2021-3749", Some("0.21.2")),
        )]),
        HashMap::new(),
    );
    let verdict = check(&stub.base_url, Ecosystem::Npm, "axios", "0.21.0").unwrap();
    assert!(verdict.is_vulnerable);
    assert_eq!(verdict.matches[0].advisory_id, "CVE-2021-3749");
    assert_eq!(verdict.matches[0].fixed_version.as_deref(), Some("0.21.2"));
}

#[test]
fn stub_unknown_package_is_clean() {
    let stub = spawn_with_statuses(HashMap::new(), HashMap::new());
    let verdict = check(&stub.base_url, Ecosystem::Npm, "no-such-package", "1.0.0").unwrap();
    assert!(!verdict.is_vulnerable);
    assert!(verdict.matches.is_empty());
}

#[test]
fn stub_serves_committed_fixture_bodies() {
    // The four committed fixtures, end to end through the client: the
    // contract's serialization examples must survive the full HTTP path,
    // identity guard included.
    let stub = spawn_with_statuses(
        HashMap::from([
            (
                key("pypi", "requests", "2.31.0"),
                fixture_body("check_clean.json"),
            ),
            (
                key("pypi", "django", "3.2.0"),
                fixture_body("check_vulnerable.json"),
            ),
            (
                key("npm", "wozhendeshitule", "1.0.0"),
                fixture_body("check_malware.json"),
            ),
            (
                key("pypi", "this-package-does-not-exist", "9.9.9"),
                fixture_body("check_unknown.json"),
            ),
        ]),
        HashMap::new(),
    );

    let clean = check(&stub.base_url, Ecosystem::Pypi, "requests", "2.31.0").unwrap();
    assert!(!clean.is_vulnerable);

    let vulnerable = check(&stub.base_url, Ecosystem::Pypi, "django", "3.2.0").unwrap();
    assert!(vulnerable.is_vulnerable);
    assert_eq!(
        vulnerable.matches[0].fixed_version.as_deref(),
        Some("3.2.5")
    );

    let malware = check(&stub.base_url, Ecosystem::Npm, "wozhendeshitule", "1.0.0").unwrap();
    assert!(malware.is_vulnerable);
    assert!(malware.matches[0].advisory_id.starts_with("MAL-"));
    assert!(malware.matches[0].fixed_version.is_none());

    let unknown = check(
        &stub.base_url,
        Ecosystem::Pypi,
        "this-package-does-not-exist",
        "9.9.9",
    )
    .unwrap();
    assert!(!unknown.is_vulnerable);
}

#[test]
fn stub_server_error_surfaces_as_unavailable() {
    let stub = spawn_with_statuses(
        HashMap::from([(key("npm", "flaky", "1.0.0"), "{}".to_string())]),
        HashMap::from([(key("npm", "flaky", "1.0.0"), 503u16)]),
    );
    let err = check(&stub.base_url, Ecosystem::Npm, "flaky", "1.0.0").unwrap_err();
    assert!(err.to_string().contains("unavailable (HTTP 503)"));
}

#[test]
fn fixture_package_profile_deserializes() {
    // The committed profile fixture (full server serialization) must
    // deserialize into the CLI's tolerant subset — ignored fields and all.
    let parsed: PackageProfile =
        serde_json::from_str(&fixture_body("package_profile.json")).expect("parse profile fixture");
    assert_eq!(parsed.package.ecosystem, "npm");
    assert_eq!(parsed.package.name, "axios");
    assert_eq!(parsed.advisories.len(), 2);
    assert!(parsed.advisories.iter().any(|a| a.malware == Some(true)));
}

#[test]
fn stub_profile_roundtrip_and_not_found() {
    let stub = spawn_with_profiles(
        HashMap::new(),
        HashMap::new(),
        HashMap::from([(
            profile_key("npm", "axios"),
            fixture_body("package_profile.json"),
        )]),
        HashMap::new(),
    );
    let client = http_client().expect("client");
    let profile = fetch_package_profile(&client, &stub.base_url, None, Ecosystem::Npm, "axios")
        .unwrap()
        .expect("known package should be Some");
    assert_eq!(profile.advisories.len(), 2);

    let missing =
        fetch_package_profile(&client, &stub.base_url, None, Ecosystem::Npm, "no-such-pkg")
            .unwrap();
    assert!(missing.is_none(), "unknown package profile is Ok(None)");
}

// ---- staging (network, deterministic targets) ----

fn assert_staging_vulnerable(ecosystem: Ecosystem, name: &str, version: &str) {
    let verdict = check(STAGING_URL, ecosystem, name, version)
        .unwrap_or_else(|e| panic!("staging check {name}@{version} failed: {e}"));
    assert!(
        verdict.is_vulnerable,
        "{name}@{version} should be vulnerable"
    );
    assert!(!verdict.matches.is_empty());
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_axios_0_21_0_is_vulnerable_with_remediation() {
    let verdict = check(STAGING_URL, Ecosystem::Npm, "axios", "0.21.0").unwrap();
    assert!(verdict.is_vulnerable);
    // Remediation data: at least one advisory carries a fixed version.
    assert!(verdict.matches.iter().any(|m| m.fixed_version.is_some()));
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_minimist_0_0_8_is_vulnerable() {
    assert_staging_vulnerable(Ecosystem::Npm, "minimist", "0.0.8");
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_node_fetch_2_6_0_is_vulnerable() {
    assert_staging_vulnerable(Ecosystem::Npm, "node-fetch", "2.6.0");
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_mezzanine_6_0_0_is_vulnerable() {
    assert_staging_vulnerable(Ecosystem::Pypi, "mezzanine", "6.0.0");
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_unknown_package_profile_is_not_found() {
    // Pins the worker's package-miss sentinel body: fetch_package_profile
    // maps a 404 to Ok(None) only when it carries {"error":"Package not
    // found"}, so this fails if the worker ever changes that body.
    let client = http_client().expect("client");
    let missing = fetch_package_profile(
        &client,
        STAGING_URL,
        None,
        Ecosystem::Npm,
        "corgea-contract-test-nonexistent",
    )
    .unwrap();
    assert!(missing.is_none(), "sentinel 404 should map to Ok(None)");
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_unknown_package_is_clean() {
    let verdict = check(
        STAGING_URL,
        Ecosystem::Npm,
        "corgea-contract-test-nonexistent",
        "1.0.0",
    )
    .unwrap();
    assert!(!verdict.is_vulnerable);
    assert!(verdict.matches.is_empty());
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_axios_profile_lists_advisories() {
    let client = http_client().expect("client");
    let profile = fetch_package_profile(&client, STAGING_URL, None, Ecosystem::Npm, "axios")
        .unwrap()
        .expect("axios should have a profile row");
    assert!(
        !profile.advisories.is_empty(),
        "axios profile should list advisories"
    );
}

#[test]
#[ignore = "network: hits the staging vuln-api"]
fn staging_unknown_package_profile_is_none() {
    let client = http_client().expect("client");
    let profile = fetch_package_profile(
        &client,
        STAGING_URL,
        None,
        Ecosystem::Npm,
        "corgea-contract-test-nonexistent",
    )
    .unwrap();
    assert!(profile.is_none(), "unknown package profile is Ok(None)");
}
