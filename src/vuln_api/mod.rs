//! Corgea vuln-api client.
//!
//! Deliberately independent of `utils::api::SHARED_CLIENT` because:
//!   * the vuln-api host is user-configurable via `CORGEA_VULN_API_URL`,
//!     so we must never silently replay Corgea cookies / non-JWT
//!     `CORGEA-TOKEN` headers via redirect following or the shared
//!     cookie jar.
//!   * the shared client's `check_for_warnings` exits the process on
//!     HTTP 410, which is wrong for per-dep CVE lookups.
//!
//! The auth header is attached explicitly per call from a caller-owned
//! token (no global state).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::log::debug;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnCheckResponse {
    pub ecosystem: String,
    pub package_name: String,
    pub version: String,
    pub is_vulnerable: bool,
    pub matches: Vec<VulnMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnMatch {
    pub advisory_id: String,
    pub severity_level: String,
    pub tier: u8,
    pub vulnerable_version_range: Option<String>,
    pub fixed_version: Option<String>,
}

/// Subset of `GET /v1/advisories/:id` we consume.
///
/// Field-name notes (kept stable for callers, but mapped to the real
/// server shape via `#[serde(rename = …)]`):
///
/// * `advisory_id` ← server's `id`
/// * `url` ← server's `source_url`
/// * `tier` is `Option<u8>` because the server may emit `null`
///   (see `VULNERABILITY_SERVICE.md` §5).
///
/// The server also returns many fields we don't currently use
/// (`alias`, `summary`, `severity`, `severity_badge`, `tier_score`,
/// `llm_summary`, `packages`, `cwes`, `raw`, …). `serde` ignores
/// unknown fields by default; we add them here only when a caller
/// needs them. No top-level `remediation` field exists on the
/// server — do not add one (server's `llm_summary` is a 1-2 sentence
/// developer summary, not remediation guidance, and the semantics
/// differ).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryResponse {
    #[serde(rename = "id")]
    pub advisory_id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub severity_level: Option<String>,
    #[serde(default)]
    pub tier: Option<u8>,
    #[serde(default, rename = "source_url")]
    pub url: Option<String>,
}

fn user_agent() -> String {
    format!("corgea-cli/{} (vuln-api)", env!("CARGO_PKG_VERSION"))
}

fn http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(user_agent())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("failed to build vuln-api http client: {}", e))
}

fn is_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

fn normalize_base_url(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

/// Encode package name for the vuln-api path segment.
/// npm scoped names: `@scope/pkg` → `@scope%2fpkg` (mirrors registry.rs).
fn encode_package_name(ecosystem: &str, name: &str) -> String {
    if ecosystem.eq_ignore_ascii_case("npm") {
        if let Some(stripped) = name.strip_prefix('@') {
            if let Some((scope, pkg)) = stripped.split_once('/') {
                return format!("@{}%2f{}", scope, pkg);
            }
        }
        name.to_string()
    } else {
        urlencoding::encode(name).into_owned()
    }
}

pub fn check_package_version(
    base_url: &str,
    token: &str,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
    if token.is_empty() {
        return Err("missing Corgea token for vuln-api request".into());
    }
    let base = normalize_base_url(base_url);
    if base.is_empty() {
        return Err("vuln-api base URL is empty".into());
    }
    let encoded_name = encode_package_name(ecosystem, name);
    let encoded_version = urlencoding::encode(version);
    let url = format!(
        "{}/v1/packages/{}/{}/versions/{}/check",
        base, ecosystem, encoded_name, encoded_version
    );

    let client = http_client()?;
    debug(&format!("Sending vuln-api request to URL: {}", url));

    let mut req = client
        .get(&url)
        .header("Accept", "application/json")
        .header("CORGEA-SOURCE", "cli");
    if is_jwt(token) {
        req = req.header("Authorization", format!("Bearer {}", token));
    } else {
        req = req.header("CORGEA-TOKEN", token);
    }

    let response = req
        .send()
        .map_err(|e| format!("Failed to send vuln-api request: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Error: Unable to check package version. Status code: {}",
            status
        )
        .into());
    }

    let response_text = response.text()?;
    let parsed: VulnCheckResponse = serde_json::from_str(&response_text).map_err(|e| {
        debug(&format!(
            "Failed to parse vuln-api response: {}. Body: {}",
            e, response_text
        ));
        format!("Failed to parse vuln-api response: {}", e)
    })?;

    // Confused-deputy guard: refuse to attribute advisories to a different
    // (name, version, ecosystem) than what we asked about. The server is
    // allowed to be silent on identity, but if it answers, it must match.
    if !parsed.ecosystem.is_empty() && !parsed.ecosystem.eq_ignore_ascii_case(ecosystem) {
        return Err(format!(
            "vuln-api response ecosystem '{}' does not match request '{}'",
            parsed.ecosystem, ecosystem
        )
        .into());
    }
    if !parsed.package_name.is_empty() && !parsed.package_name.eq_ignore_ascii_case(name) {
        return Err(format!(
            "vuln-api response package '{}' does not match request '{}'",
            parsed.package_name, name
        )
        .into());
    }
    if !parsed.version.is_empty() && parsed.version != version {
        return Err(format!(
            "vuln-api response version '{}' does not match request '{}'",
            parsed.version, version
        )
        .into());
    }

    // is_vulnerable=true with no matches is contradictory — treat as an
    // error so the caller can surface it rather than silently demoting
    // the dep to "clean".
    if parsed.is_vulnerable && parsed.matches.is_empty() {
        return Err(
            "vuln-api reported is_vulnerable=true with no matches; refusing to interpret".into(),
        );
    }

    Ok(parsed)
}

pub fn get_advisory(
    base_url: &str,
    token: &str,
    advisory_id: &str,
) -> Result<AdvisoryResponse, Box<dyn std::error::Error>> {
    if token.is_empty() {
        return Err("missing Corgea token for vuln-api request".into());
    }
    let base = normalize_base_url(base_url);
    if base.is_empty() {
        return Err("vuln-api base URL is empty".into());
    }
    let encoded_id = urlencoding::encode(advisory_id);
    let url = format!("{}/v1/advisories/{}", base, encoded_id);

    let client = http_client()?;
    debug(&format!(
        "Sending vuln-api advisory request to URL: {}",
        url
    ));

    let mut req = client
        .get(&url)
        .header("Accept", "application/json")
        .header("CORGEA-SOURCE", "cli");
    if is_jwt(token) {
        req = req.header("Authorization", format!("Bearer {}", token));
    } else {
        req = req.header("CORGEA-TOKEN", token);
    }

    let response = req
        .send()
        .map_err(|e| format!("Failed to send vuln-api advisory request: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("Error: Unable to fetch advisory. Status code: {}", status).into());
    }

    let response_text = response.text()?;
    let parsed: AdvisoryResponse = serde_json::from_str(&response_text).map_err(|e| {
        debug(&format!(
            "Failed to parse vuln-api advisory response: {}. Body: {}",
            e, response_text
        ));
        format!("Failed to parse vuln-api advisory response: {}", e)
    })?;

    // Identity guard: refuse a response that names a different advisory
    // than we asked about. The server is allowed to be silent on
    // identity (empty advisory_id), but if it answers it must match
    // either the canonical id or one of the aliases.
    if !parsed.advisory_id.is_empty()
        && !parsed.advisory_id.eq_ignore_ascii_case(advisory_id)
        && !parsed
            .aliases
            .iter()
            .any(|a| a.eq_ignore_ascii_case(advisory_id))
    {
        return Err(format!(
            "vuln-api response advisory_id '{}' does not match request '{}'",
            parsed.advisory_id, advisory_id
        )
        .into());
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_package_name_scoped_npm() {
        assert_eq!(encode_package_name("npm", "@types/node"), "@types%2fnode");
        assert_eq!(encode_package_name("npm", "lodash"), "lodash");
    }

    #[test]
    fn encode_package_name_pypi() {
        assert_eq!(encode_package_name("PyPI", "requests"), "requests");
    }

    #[test]
    fn encode_package_name_npm_case_insensitive() {
        // Defends against vuln_api_ecosystem() casing changes.
        assert_eq!(encode_package_name("NPM", "@types/node"), "@types%2fnode");
    }

    #[test]
    fn deserialize_vuln_check_response() {
        let body = r#"{
            "ecosystem": "npm",
            "package_name": "lodash",
            "version": "4.17.20",
            "is_vulnerable": true,
            "matches": [{
                "advisory_id": "GHSA-xxxx-yyyy-zzzz",
                "severity_level": "high",
                "tier": 1,
                "vulnerable_version_range": "<4.17.21",
                "fixed_version": "4.17.21"
            }]
        }"#;
        let parsed: VulnCheckResponse = serde_json::from_str(body).unwrap();
        assert!(parsed.is_vulnerable);
        assert_eq!(parsed.matches.len(), 1);
        assert_eq!(parsed.matches[0].advisory_id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(parsed.matches[0].tier, 1);
    }

    #[test]
    fn normalize_base_url_strips_trailing_slash() {
        assert_eq!(
            normalize_base_url("http://localhost:8080/"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn is_jwt_detection() {
        assert!(is_jwt("a.b.c"));
        assert!(!is_jwt("plain-token"));
        assert!(!is_jwt("a.b"));
        assert!(!is_jwt("a..c"));
    }

    #[test]
    fn deserialize_advisory_response_real_server_shape() {
        // Mirrors the worker's emitted payload (cve_worker/src/worker.js):
        // server emits `id` (not `advisory_id`) and `source_url` (not `url`),
        // plus many fields we ignore. No top-level `remediation` exists.
        let body = r#"{
            "id": "GHSA-xxxx-yyyy-zzzz",
            "source": "ghsa",
            "source_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "alias": "CVE-2026-12345",
            "aliases": ["CVE-2026-12345"],
            "ecosystem": "npm",
            "summary": "Prototype pollution in lodash",
            "severity": "HIGH",
            "severity_badge": "HIGH",
            "tier": 1,
            "tier_score": 74.5,
            "llm_summary": "Short developer-facing summary.",
            "packages": [],
            "cwes": []
        }"#;
        let parsed: AdvisoryResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.advisory_id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(parsed.aliases, vec!["CVE-2026-12345".to_string()]);
        assert_eq!(parsed.tier, Some(1));
        assert_eq!(
            parsed.url.as_deref(),
            Some("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz")
        );
    }

    #[test]
    fn deserialize_advisory_response_tier_null_and_missing_source_url() {
        // Server emits `tier: null` for unscored advisories
        // (VULNERABILITY_SERVICE.md §5). `source_url` may also be absent.
        let body = r#"{
            "id": "GHSA-only-id",
            "tier": null
        }"#;
        let parsed: AdvisoryResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.advisory_id, "GHSA-only-id");
        assert!(parsed.tier.is_none());
        assert!(parsed.aliases.is_empty());
        assert!(parsed.title.is_none());
        assert!(parsed.severity_level.is_none());
        assert!(parsed.url.is_none());
    }
}
