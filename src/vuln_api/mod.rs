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
}
