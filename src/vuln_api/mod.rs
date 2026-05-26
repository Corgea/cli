use serde::{Deserialize, Serialize};

use crate::log::debug;
use crate::utils::api::{check_for_warnings, http_client};

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

fn normalize_base_url(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

/// Encode package name for the vuln-api path segment.
/// npm scoped names: `@scope/pkg` → `@scope%2fpkg` (mirrors registry.rs).
fn encode_package_name(ecosystem: &str, name: &str) -> String {
    if ecosystem == "npm" {
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
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<VulnCheckResponse, Box<dyn std::error::Error>> {
    let base = normalize_base_url(base_url);
    let encoded_name = encode_package_name(ecosystem, name);
    let url = format!(
        "{}/v1/packages/{}/{}/versions/{}/check",
        base, ecosystem, encoded_name, version
    );

    let client = http_client();
    debug(&format!("Sending request to URL: {}", url));
    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    check_for_warnings(response.headers(), response.status());

    if response.status().is_success() {
        let response_text = response.text()?;
        let parsed: VulnCheckResponse = serde_json::from_str(&response_text).map_err(|e| {
            debug(&format!(
                "Failed to parse vuln-api response: {}. Body: {}",
                e, response_text
            ));
            format!("Failed to parse vuln-api response: {}", e)
        })?;
        Ok(parsed)
    } else {
        Err(format!(
            "Error: Unable to check package version. Status code: {}",
            response.status()
        )
        .into())
    }
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
}
