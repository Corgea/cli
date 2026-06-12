//! OSV public vulnerability client.
//!
//! OSV is a secondary signal for install gating. It can add a block when it
//! finds a package-version advisory, but an OSV clean result never weakens an
//! authenticated Corgea fail-closed verdict.

use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::vuln_api::VulnMatch;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct OsvConfig {
    pub base_url: String,
}

#[derive(Debug, Clone)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsvVerdict {
    Clean,
    Vulnerable(Vec<VulnMatch>),
}

#[derive(Debug, Serialize)]
struct QueryBatchRequest<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Debug, Serialize)]
struct Query<'a> {
    package: Package<'a>,
    version: &'a str,
}

#[derive(Debug, Serialize)]
struct Package<'a> {
    ecosystem: &'a str,
    name: &'a str,
}

#[derive(Debug, Deserialize)]
struct QueryBatchResponse {
    results: Vec<QueryResult>,
}

#[derive(Debug, Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(default)]
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

fn user_agent() -> String {
    format!("corgea-cli/{} (osv)", env!("CARGO_PKG_VERSION"))
}

pub fn http_client() -> Result<reqwest::blocking::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::blocking::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .user_agent(user_agent())
                .build()
                .map_err(|e| format!("failed to build OSV http client: {e}"))
        })
        .clone()
}

pub fn query_batch(
    client: &reqwest::blocking::Client,
    base_url: &str,
    packages: &[OsvPackage],
) -> Result<Vec<OsvVerdict>, String> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }
    let base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("OSV base URL is empty".to_string());
    }
    let url = format!("{base}/v1/querybatch");
    let body = QueryBatchRequest {
        queries: packages
            .iter()
            .map(|pkg| Query {
                package: Package {
                    ecosystem: &pkg.ecosystem,
                    name: &pkg.name,
                },
                version: &pkg.version,
            })
            .collect(),
    };

    let response = client
        .post(&url)
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("OSV request failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("OSV returned HTTP {}", status.as_u16()));
    }
    let response_text = response
        .text()
        .map_err(|e| format!("failed to read OSV response: {e}"))?;
    let parsed: QueryBatchResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("failed to parse OSV response: {e}"))?;
    if parsed.results.len() != packages.len() {
        return Err(format!(
            "OSV response returned {} results for {} queries",
            parsed.results.len(),
            packages.len()
        ));
    }

    Ok(parsed
        .results
        .into_iter()
        .map(|result| {
            if result.vulns.is_empty() {
                OsvVerdict::Clean
            } else {
                OsvVerdict::Vulnerable(result.vulns.into_iter().map(osv_match).collect())
            }
        })
        .collect())
}

fn osv_match(vuln: OsvVuln) -> VulnMatch {
    VulnMatch {
        advisory_id: advisory_id(&vuln),
        severity_level: severity_level(&vuln),
        tier: severity_tier(&severity_level(&vuln)),
        vulnerable_version_range: None,
        fixed_version: fixed_version(&vuln),
        source: Some("OSV".to_string()),
    }
}

fn advisory_id(vuln: &OsvVuln) -> String {
    if !vuln.id.trim().is_empty() {
        return vuln.id.clone();
    }
    vuln.aliases
        .iter()
        .find(|alias| !alias.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "OSV".to_string())
}

fn severity_level(vuln: &OsvVuln) -> String {
    if let Some(sev) = vuln
        .database_specific
        .get("severity")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        return sev.to_ascii_lowercase();
    }
    let max_score = vuln
        .severity
        .iter()
        .filter_map(|s| cvss_score(&s.score))
        .fold(None, |max: Option<f64>, score| {
            Some(max.map_or(score, |m| m.max(score)))
        });
    match max_score {
        Some(score) if score >= 9.0 => "critical".to_string(),
        Some(score) if score >= 7.0 => "high".to_string(),
        Some(score) if score >= 4.0 => "medium".to_string(),
        Some(_) => "low".to_string(),
        None => "unknown".to_string(),
    }
}

fn cvss_score(raw: &str) -> Option<f64> {
    raw.parse::<f64>().ok()
}

fn severity_tier(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 1,
        "high" => 2,
        "medium" => 3,
        "low" => 4,
        _ => 5,
    }
}

fn fixed_version(vuln: &OsvVuln) -> Option<String> {
    vuln.affected
        .iter()
        .flat_map(|affected| &affected.ranges)
        .flat_map(|range| &range.events)
        .find_map(|event| event.fixed.clone())
}

pub fn ecosystem_for_osv(ecosystem: &str) -> String {
    match ecosystem {
        "pypi" => "PyPI".to_string(),
        "npm" => "npm".to_string(),
        _ => ecosystem.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn spawn_osv_stub(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0; 4096];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        base
    }

    #[test]
    fn query_batch_maps_osv_vulnerabilities() {
        let base = spawn_osv_stub(
            r#"{"results":[{"vulns":[{"id":"GHSA-test","database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"events":[{"fixed":"2.0.0"}]}]}]}]}]}"#,
        );
        let client = http_client().expect("client");
        let out = query_batch(
            &client,
            &base,
            &[OsvPackage {
                ecosystem: "PyPI".to_string(),
                name: "oldpkg".to_string(),
                version: "1.0.0".to_string(),
            }],
        )
        .expect("query");
        let OsvVerdict::Vulnerable(matches) = &out[0] else {
            panic!("expected vulnerable: {out:?}");
        };
        assert_eq!(matches[0].advisory_id, "GHSA-test");
        assert_eq!(matches[0].severity_level, "high");
        assert_eq!(matches[0].fixed_version.as_deref(), Some("2.0.0"));
        assert_eq!(matches[0].source.as_deref(), Some("OSV"));
    }
}
