//! Registry lookups for npm and PyPI publish times.
//!
//! These talk to public registries (no auth) and are kept independent
//! of the rest of the CLI's HTTP client because:
//!   * we must not send the user's Corgea auth header to a third-party,
//!   * the timeouts and retry policy are different.
//!
//! Both functions return the publish time of an exact (name, version)
//! tuple as a UTC timestamp.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";
const DEFAULT_PYPI_REGISTRY: &str = "https://pypi.org";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

fn user_agent() -> String {
    format!("corgea-cli/{} (verify-deps)", env!("CARGO_PKG_VERSION"))
}

fn http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(user_agent())
        .build()
        .map_err(|e| format!("failed to build http client: {}", e))
}

#[derive(Debug, Deserialize)]
struct NpmTimeResponse {
    #[serde(default)]
    time: std::collections::BTreeMap<String, String>,
}

/// Look up the publish time of an exact `name@version` from the npm registry.
///
/// We hit the package metadata URL and pull the version's timestamp out
/// of the `time` map. We only need that map, so we set the
/// `application/vnd.npm.install-v1+json` *negotiation* via the regular
/// JSON accept (the abbreviated form omits `time`, so we use the full
/// form intentionally).
pub fn npm_publish_time(
    name: &str,
    version: &str,
    registry: Option<&str>,
) -> Result<DateTime<Utc>, String> {
    if name.is_empty() {
        return Err("empty package name".to_string());
    }
    let base = registry.unwrap_or(DEFAULT_NPM_REGISTRY).trim_end_matches('/');
    let path = encode_npm_name(name);
    let url = format!("{}/{}", base, path);

    let client = http_client()?;
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| format!("npm registry request failed: {}", e))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "package '{}' not found on npm registry ({})",
            name, base
        ));
    }
    if !status.is_success() {
        return Err(format!(
            "npm registry returned status {} for '{}'",
            status, name
        ));
    }

    let body = resp
        .text()
        .map_err(|e| format!("failed to read npm registry response: {}", e))?;

    let parsed: NpmTimeResponse = serde_json::from_str(&body)
        .map_err(|e| format!("failed to parse npm registry response for '{}': {}", name, e))?;

    let raw = parsed.time.get(version).ok_or_else(|| {
        format!(
            "version '{}' for package '{}' not found in npm registry metadata",
            version, name
        )
    })?;

    parse_iso8601(raw).map_err(|e| {
        format!(
            "could not parse publish time '{}' for {}@{}: {}",
            raw, name, version, e
        )
    })
}

/// URL-encode an npm package name. Scoped names contain `@` and `/`,
/// the latter must be encoded as `%2f` for the package metadata URL.
fn encode_npm_name(name: &str) -> String {
    if let Some(stripped) = name.strip_prefix('@') {
        if let Some((scope, pkg)) = stripped.split_once('/') {
            return format!("@{}%2f{}", scope, pkg);
        }
    }
    name.to_string()
}

#[derive(Debug, Deserialize)]
struct PypiVersionResponse {
    urls: Vec<PypiUrl>,
}

#[derive(Debug, Deserialize)]
struct PypiUrl {
    upload_time_iso_8601: Option<String>,
    upload_time: Option<String>,
}

/// Look up the publish time of an exact (name, version) from PyPI.
///
/// We hit the JSON API for that exact version (`/pypi/<name>/<version>/json`)
/// and use the earliest `upload_time_iso_8601` across the version's
/// uploaded files (sdist + wheels) as the publish time. The earliest
/// time is the right one — once the first artifact is up the version
/// is effectively published.
pub fn pypi_publish_time(
    name: &str,
    version: &str,
    registry: Option<&str>,
) -> Result<DateTime<Utc>, String> {
    if name.is_empty() {
        return Err("empty package name".to_string());
    }
    let base = registry.unwrap_or(DEFAULT_PYPI_REGISTRY).trim_end_matches('/');
    let url = format!(
        "{}/pypi/{}/{}/json",
        base,
        urlencoding::encode(name),
        urlencoding::encode(version)
    );

    let client = http_client()?;
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| format!("PyPI request failed: {}", e))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "package '{}=={}' not found on PyPI ({})",
            name, version, base
        ));
    }
    if !status.is_success() {
        return Err(format!(
            "PyPI returned status {} for '{}=={}'",
            status, name, version
        ));
    }

    let body = resp
        .text()
        .map_err(|e| format!("failed to read PyPI response: {}", e))?;

    let parsed: PypiVersionResponse = serde_json::from_str(&body).map_err(|e| {
        format!(
            "failed to parse PyPI response for '{}=={}': {}",
            name, version, e
        )
    })?;

    let mut earliest: Option<DateTime<Utc>> = None;
    for u in parsed.urls {
        let raw = u
            .upload_time_iso_8601
            .or(u.upload_time);
        if let Some(raw) = raw {
            if let Ok(dt) = parse_iso8601(&raw) {
                earliest = match earliest {
                    Some(prev) if prev <= dt => Some(prev),
                    _ => Some(dt),
                };
            }
        }
    }

    earliest.ok_or_else(|| {
        format!(
            "no upload time information found on PyPI for '{}=={}' (yanked?)",
            name, version
        )
    })
}

/// Parse an ISO-8601 timestamp from npm or PyPI. PyPI sometimes emits
/// a naive timestamp like `2023-05-22T18:30:00` (no offset) which
/// chrono's RFC3339 parser rejects, so we accept both shapes.
fn parse_iso8601(raw: &str) -> Result<DateTime<Utc>, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f") {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    Err(format!("unrecognised timestamp format: {}", raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_name_encoding() {
        assert_eq!(encode_npm_name("left-pad"), "left-pad");
        assert_eq!(encode_npm_name("@scope/pkg"), "@scope%2fpkg");
        assert_eq!(encode_npm_name("@types/node"), "@types%2fnode");
    }

    #[test]
    fn parses_iso8601_variants() {
        assert!(parse_iso8601("2024-01-02T03:04:05Z").is_ok());
        assert!(parse_iso8601("2024-01-02T03:04:05.123Z").is_ok());
        assert!(parse_iso8601("2024-01-02T03:04:05+00:00").is_ok());
        assert!(parse_iso8601("2024-01-02T03:04:05").is_ok());
        assert!(parse_iso8601("not a date").is_err());
    }

    /// Network-touching integration tests. Skipped by default (#[ignore])
    /// so unit-test runs stay hermetic. Run with:
    ///   cargo test -- --ignored verify_deps::registry::tests::live
    #[test]
    #[ignore]
    fn live_npm_left_pad() {
        let dt = npm_publish_time("left-pad", "1.3.0", None).expect("npm lookup");
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2018-04-09");
    }

    #[test]
    #[ignore]
    fn live_pypi_requests() {
        let dt = pypi_publish_time("requests", "2.31.0", None).expect("pypi lookup");
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2023-05-22");
    }

    #[test]
    #[ignore]
    fn live_pypi_case_insensitive() {
        let dt = pypi_publish_time("Flask", "2.3.2", None).expect("pypi case-insensitive");
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2023-05-01");
    }

    #[test]
    #[ignore]
    fn live_npm_unknown_version() {
        let err = npm_publish_time("left-pad", "999.999.999", None).err().unwrap();
        assert!(err.contains("not found"), "got: {}", err);
    }

    #[test]
    #[ignore]
    fn live_pypi_unknown_version() {
        let err = pypi_publish_time("requests", "999.999.999", None).err().unwrap();
        assert!(err.contains("not found"), "got: {}", err);
    }
}
