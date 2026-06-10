//! Registry lookups for npm and PyPI publish times.
//!
//! These talk to public registries (no auth) and are kept independent
//! of the rest of the CLI's HTTP client because:
//!   * we must not send the user's Corgea auth header to a third-party,
//!   * the timeouts and retry policy are different.
//!
//! Both resolvers turn a version spec into the concrete version that
//! would be installed, plus its publish time as a UTC timestamp.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::OnceLock;
use std::time::Duration;

const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";
const DEFAULT_PYPI_REGISTRY: &str = "https://pypi.org";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

fn user_agent() -> String {
    format!("corgea-cli/{} (deps)", env!("CARGO_PKG_VERSION"))
}

fn http_client() -> Result<&'static reqwest::blocking::Client, String> {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    Ok(CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(user_agent())
            .build()
            .expect("registry http client")
    }))
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
struct PypiUrl {
    upload_time_iso_8601: Option<String>,
    upload_time: Option<String>,
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

// Resolution helpers (npm + PyPI). Inserted before the tests module
// in registry.rs.

/// What the user typed after `pkg@` in an install command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpmSpec {
    /// `axios`, `axios@`, or no spec — resolve to the `latest` dist-tag.
    Latest,
    /// `axios@latest`, `axios@next`, etc.
    Tag(String),
    /// `axios@1.2.3` — already resolved.
    Exact(String),
    /// `axios@^1.0.0`, `axios@~1.2.0`, `axios@>=1.0.0 <2.0.0`, etc.
    Range(String),
}

#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct NpmFullMetadata {
    #[serde(default, rename = "dist-tags")]
    dist_tags: std::collections::BTreeMap<String, String>,
    /// Only the keys (published version strings) are used; `IgnoredAny`
    /// avoids allocating multi-MB JSON trees for big packuments.
    #[serde(default)]
    versions: std::collections::BTreeMap<String, serde::de::IgnoredAny>,
    #[serde(default)]
    time: std::collections::BTreeMap<String, String>,
}

/// Resolve an `NpmSpec` against the npm registry and return the
/// concrete version + publish time. Used by install wrappers when the
/// install command says e.g. `axios@^1.0.0` and we need to know what
/// would actually be installed before the install runs.
pub fn npm_resolve(
    name: &str,
    spec: &NpmSpec,
    registry: Option<&str>,
) -> Result<ResolvedPackage, String> {
    if name.is_empty() {
        return Err("empty package name".to_string());
    }
    let base = registry
        .unwrap_or(DEFAULT_NPM_REGISTRY)
        .trim_end_matches('/');
    let url = format!("{}/{}", base, encode_npm_name(name));

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

    let meta: NpmFullMetadata = serde_json::from_str(&body).map_err(|e| {
        format!(
            "failed to parse npm registry response for '{}': {}",
            name, e
        )
    })?;

    let resolved_version = match spec {
        NpmSpec::Latest => meta.dist_tags.get("latest").cloned().ok_or_else(|| {
            format!(
                "package '{}' has no 'latest' dist-tag on the npm registry",
                name
            )
        })?,
        NpmSpec::Tag(tag) => meta.dist_tags.get(tag).cloned().ok_or_else(|| {
            format!(
                "package '{}' has no dist-tag named '{}' (available: {})",
                name,
                tag,
                meta.dist_tags
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        })?,
        NpmSpec::Exact(v) => {
            if !meta.versions.contains_key(v) {
                return Err(format!(
                    "version '{}' for package '{}' was not found on the npm registry",
                    v, name
                ));
            }
            v.clone()
        }
        NpmSpec::Range(range) => {
            npm_pick_highest_matching(&meta.versions, range).ok_or_else(|| {
                format!(
                    "no published version of '{}' satisfies range '{}'",
                    name, range
                )
            })?
        }
    };

    let raw_time = meta.time.get(&resolved_version).ok_or_else(|| {
        format!(
            "publish time missing for {}@{} on the npm registry",
            name, resolved_version
        )
    })?;

    let published_at = parse_iso8601(raw_time).map_err(|e| {
        format!(
            "could not parse publish time '{}' for {}@{}: {}",
            raw_time, name, resolved_version, e
        )
    })?;

    Ok(ResolvedPackage {
        name: name.to_string(),
        version: resolved_version,
        published_at,
    })
}

/// Pick the highest semver-compatible version that satisfies `range`.
/// Pre-releases are excluded unless the range itself references a
/// pre-release (matches npm's behaviour).
/// Translate an npm-style version range (`>=1.0.0 <2.0.0`,
/// `1.x`, `>=1.0.0`) to a `semver::VersionReq`. The Rust crate uses
/// `,` as the AND separator, npm uses whitespace, so we normalise
/// before parsing.
fn parse_npm_range(range: &str) -> Option<semver::VersionReq> {
    if let Ok(req) = semver::VersionReq::parse(range) {
        return Some(req);
    }
    let normalised = range.split_whitespace().collect::<Vec<_>>().join(",");
    semver::VersionReq::parse(&normalised).ok()
}

fn npm_pick_highest_matching(
    versions: &std::collections::BTreeMap<String, serde::de::IgnoredAny>,
    range: &str,
) -> Option<String> {
    // npm separates predicates with spaces (`>=1.0.0 <2.0.0`); the
    // Rust `semver` crate uses commas. Try both. We don't support
    // npm's `||` OR syntax here — those are best-effort skipped.
    let req = parse_npm_range(range)?;
    let range_has_prerelease = range.contains('-');

    let mut best: Option<(semver::Version, String)> = None;
    for raw in versions.keys() {
        let v = match semver::Version::parse(raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !v.pre.is_empty() && !range_has_prerelease {
            continue;
        }
        if !req.matches(&v) {
            continue;
        }
        match &best {
            Some((cur, _)) if cur >= &v => {}
            _ => best = Some((v, raw.clone())),
        }
    }
    best.map(|(_, raw)| raw)
}

/// PyPI version specifier used by install wrappers. We parse a
/// limited subset of PEP 440 specifiers — enough for the common
/// install-command cases (`pkg`, `pkg==X`, `pkg>=X`, `pkg<X`,
/// `pkg~=X.Y`). For anything more exotic we resolve to the latest
/// non-prerelease and warn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PypiSpec {
    /// Bare name — resolve to the latest non-prerelease.
    Latest,
    /// `pkg==X` — already resolved.
    Exact(String),
    /// One or more PEP 440 specifiers we'll best-effort match against
    /// the version list (e.g. `>=2.0`, `<3,>=2`, `~=1.4`).
    Specifier(String),
}

#[derive(Debug, Deserialize)]
struct PypiInfoResponse {
    releases: std::collections::BTreeMap<String, Vec<PypiUrl>>,
}

/// Resolve a `PypiSpec` against PyPI and return the concrete version
/// + publish time. The latest non-prerelease, non-yanked release is
///   preferred.
pub fn pypi_resolve(
    name: &str,
    spec: &PypiSpec,
    registry: Option<&str>,
) -> Result<ResolvedPackage, String> {
    if name.is_empty() {
        return Err("empty package name".to_string());
    }
    let base = registry
        .unwrap_or(DEFAULT_PYPI_REGISTRY)
        .trim_end_matches('/');
    let url = format!("{}/pypi/{}/json", base, urlencoding::encode(name));

    let client = http_client()?;
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| format!("PyPI request failed: {}", e))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(format!("package '{}' not found on PyPI ({})", name, base));
    }
    if !status.is_success() {
        return Err(format!("PyPI returned status {} for '{}'", status, name));
    }

    let body = resp
        .text()
        .map_err(|e| format!("failed to read PyPI response: {}", e))?;

    let meta: PypiInfoResponse = serde_json::from_str(&body)
        .map_err(|e| format!("failed to parse PyPI response for '{}': {}", name, e))?;

    let candidates = collect_pypi_candidates(&meta);
    let chosen = match spec {
        PypiSpec::Latest => pick_latest_stable(&candidates).map(|c| c.0.clone()),
        PypiSpec::Exact(v) => {
            if candidates.iter().any(|(ver, _)| ver == v) {
                Some(v.clone())
            } else {
                None
            }
        }
        PypiSpec::Specifier(spec_str) => pypi_resolve_specifier(&candidates, spec_str)
            .or_else(|| pick_latest_stable(&candidates).map(|c| c.0.clone())),
    };

    let chosen = chosen.ok_or_else(|| match spec {
        PypiSpec::Exact(v) => {
            format!(
                "version '{}' for package '{}' was not found on PyPI",
                v, name
            )
        }
        _ => format!("no installable version found for '{}' on PyPI", name),
    })?;

    let published_at = candidates
        .iter()
        .find(|(ver, _)| ver == &chosen)
        .map(|(_, dt)| *dt)
        .ok_or_else(|| {
            format!(
                "no upload timestamp for '{}' version '{}' on PyPI",
                name, chosen
            )
        })?;

    Ok(ResolvedPackage {
        name: name.to_string(),
        version: chosen,
        published_at,
    })
}

/// Returns `(version, earliest_upload_time)` for every non-yanked
/// release that has at least one uploaded artifact. Empty release
/// entries (which PyPI sometimes keeps around for yanked / private
/// versions) are filtered out so we never pick them.
fn collect_pypi_candidates(meta: &PypiInfoResponse) -> Vec<(String, DateTime<Utc>)> {
    let mut out = Vec::new();
    for (ver, files) in &meta.releases {
        if files.is_empty() {
            continue;
        }
        // Skip yanked-only releases.
        if files
            .iter()
            .all(|f| f.upload_time_iso_8601.is_none() && f.upload_time.is_none())
        {
            continue;
        }
        let mut earliest: Option<DateTime<Utc>> = None;
        for f in files {
            let raw = f
                .upload_time_iso_8601
                .as_deref()
                .or(f.upload_time.as_deref());
            if let Some(raw) = raw {
                if let Ok(dt) = parse_iso8601(raw) {
                    earliest = match earliest {
                        Some(prev) if prev <= dt => Some(prev),
                        _ => Some(dt),
                    };
                }
            }
        }
        if let Some(dt) = earliest {
            out.push((ver.clone(), dt));
        }
    }
    out
}

/// Pick the latest non-prerelease version using `semver` parsing as a
/// best-effort PEP 440 ordering. Falls back to the entry with the
/// latest upload time if no candidate parses as semver.
fn pick_latest_stable(candidates: &[(String, DateTime<Utc>)]) -> Option<&(String, DateTime<Utc>)> {
    let mut best_semver: Option<(semver::Version, &(String, DateTime<Utc>))> = None;
    for c in candidates {
        let normalized = normalize_for_semver(&c.0);
        if let Ok(v) = semver::Version::parse(&normalized) {
            if !v.pre.is_empty() {
                continue;
            }
            match &best_semver {
                Some((cur, _)) if cur >= &v => {}
                _ => best_semver = Some((v, c)),
            }
        }
    }
    if let Some((_, picked)) = best_semver {
        return Some(picked);
    }
    candidates.iter().max_by_key(|c| c.1)
}

/// Best-effort PEP 440 → semver: PyPI versions are usually `X.Y.Z` or
/// `X.Y` or `X.Y.Z.postN` — the dotted-number form usually parses
/// straight as semver if we pad to 3 components. Anything more exotic
/// (`1.0a1`, `2!1.0`, etc.) is left alone and rejected by semver.
///
/// Also used outside the registry (`precheck::safe_version`) as a lenient
/// cross-ecosystem pad for ordering fixed versions; keep it ecosystem-agnostic.
pub(crate) fn normalize_for_semver(v: &str) -> String {
    if v.contains('!')
        || v.contains('a')
        || v.contains('b')
        || v.contains("rc")
        || v.contains(".dev")
    {
        return v.to_string();
    }
    let parts: Vec<&str> = v.split('.').collect();
    match parts.len() {
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => v.to_string(),
    }
}

/// Apply a PEP 440-style specifier expression to the candidate list
/// and return the highest match. Supported operators: `==`, `>=`, `>`,
/// `<=`, `<`, `~=`, `!=`. Unknown operators cause us to give up and
/// return `None` (the caller falls back to "latest stable").
fn pypi_resolve_specifier(candidates: &[(String, DateTime<Utc>)], spec: &str) -> Option<String> {
    let parts: Vec<&str> = spec.split(',').map(|s| s.trim()).collect();
    let mut requirements: Vec<(&'static str, semver::Version)> = Vec::new();

    for p in &parts {
        let (op, val): (&str, &str) = if let Some(v) = p.strip_prefix("===") {
            ("==", v.trim())
        } else if let Some(v) = p.strip_prefix("==") {
            ("==", v.trim())
        } else if let Some(v) = p.strip_prefix(">=") {
            (">=", v.trim())
        } else if let Some(v) = p.strip_prefix("<=") {
            ("<=", v.trim())
        } else if let Some(v) = p.strip_prefix("!=") {
            ("!=", v.trim())
        } else if let Some(v) = p.strip_prefix("~=") {
            ("~=", v.trim())
        } else if let Some(v) = p.strip_prefix(">") {
            (">", v.trim())
        } else if let Some(v) = p.strip_prefix("<") {
            ("<", v.trim())
        } else {
            return None;
        };
        let v = semver::Version::parse(&normalize_for_semver(val)).ok()?;
        requirements.push((op, v));
    }

    let mut best: Option<(semver::Version, String)> = None;
    for (raw, _) in candidates {
        let v = match semver::Version::parse(&normalize_for_semver(raw)) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !v.pre.is_empty() {
            continue;
        }
        let satisfies = requirements.iter().all(|(op, want)| match *op {
            "==" => &v == want,
            ">=" => &v >= want,
            "<=" => &v <= want,
            "!=" => &v != want,
            ">" => &v > want,
            "<" => &v < want,
            "~=" => {
                if &v < want {
                    return false;
                }
                let upper = semver::Version::new(want.major, want.minor + 1, 0);
                v < upper
            }
            _ => false,
        });
        if !satisfies {
            continue;
        }
        match &best {
            Some((cur, _)) if cur >= &v => {}
            _ => best = Some((v, raw.clone())),
        }
    }
    best.map(|(_, raw)| raw)
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
    fn live_npm_resolve_latest() {
        let r = npm_resolve("left-pad", &NpmSpec::Latest, None).expect("npm resolve latest");
        assert_eq!(r.name, "left-pad");
        assert_eq!(r.version, "1.3.0");
        assert_eq!(r.published_at.format("%Y-%m-%d").to_string(), "2018-04-09");
    }

    #[test]
    #[ignore]
    fn live_npm_resolve_exact() {
        let r = npm_resolve("left-pad", &NpmSpec::Exact("1.3.0".to_string()), None)
            .expect("npm resolve exact");
        assert_eq!(r.version, "1.3.0");
    }

    #[test]
    #[ignore]
    fn live_npm_resolve_range() {
        let r = npm_resolve("left-pad", &NpmSpec::Range("^1.0.0".to_string()), None)
            .expect("npm resolve range");
        assert_eq!(r.version, "1.3.0");
    }

    #[test]
    #[ignore]
    fn live_npm_resolve_npm_style_range() {
        // npm uses spaces, the Rust crate uses commas — we should
        // accept both.
        let r = npm_resolve(
            "left-pad",
            &NpmSpec::Range(">=1.0.0 <2.0.0".to_string()),
            None,
        )
        .expect("npm resolve space-range");
        assert_eq!(r.version, "1.3.0");
    }

    #[test]
    #[ignore]
    fn live_npm_resolve_unknown_tag() {
        let err = npm_resolve(
            "left-pad",
            &NpmSpec::Tag("does-not-exist".to_string()),
            None,
        )
        .err()
        .unwrap();
        assert!(err.contains("dist-tag"), "got: {}", err);
    }

    #[test]
    #[ignore]
    fn live_pypi_resolve_latest() {
        let r = pypi_resolve("flask", &PypiSpec::Latest, None).expect("pypi resolve latest");
        assert_eq!(r.name, "flask");
        assert!(!r.version.is_empty());
    }

    #[test]
    #[ignore]
    fn live_pypi_resolve_exact() {
        let r = pypi_resolve("requests", &PypiSpec::Exact("2.31.0".to_string()), None)
            .expect("pypi resolve exact");
        assert_eq!(r.version, "2.31.0");
        assert_eq!(r.published_at.format("%Y-%m-%d").to_string(), "2023-05-22");
    }

    #[test]
    #[ignore]
    fn live_pypi_resolve_specifier() {
        let r = pypi_resolve(
            "requests",
            &PypiSpec::Specifier(">=2.30,<2.32".to_string()),
            None,
        )
        .expect("pypi resolve specifier");
        // `requests==2.31.0` is the only release in [2.30, 2.32).
        assert_eq!(r.version, "2.31.0");
    }
}
