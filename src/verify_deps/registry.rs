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

// Matches `vuln_api::REQUEST_TIMEOUT` so a gate run degrades uniformly:
// both legs of a verdict pass give up at the same horizon.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

use crate::vuln_api::{encode_npm_name, user_agent};

fn http_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(user_agent("deps"))
            .build()
            .expect("registry http client")
    })
}

/// Shared fetch/parse boilerplate for registry metadata GETs: 404 → "not
/// found", other non-success → status error, then parse the JSON body.
/// `label` names the registry in error messages ("npm registry" / "PyPI").
fn fetch_registry_json<T: serde::de::DeserializeOwned>(
    url: &str,
    label: &str,
    name: &str,
    base: &str,
) -> Result<T, String> {
    let resp = http_client()
        .get(url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| format!("{} request failed: {}", label, e))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "package '{}' not found on {} ({})",
            name, label, base
        ));
    }
    if !status.is_success() {
        return Err(format!(
            "{} returned status {} for '{}'",
            label, status, name
        ));
    }

    let body = resp
        .text()
        .map_err(|e| format!("failed to read {} response: {}", label, e))?;
    serde_json::from_str(&body)
        .map_err(|e| format!("failed to parse {} response for '{}': {}", label, name, e))
}

#[derive(Debug, Deserialize)]
struct PypiUrl {
    upload_time_iso_8601: Option<String>,
    upload_time: Option<String>,
    /// PEP 592. PyPI's JSON API emits a bool; some mirrors emit the
    /// yank reason string instead. Either form means yanked.
    #[serde(default)]
    yanked: Option<serde_json::Value>,
}

impl PypiUrl {
    fn is_yanked(&self) -> bool {
        match &self.yanked {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(_)) => true,
            _ => false,
        }
    }
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
    let meta: NpmFullMetadata = fetch_registry_json(&url, "npm registry", name, base)?;

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

/// Translate an npm-style version range to `semver::VersionReq`
/// alternatives (one per `||` branch — any-match). Handles npm grammar
/// the Rust crate doesn't: whitespace AND separators, hyphen ranges
/// (`1.0.0 - 2.0.0`), `||` unions, and bare partials (`1.0`, which npm
/// reads as `1.0.x` but Cargo would read as `^1.0`).
fn parse_npm_range(range: &str) -> Option<Vec<semver::VersionReq>> {
    range
        .split("||")
        .map(|alt| parse_npm_range_alternative(alt.trim()))
        .collect()
}

fn parse_npm_range_alternative(alt: &str) -> Option<semver::VersionReq> {
    if let Some((lo, hi)) = alt.split_once(" - ") {
        return hyphen_range(lo.trim(), hi.trim());
    }
    if let Some(tilde) = bare_partial_to_tilde(alt) {
        return semver::VersionReq::parse(&tilde).ok();
    }
    if let Ok(req) = semver::VersionReq::parse(alt) {
        return Some(req);
    }
    let normalised = alt.split_whitespace().collect::<Vec<_>>().join(",");
    semver::VersionReq::parse(&normalised).ok()
}

/// node-semver hyphen range `A - B`. A partial low bound fills with zeros
/// (`1.2` → `>=1.2.0`); a partial high bound excludes the next component
/// (`- 2.3` → `<2.4.0`, `- 2` → `<3.0.0`), matching npm.
fn hyphen_range(lo: &str, hi: &str) -> Option<semver::VersionReq> {
    let lo_v = pad_partial(lo)?;
    let hi_segments = hi.split('.').count();
    let hi_v = pad_partial(hi)?;
    let expr = match hi_segments {
        1 => format!(">={lo_v}, <{}", semver::Version::new(hi_v.major + 1, 0, 0)),
        2 => format!(
            ">={lo_v}, <{}",
            semver::Version::new(hi_v.major, hi_v.minor + 1, 0)
        ),
        _ => format!(">={lo_v}, <={hi_v}"),
    };
    semver::VersionReq::parse(&expr).ok()
}

/// `1.2` → `1.2.0` (accepts an optional leading `v`, like npm).
fn pad_partial(v: &str) -> Option<semver::Version> {
    let v = v.trim();
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut segments: Vec<&str> = v.split('.').collect();
    while segments.len() < 3 {
        segments.push("0");
    }
    semver::Version::parse(&segments.join(".")).ok()
}

/// npm desugars a bare two-component version (`1.0`) to the x-range
/// `1.0.x`; Cargo's `VersionReq` would read it as caret (`^1.0`, matching
/// 1.9). Translate to tilde, which has npm's intended bounds.
fn bare_partial_to_tilde(alt: &str) -> Option<String> {
    let segments: Vec<&str> = alt.split('.').collect();
    (segments.len() == 2
        && segments
            .iter()
            .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())))
    .then(|| format!("~{alt}"))
}

/// Pick the highest published version that satisfies `range`. Pre-releases
/// are excluded unless the range itself references one (matches npm).
fn npm_pick_highest_matching(
    versions: &std::collections::BTreeMap<String, serde::de::IgnoredAny>,
    range: &str,
) -> Option<String> {
    let reqs = parse_npm_range(range)?;
    let range_has_prerelease = range.contains('-') && !range.contains(" - ");
    versions
        .keys()
        .filter_map(|raw| semver::Version::parse(raw).ok().map(|v| (v, raw)))
        .filter(|(v, _)| {
            (v.pre.is_empty() || range_has_prerelease) && reqs.iter().any(|req| req.matches(v))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, raw)| raw.clone())
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
    let meta: PypiInfoResponse = fetch_registry_json(&url, "PyPI", name, base)?;

    let candidates = collect_pypi_candidates(&meta);
    // A yanked release resolves only via an exact pin (PEP 592), matching
    // pip — otherwise we'd gate a version pip would never choose.
    let installable: Vec<PypiCandidate> =
        candidates.iter().filter(|c| !c.yanked).cloned().collect();
    let chosen = match spec {
        PypiSpec::Latest => pick_latest_stable(&installable).map(|c| c.version.clone()),
        // PEP 440 equality, not string equality: `==2.31` must match the
        // release key `2.31.0` (and resolve to the key, so the publish-time
        // lookup below finds it).
        PypiSpec::Exact(v) => {
            let want = PypiVersion::parse(v);
            candidates
                .iter()
                .find(|c| {
                    &c.version == v
                        || matches!(
                            (&want, PypiVersion::parse(&c.version)),
                            (Some(w), Some(cv)) if *w == cv
                        )
                })
                .map(|c| c.version.clone())
        }
        PypiSpec::Specifier(spec_str) => pypi_resolve_specifier(&installable, spec_str)
            .map_err(|e| format!("{} for '{}'", e, name))?,
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
        .find(|c| c.version == chosen)
        .map(|c| c.uploaded)
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

/// One published release a `PypiSpec` can resolve to.
#[derive(Debug, Clone)]
struct PypiCandidate {
    version: String,
    uploaded: DateTime<Utc>,
    /// Every artifact of this release is yanked (PEP 592) — pip skips
    /// it for anything but an exact pin, so non-exact resolution must too.
    yanked: bool,
}

/// Returns a candidate for every release that has at least one uploaded,
/// timestamped artifact. Empty or timestampless release entries (which
/// PyPI sometimes keeps around for deleted / private versions) are
/// filtered out so we never pick them.
fn collect_pypi_candidates(meta: &PypiInfoResponse) -> Vec<PypiCandidate> {
    let mut out = Vec::new();
    for (ver, files) in &meta.releases {
        if files.is_empty() {
            continue;
        }
        let earliest = files
            .iter()
            .filter_map(|f| {
                f.upload_time_iso_8601
                    .as_deref()
                    .or(f.upload_time.as_deref())
            })
            .filter_map(|raw| parse_iso8601(raw).ok())
            .min();
        if let Some(dt) = earliest {
            out.push(PypiCandidate {
                version: ver.clone(),
                uploaded: dt,
                yanked: files.iter().all(PypiUrl::is_yanked),
            });
        }
    }
    out
}

/// PEP 440-ish ordering key: the semver-parsed release plus its `.postN`
/// number. Post-releases order after their base (`1.0.post1` > `1.0`) and
/// pip installs them by default — dropping them from candidates would
/// verdict a different version than the install. Pre/dev releases stay
/// excluded (matching pip's defaults); epochs (`1!2.0`) remain unsupported
/// and are skipped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PypiVersion {
    base: semver::Version,
    /// `.postN` number; `None` for a plain release. Ordering: derive(Ord)
    /// compares `base` first, then `post` (`None` < `Some(_)`), which is
    /// exactly PEP 440's post-release ordering.
    post: Option<u64>,
}

impl PypiVersion {
    fn parse(raw: &str) -> Option<Self> {
        let (release, post) = match raw.find(".post") {
            Some(idx) => {
                let n: u64 = raw[idx + ".post".len()..].parse().ok()?;
                (&raw[..idx], Some(n))
            }
            None => (raw, None),
        };
        let base = semver::Version::parse(&normalize_for_semver(release)).ok()?;
        Some(PypiVersion { base, post })
    }

    fn is_prerelease(&self) -> bool {
        !self.base.pre.is_empty()
    }
}

/// Pick the latest non-prerelease version using PEP 440-ish parsing as a
/// best-effort ordering. Falls back to the entry with the latest upload
/// time if no candidate parses.
fn pick_latest_stable(candidates: &[PypiCandidate]) -> Option<&PypiCandidate> {
    candidates
        .iter()
        .filter_map(|c| {
            PypiVersion::parse(&c.version)
                .filter(|v| !v.is_prerelease())
                .map(|v| (v, c))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, c)| c)
        .or_else(|| candidates.iter().max_by_key(|c| c.uploaded))
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
/// and return the highest match (`Ok(None)` when nothing satisfies it).
/// Supported operators: `==` (incl. wildcards `==1.4.*`), `>=`, `>`,
/// `<=`, `<`, `~=`, `!=`. An expression we can't parse (unknown operator,
/// exotic version) is `Err` — resolving anything else would gate a
/// different version than the package manager installs.
fn pypi_resolve_specifier(
    candidates: &[PypiCandidate],
    spec: &str,
) -> Result<Option<String>, String> {
    let parts: Vec<&str> = spec.split(',').map(|s| s.trim()).collect();
    let mut requirements: Vec<(&'static str, semver::Version)> = Vec::new();

    // Longest prefixes first so `>=` never matches as `>`.
    const OPERATORS: &[(&str, &str)] = &[
        ("===", "=="),
        ("==", "=="),
        (">=", ">="),
        ("<=", "<="),
        ("!=", "!="),
        ("~=", "~="),
        (">", ">"),
        ("<", "<"),
    ];
    for p in &parts {
        let unsupported = || format!("unsupported version specifier '{}'", spec);
        let (op, val) = OPERATORS
            .iter()
            .find_map(|(prefix, op)| p.strip_prefix(prefix).map(|v| (*op, v.trim())))
            .ok_or_else(unsupported)?;
        // Wildcard pin `==X.Y.*` — desugar to the half-open range it means.
        if op == "==" {
            if let Some(prefix) = val.strip_suffix(".*") {
                let (lo, hi) = wildcard_bounds(prefix).ok_or_else(unsupported)?;
                requirements.push((">=", lo));
                requirements.push(("<", hi));
                continue;
            }
        }
        if val.contains('*') {
            return Err(unsupported());
        }
        let v = semver::Version::parse(&normalize_for_semver(val)).map_err(|_| unsupported())?;
        // PEP 440 `~=X.Y` bumps the LAST release component of the written
        // spec: `~=1.4` means `<2.0`, `~=1.4.5` means `<1.5.0`. Desugar
        // here — the padded `v` has lost the component count.
        if op == "~=" {
            let hi = match val.split('.').count() {
                2 => semver::Version::new(v.major + 1, 0, 0),
                3 => semver::Version::new(v.major, v.minor + 1, 0),
                _ => return Err(unsupported()),
            };
            requirements.push((">=", v));
            requirements.push(("<", hi));
            continue;
        }
        requirements.push((op, v));
    }

    // PEP 440 comparison against a candidate that may be a post-release:
    // `>=V` includes V's posts, `>V`/`<=V` exclude them, `==V` matches
    // only the plain release.
    let satisfies = |c: &PypiVersion| {
        requirements.iter().all(|(op, want)| match *op {
            "==" => c.base == *want && c.post.is_none(),
            ">=" => c.base >= *want,
            "<=" => c.base < *want || (c.base == *want && c.post.is_none()),
            "!=" => !(c.base == *want && c.post.is_none()),
            ">" => c.base > *want,
            "<" => c.base < *want,
            _ => false,
        })
    };
    Ok(candidates
        .iter()
        .filter_map(|c| PypiVersion::parse(&c.version).map(|v| (v, &c.version)))
        .filter(|(v, _)| !v.is_prerelease() && satisfies(v))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, raw)| raw.clone()))
}

/// `==X.*` / `==X.Y.*` / `==X.Y.Z.*` bounds: everything the written prefix
/// covers, half-open at the bumped last component.
fn wildcard_bounds(prefix: &str) -> Option<(semver::Version, semver::Version)> {
    let lo = semver::Version::parse(&normalize_for_semver(prefix)).ok()?;
    let hi = match prefix.split('.').count() {
        1 => semver::Version::new(lo.major + 1, 0, 0),
        2 => semver::Version::new(lo.major, lo.minor + 1, 0),
        3 => semver::Version::new(lo.major, lo.minor, lo.patch + 1),
        _ => return None,
    };
    Some((lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(versions: &[&str]) -> Vec<PypiCandidate> {
        versions
            .iter()
            .map(|v| PypiCandidate {
                version: v.to_string(),
                uploaded: Utc::now(),
                yanked: false,
            })
            .collect()
    }

    #[test]
    fn specifier_resolves_highest_match() {
        let c = candidates(&["1.0.0", "2.5.0", "3.0.0"]);
        assert_eq!(
            pypi_resolve_specifier(&c, ">=1.0,<3").expect("parse"),
            Some("2.5.0".to_string())
        );
    }

    #[test]
    fn specifier_with_no_match_is_ok_none() {
        let c = candidates(&["1.0.0"]);
        assert_eq!(pypi_resolve_specifier(&c, ">=9.0").expect("parse"), None);
    }

    #[test]
    fn unparseable_specifier_errors_instead_of_falling_back() {
        // Resolving "latest stable" for an expression we can't represent
        // would gate the wrong version.
        let c = candidates(&["1.0.0", "2.0.0"]);
        for spec in ["@weird", ">= not-a-version", "!=1.*"] {
            let err = pypi_resolve_specifier(&c, spec).expect_err(spec);
            assert!(
                err.contains("unsupported version specifier"),
                "{spec}: {err}"
            );
        }
    }

    #[test]
    fn wildcard_pin_resolves_as_a_range() {
        // pip: `==4.2.*` matches the 4.2 series, highest first.
        let c = candidates(&["4.1.0", "4.2.0", "4.2.9", "4.3.0"]);
        assert_eq!(
            pypi_resolve_specifier(&c, "==4.2.*").expect("parse"),
            Some("4.2.9".to_string())
        );
        let c = candidates(&["0.9.0", "1.0.0", "1.9.0", "2.0.0"]);
        assert_eq!(
            pypi_resolve_specifier(&c, "==1.*").expect("parse"),
            Some("1.9.0".to_string())
        );
    }

    #[test]
    fn compatible_release_bumps_the_written_component() {
        // PEP 440: `~=4.0` means `>=4.0, <5.0` (NOT `<4.1`) — pip installs
        // 4.2.x, so the gate must verdict the same series.
        let c = candidates(&["4.0.0", "4.0.5", "4.2.9", "5.0.0"]);
        assert_eq!(
            pypi_resolve_specifier(&c, "~=4.0").expect("parse"),
            Some("4.2.9".to_string())
        );
        // `~=1.4.5` means `>=1.4.5, <1.5.0`.
        let c = candidates(&["1.4.4", "1.4.6", "1.5.0"]);
        assert_eq!(
            pypi_resolve_specifier(&c, "~=1.4.5").expect("parse"),
            Some("1.4.6".to_string())
        );
    }

    #[test]
    fn post_releases_resolve_and_outrank_their_base() {
        // pip installs post-releases by default; dropping them would
        // verdict a different version than the install.
        let c = candidates(&["1.0", "1.0.post1", "0.9.0"]);
        assert_eq!(
            pypi_resolve_specifier(&c, ">=1.0").expect("parse"),
            Some("1.0.post1".to_string())
        );
        assert_eq!(
            pick_latest_stable(&c).map(|c| c.version.as_str()),
            Some("1.0.post1")
        );
        // …but a plain `==1.0` pin means the base release, not its posts.
        assert_eq!(
            pypi_resolve_specifier(&c, "==1.0").expect("parse"),
            Some("1.0".to_string())
        );
        // PEP 440: `>V` excludes V's own post-releases.
        assert_eq!(pypi_resolve_specifier(&c, ">1.0").expect("parse"), None);
    }

    #[test]
    fn yanked_only_releases_are_flagged() {
        // 2.0.0 has every file yanked (one bool, one mirror-style reason
        // string); 1.0.0 has a non-yanked file. Timestamps alone must not
        // decide yanked status — yanked files keep theirs.
        let meta: PypiInfoResponse = serde_json::from_str(
            r#"{"releases":{
                "1.0.0":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z","yanked":false}],
                "2.0.0":[{"upload_time_iso_8601":"2021-01-01T00:00:00Z","yanked":true},
                         {"upload_time_iso_8601":"2021-01-01T00:00:00Z","yanked":"broken build"}]
            }}"#,
        )
        .expect("parse pypi json");
        let candidates = collect_pypi_candidates(&meta);
        let yanked_of = |v: &str| candidates.iter().find(|c| c.version == v).unwrap().yanked;
        assert!(!yanked_of("1.0.0"));
        assert!(yanked_of("2.0.0"));

        // Latest/specifier resolution must skip the yanked release…
        let installable: Vec<PypiCandidate> =
            candidates.iter().filter(|c| !c.yanked).cloned().collect();
        assert_eq!(
            pick_latest_stable(&installable).map(|c| c.version.as_str()),
            Some("1.0.0")
        );
        assert_eq!(
            pypi_resolve_specifier(&installable, ">=1.0").expect("parse"),
            Some("1.0.0".to_string())
        );
        // …while an exact pin still finds it (pip installs it with a warning).
        assert!(candidates.iter().any(|c| c.version == "2.0.0"));
    }

    #[test]
    fn release_with_partially_yanked_files_stays_installable() {
        let meta: PypiInfoResponse = serde_json::from_str(
            r#"{"releases":{"1.5.0":[
                {"upload_time_iso_8601":"2020-06-01T00:00:00Z","yanked":true},
                {"upload_time_iso_8601":"2020-06-01T00:00:00Z","yanked":false}
            ]}}"#,
        )
        .expect("parse pypi json");
        let candidates = collect_pypi_candidates(&meta);
        assert!(!candidates[0].yanked);
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
