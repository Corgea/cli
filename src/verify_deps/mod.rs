//! Dependency freshness verification.
//!
//! Discovers installed dependencies from a project (npm and/or Python),
//! looks up publish times from the public registries (npmjs.org / pypi.org),
//! and flags any package whose installed version was published within a
//! configurable recency threshold. This is intended to act as a fast
//! supply-chain tripwire against very recently published versions of
//! dependencies (a common malware-injection pattern).

pub mod npm;
pub mod python;
pub mod registry;
pub mod report;

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::utils::terminal::{set_text_color, TerminalColor};
use crate::vuln_api;

/// Which ecosystem(s) to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Python,
    All,
}

impl Ecosystem {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "npm" | "node" | "javascript" | "js" => Ok(Ecosystem::Npm),
            "python" | "py" | "pypi" => Ok(Ecosystem::Python),
            "all" | "auto" => Ok(Ecosystem::All),
            other => Err(format!(
                "Unknown ecosystem '{}'. Valid options are: npm, python, all.",
                other
            )),
        }
    }
}

/// A single resolved dependency that we want to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: DependencyEcosystem,
    /// Where in the project we discovered this dependency (e.g. lockfile path).
    pub source: String,
    /// Whether the dependency is a development-only dependency.
    pub dev: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyEcosystem {
    Npm,
    Python,
}

impl DependencyEcosystem {
    pub fn label(self) -> &'static str {
        match self {
            DependencyEcosystem::Npm => "npm",
            DependencyEcosystem::Python => "python",
        }
    }

    fn vuln_api_ecosystem(self) -> &'static str {
        match self {
            DependencyEcosystem::Npm => "npm",
            DependencyEcosystem::Python => "PyPI",
        }
    }
}

/// One verification finding: the dep was published within the threshold.
#[derive(Debug, Clone)]
pub struct Finding {
    pub dep: Dependency,
    pub published_at: DateTime<Utc>,
    pub age: Duration,
}

/// Outcome categories for individual dependency lookups.
#[derive(Debug, Clone)]
pub enum LookupOutcome {
    /// The dep is older than the threshold — safe.
    Ok {
        dep: Dependency,
        published_at: DateTime<Utc>,
        age: Duration,
    },
    /// The dep was published within the threshold window.
    Recent(Finding),
    /// We could not retrieve metadata for this dep.
    Error { dep: Dependency, error: String },
}

/// Outcome of a vuln-api CVE lookup for a single dependency.
#[derive(Debug, Clone)]
pub enum CveLookupOutcome {
    Clean { dep: Dependency },
    Vulnerable(CveFinding),
    Error { dep: Dependency, error: String },
}

#[derive(Debug, Clone)]
pub struct CveFinding {
    pub dep: Dependency,
    pub matches: Vec<crate::vuln_api::VulnMatch>,
    /// Best-effort enrichment from `/v1/advisories/:id`. Index-aligned
    /// with `matches`; `None` for entries whose detail lookup failed
    /// (404, network, parse, or the cache previously recorded a
    /// failure). The CVE line still renders without the advisory URL
    /// when this is `None`.
    pub advisory_details: Vec<Option<crate::vuln_api::AdvisoryResponse>>,
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub ecosystem: Ecosystem,
    pub threshold: Duration,
    pub include_dev: bool,
    pub fail: bool,
    /// When true, treat any unpinned dependency or missing-lockfile
    /// situation (`package.json` without a lockfile, unpinned
    /// `requirements.txt` lines, `pyproject.toml`/`Pipfile` without a
    /// matching lockfile) as a hard failure.
    pub fail_unpinned: bool,
    /// When true, exit non-zero if any dependency has known CVEs.
    /// Requires `check_cve`. Independent of `fail` and `fail_unpinned`.
    pub fail_cve: bool,
    pub json: bool,
    pub path: PathBuf,
    /// Optional registry overrides (used in tests).
    pub npm_registry: Option<String>,
    pub pypi_registry: Option<String>,
    /// When true, query vuln-api for known CVEs/advisories per dependency.
    pub check_cve: bool,
    /// Base URL for vuln-api (resolved from env/config in main.rs).
    pub vuln_api_url: Option<String>,
    /// Token sent to vuln-api as `Authorization: Bearer …` (JWT) or
    /// `CORGEA-TOKEN: …` (legacy). Required and non-empty when
    /// `check_cve = true`. Preflight in `main.rs` guarantees this before
    /// `run()` is called.
    pub vuln_api_token: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            ecosystem: Ecosystem::All,
            threshold: Duration::from_secs(2 * 24 * 60 * 60),
            include_dev: false,
            fail: false,
            fail_unpinned: false,
            fail_cve: false,
            json: false,
            path: PathBuf::from("."),
            npm_registry: None,
            pypi_registry: None,
            check_cve: false,
            vuln_api_url: None,
            vuln_api_token: None,
        }
    }
}

impl VerifyOptions {
    /// Lockfile scan used by install wrappers (`corgea npm`, `pip`, `uv`, …).
    #[allow(clippy::too_many_arguments)]
    pub fn for_install_wrap(
        ecosystem: Ecosystem,
        path: PathBuf,
        threshold: Duration,
        fail: bool,
        fail_unpinned: bool,
        json: bool,
        npm_registry: Option<String>,
        pypi_registry: Option<String>,
    ) -> Self {
        Self {
            ecosystem,
            threshold,
            include_dev: false,
            fail,
            fail_unpinned,
            fail_cve: false,
            json,
            path,
            npm_registry,
            pypi_registry,
            check_cve: false,
            vuln_api_url: None,
            vuln_api_token: None,
        }
    }
}

/// Parse a human-friendly duration like `2d`, `48h`, `30m`, `45s`, or
/// a bare integer (interpreted as days). Returns the parsed duration.
pub fn parse_threshold(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("threshold cannot be empty".to_string());
    }

    let (num_str, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            (&s[..s.len() - c.len_utf8()], c.to_ascii_lowercase())
        }
        _ => (s, 'd'),
    };

    let value: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid threshold number: '{}'", num_str))?;

    if value < 0.0 || !value.is_finite() {
        return Err(format!(
            "threshold must be a non-negative finite number: '{}'",
            input
        ));
    }

    let secs = match unit {
        's' => value,
        'm' => value * 60.0,
        'h' => value * 3600.0,
        'd' => value * 86400.0,
        'w' => value * 7.0 * 86400.0,
        other => {
            return Err(format!(
                "unknown threshold unit '{}'. Use s, m, h, d, or w.",
                other
            ))
        }
    };

    Ok(Duration::from_secs_f64(secs))
}

/// Format a Duration as a short human-readable string (e.g. `1d 4h`).
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    if total_secs < 60 {
        return format!("{}s", total_secs);
    }
    let mins = total_secs / 60;
    if mins < 60 {
        return format!("{}m", mins);
    }
    let hours = total_secs / 3600;
    let rem_mins = (total_secs % 3600) / 60;
    if hours < 24 {
        if rem_mins == 0 {
            return format!("{}h", hours);
        }
        return format!("{}h {}m", hours, rem_mins);
    }
    let days = total_secs / 86400;
    let rem_hours = (total_secs % 86400) / 3600;
    if rem_hours == 0 {
        format!("{}d", days)
    } else {
        format!("{}d {}h", days, rem_hours)
    }
}

/// Top-level entry: discover deps and verify them.
///
/// Returns `Ok(true)` if any recently-published deps were detected,
/// `Ok(false)` otherwise. Fails (`Err`) only on hard discovery errors.
pub fn run(opts: &VerifyOptions) -> Result<VerifyReport, String> {
    let path = opts.path.as_path();
    if !path.exists() {
        return Err(format!("path does not exist: {}", path.display()));
    }

    let mut deps: Vec<Dependency> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    let mut unpinned_warnings: Vec<UnpinnedWarning> = Vec::new();

    if matches!(opts.ecosystem, Ecosystem::Npm | Ecosystem::All) {
        match npm::discover(path, opts.include_dev) {
            Ok(mut found) => {
                unpinned_warnings.append(&mut found.warnings);
                if !found.deps.is_empty() {
                    sources.push(found.source.clone());
                    deps.append(&mut found.deps);
                }
            }
            Err(e) => {
                if opts.ecosystem == Ecosystem::Npm {
                    return Err(format!("npm discovery failed: {}", e));
                } else {
                    eprintln!(
                        "{}",
                        set_text_color(
                            &format!("note: skipping npm — {}", e),
                            TerminalColor::Yellow
                        )
                    );
                }
            }
        }
    }

    if matches!(opts.ecosystem, Ecosystem::Python | Ecosystem::All) {
        match python::discover(path, opts.include_dev) {
            Ok(mut found) => {
                unpinned_warnings.append(&mut found.warnings);
                if !found.deps.is_empty() {
                    sources.push(found.source.clone());
                    deps.append(&mut found.deps);
                }
            }
            Err(e) => {
                if opts.ecosystem == Ecosystem::Python {
                    return Err(format!("python discovery failed: {}", e));
                } else {
                    eprintln!(
                        "{}",
                        set_text_color(
                            &format!("note: skipping python — {}", e),
                            TerminalColor::Yellow
                        )
                    );
                }
            }
        }
    }

    if deps.is_empty() && unpinned_warnings.is_empty() {
        return Err(format!(
            "no supported dependency manifests found in {}. Expected one of: \
             package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, \
             requirements.txt, Pipfile.lock, poetry.lock, uv.lock.",
            path.display()
        ));
    }

    deps.sort_by(|a, b| {
        a.ecosystem
            .label()
            .cmp(b.ecosystem.label())
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
    deps.dedup_by(|a, b| a.name == b.name && a.version == b.version && a.ecosystem == b.ecosystem);

    let now = Utc::now();
    let threshold = chrono::Duration::from_std(opts.threshold)
        .map_err(|e| format!("invalid threshold: {}", e))?;

    let mut outcomes: Vec<LookupOutcome> = Vec::with_capacity(deps.len());
    let mut cve_outcomes: Vec<CveLookupOutcome> = Vec::new();
    let mut advisory_cache: std::collections::HashMap<
        String,
        Result<vuln_api::AdvisoryResponse, ()>,
    > = std::collections::HashMap::new();

    let cve_base_url = opts
        .vuln_api_url
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let cve_token = opts
        .vuln_api_token
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();

    for dep in deps {
        let dep_for_cve = opts.check_cve.then(|| dep.clone());

        let published = match dep.ecosystem {
            DependencyEcosystem::Npm => {
                registry::npm_publish_time(&dep.name, &dep.version, opts.npm_registry.as_deref())
            }
            DependencyEcosystem::Python => {
                registry::pypi_publish_time(&dep.name, &dep.version, opts.pypi_registry.as_deref())
            }
        };

        match published {
            Ok(published_at) => {
                let age_chrono = now.signed_duration_since(published_at);
                let age = age_chrono
                    .to_std()
                    .unwrap_or_else(|_| Duration::from_secs(0));
                if age_chrono < threshold {
                    outcomes.push(LookupOutcome::Recent(Finding {
                        dep,
                        published_at,
                        age,
                    }));
                } else {
                    outcomes.push(LookupOutcome::Ok {
                        dep,
                        published_at,
                        age,
                    });
                }
            }
            Err(e) => {
                outcomes.push(LookupOutcome::Error {
                    dep,
                    error: e.to_string(),
                });
            }
        }

        if let Some(dep_for_cve) = dep_for_cve {
            match crate::vuln_api::check_package_version(
                cve_base_url,
                cve_token,
                dep_for_cve.ecosystem.vuln_api_ecosystem(),
                &dep_for_cve.name,
                &dep_for_cve.version,
            ) {
                Ok(response) if response.is_vulnerable => {
                    let advisory_details = collect_advisory_details(
                        &mut advisory_cache,
                        cve_base_url,
                        cve_token,
                        &response.matches,
                    );
                    cve_outcomes.push(CveLookupOutcome::Vulnerable(CveFinding {
                        dep: dep_for_cve,
                        matches: response.matches,
                        advisory_details,
                    }));
                }
                Ok(_) => {
                    cve_outcomes.push(CveLookupOutcome::Clean { dep: dep_for_cve });
                }
                Err(e) => {
                    cve_outcomes.push(CveLookupOutcome::Error {
                        dep: dep_for_cve,
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    Ok(VerifyReport {
        sources,
        outcomes,
        unpinned_warnings,
        threshold: opts.threshold,
        scanned_at: now,
        check_cve: opts.check_cve,
        cve_outcomes,
    })
}

/// Aggregated result of a verification run.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub sources: Vec<String>,
    pub outcomes: Vec<LookupOutcome>,
    pub unpinned_warnings: Vec<UnpinnedWarning>,
    pub threshold: Duration,
    pub scanned_at: DateTime<Utc>,
    pub check_cve: bool,
    pub cve_outcomes: Vec<CveLookupOutcome>,
}

impl VerifyReport {
    pub fn recent(&self) -> Vec<&Finding> {
        self.outcomes
            .iter()
            .filter_map(|o| match o {
                LookupOutcome::Recent(f) => Some(f),
                _ => None,
            })
            .collect()
    }

    pub fn errors(&self) -> Vec<(&Dependency, &str)> {
        self.outcomes
            .iter()
            .filter_map(|o| match o {
                LookupOutcome::Error { dep, error } => Some((dep, error.as_str())),
                _ => None,
            })
            .collect()
    }

    pub fn ok_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, LookupOutcome::Ok { .. }))
            .count()
    }

    pub fn has_unpinned(&self) -> bool {
        !self.unpinned_warnings.is_empty()
    }

    pub fn cve_findings(&self) -> Vec<&CveFinding> {
        self.cve_outcomes
            .iter()
            .filter_map(|o| match o {
                CveLookupOutcome::Vulnerable(f) => Some(f),
                _ => None,
            })
            .collect()
    }

    pub fn cve_errors(&self) -> Vec<(&Dependency, &str)> {
        self.cve_outcomes
            .iter()
            .filter_map(|o| match o {
                CveLookupOutcome::Error { dep, error } => Some((dep, error.as_str())),
                _ => None,
            })
            .collect()
    }
}

/// Helper used by lockfile parsers to bundle their result.
///
/// `source` is empty when the discoverer could not find a lockfile;
/// in that case `warnings` typically explains why (e.g. a manifest
/// was found but no lockfile to resolve it against).
#[derive(Debug, Clone, Default)]
pub struct DiscoverResult {
    pub deps: Vec<Dependency>,
    pub source: String,
    pub warnings: Vec<UnpinnedWarning>,
}

/// A diagnostic about a dependency we *could not* verify because it
/// isn't pinned to an exact version. Examples:
///
/// * `package.json` is present but no `package-lock.json` /
///   `pnpm-lock.yaml` / `yarn.lock` exists.
/// * `pyproject.toml` or `Pipfile` is present without a matching
///   lockfile.
/// * A `requirements.txt` line is not `==`-pinned (e.g. `requests>=2.0`).
///
/// These are surfaced in the regular report and, with
/// `--fail-unpinned`, cause a non-zero exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpinnedWarning {
    pub ecosystem: DependencyEcosystem,
    /// Which manifest the warning is about (relative path or filename).
    pub manifest: String,
    /// Human-readable description of why the dep can't be verified.
    pub reason: String,
}

/// Read the file at `path` into a String, returning an informative error.
pub(crate) fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {}", path.display(), e))
}

/// Pick the highest `fixed_version` candidate (lexically as semver) from
/// the matches that returned one. Python `fixed_version` strings are
/// piped through `registry::normalize_for_semver` first (PEP 440 →
/// semver). Falls back to the first candidate string if none parse —
/// preserves chunk-01 behaviour for exotic version strings.
pub(super) fn pick_highest_fixed(
    eco: DependencyEcosystem,
    candidates: &[String],
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    let mut best: Option<(semver::Version, String)> = None;
    for raw in candidates {
        let normalised = match eco {
            DependencyEcosystem::Npm => raw.clone(),
            DependencyEcosystem::Python => registry::normalize_for_semver(raw),
        };
        if let Ok(v) = semver::Version::parse(&normalised) {
            if best.as_ref().map(|(b, _)| v > *b).unwrap_or(true) {
                best = Some((v, raw.clone()));
            }
        }
    }
    best.map(|(_, raw)| raw)
        .or_else(|| candidates.first().cloned())
}

/// Best-effort fetch of advisory detail for every match in `matches`,
/// memoised in `cache`. Returns a `Vec<Option<AdvisoryResponse>>`
/// index-aligned with the input; `None` for misses (404, network, parse,
/// or a previously-recorded failure). If either `base_url` or `token`
/// is empty, returns all-`None` without making any HTTP calls.
fn collect_advisory_details(
    cache: &mut std::collections::HashMap<String, Result<vuln_api::AdvisoryResponse, ()>>,
    base_url: &str,
    token: &str,
    matches: &[vuln_api::VulnMatch],
) -> Vec<Option<vuln_api::AdvisoryResponse>> {
    if base_url.is_empty() || token.is_empty() {
        return vec![None; matches.len()];
    }
    matches
        .iter()
        .map(|m| {
            let id = m.advisory_id.clone();
            if let Some(entry) = cache.get(&id) {
                return entry.as_ref().ok().cloned();
            }
            let entry = match vuln_api::get_advisory(base_url, token, &id) {
                Ok(resp) => Ok(resp),
                Err(_) => Err(()),
            };
            let result = entry.as_ref().ok().cloned();
            cache.insert(id, entry);
            result
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    struct VulnApiStub {
        base_url: String,
        seen_auth: Arc<Mutex<Vec<String>>>,
        advisory_hits: Arc<Mutex<HashMap<String, usize>>>,
        _handle: thread::JoinHandle<()>,
    }

    fn spawn_vuln_api_stub(
        fixtures: HashMap<(String, String, String), crate::vuln_api::VulnCheckResponse>,
    ) -> VulnApiStub {
        spawn_vuln_api_stub_with_advisories(fixtures, HashMap::new())
    }

    /// Advisory fixture in the real server's wire shape.
    ///
    /// Tests build this as a raw `serde_json::Value` so the CLI's
    /// deserialization path (with `#[serde(rename = "id" / "source_url")]`)
    /// is actually exercised. Serializing `AdvisoryResponse` directly
    /// would round-trip through the same Rust struct and hide a future
    /// server-side rename.
    fn spawn_vuln_api_stub_with_advisories(
        fixtures: HashMap<(String, String, String), crate::vuln_api::VulnCheckResponse>,
        advisory_fixtures: HashMap<String, serde_json::Value>,
    ) -> VulnApiStub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);
        let fixtures = Arc::new(Mutex::new(fixtures));
        let advisory_fixtures = Arc::new(Mutex::new(advisory_fixtures));
        let seen_auth: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let advisory_hits: Arc<Mutex<HashMap<String, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let seen_auth_thread = seen_auth.clone();
        let advisory_hits_thread = advisory_hits.clone();

        let handle = thread::spawn(move || {
            for stream in listener.incoming().take(32) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut buf = Vec::with_capacity(4096);
                let mut chunk = [0u8; 1024];
                while let Ok(n) = stream.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&buf);

                for line in req.lines() {
                    let lower = line.to_ascii_lowercase();
                    if lower.starts_with("authorization:") || lower.starts_with("corgea-token:") {
                        seen_auth_thread.lock().unwrap().push(line.to_string());
                    }
                }

                let (status_code, status_text, response_body): (u16, &str, String) = if let Some(
                    path,
                ) =
                    req.lines().next().and_then(|l| l.split_whitespace().nth(1))
                {
                    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                    if parts.len() >= 7
                        && parts[0] == "v1"
                        && parts[1] == "packages"
                        && parts[4] == "versions"
                        && parts[6] == "check"
                    {
                        let eco = parts[2].to_string();
                        let name = urlencoding::decode(parts[3])
                            .unwrap_or_default()
                            .into_owned();
                        let ver = urlencoding::decode(parts[5])
                            .unwrap_or_default()
                            .into_owned();
                        let body = fixtures
                            .lock()
                            .unwrap()
                            .get(&(eco.clone(), name.clone(), ver.clone()))
                            .map(|r| serde_json::to_string(r).unwrap())
                            .unwrap_or_else(|| {
                                serde_json::to_string(&crate::vuln_api::VulnCheckResponse {
                                    ecosystem: eco,
                                    package_name: name,
                                    version: ver,
                                    is_vulnerable: false,
                                    matches: vec![],
                                })
                                .unwrap()
                            });
                        (200, "OK", body)
                    } else if parts.len() >= 3 && parts[0] == "v1" && parts[1] == "advisories" {
                        let id = urlencoding::decode(parts[2])
                            .unwrap_or_default()
                            .into_owned();
                        *advisory_hits_thread
                            .lock()
                            .unwrap()
                            .entry(id.clone())
                            .or_insert(0) += 1;
                        match advisory_fixtures.lock().unwrap().get(&id) {
                            Some(r) => (200, "OK", serde_json::to_string(r).unwrap()),
                            None => (404, "Not Found", r#"{"error":"not found"}"#.to_string()),
                        }
                    } else {
                        (200, "OK", r#"{"error":"not found"}"#.to_string())
                    }
                } else {
                    (200, "OK", r#"{"error":"bad request"}"#.to_string())
                };

                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    status_code,
                    status_text,
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        thread::sleep(Duration::from_millis(50));

        VulnApiStub {
            base_url,
            seen_auth,
            advisory_hits,
            _handle: handle,
        }
    }

    #[test]
    fn pick_highest_fixed_npm_picks_highest() {
        let got = pick_highest_fixed(
            DependencyEcosystem::Npm,
            &["1.0.0".into(), "1.2.0".into(), "1.1.0".into()],
        );
        assert_eq!(got, Some("1.2.0".into()));
    }

    #[test]
    fn pick_highest_fixed_python_via_normalize() {
        // "1.0" normalises to "1.0.0", "1.0.1" stays as-is.
        let got = pick_highest_fixed(DependencyEcosystem::Python, &["1.0".into(), "1.0.1".into()]);
        assert_eq!(got, Some("1.0.1".into()));
    }

    #[test]
    fn pick_highest_fixed_unparseable_falls_back_to_first() {
        // Both PEP 440 prerelease — normalize_for_semver leaves them alone,
        // semver parsing fails, helper falls back to candidates.first().
        let got = pick_highest_fixed(
            DependencyEcosystem::Python,
            &["1.0a1".into(), "1.0rc1".into()],
        );
        assert_eq!(got, Some("1.0a1".into()));
    }

    #[test]
    fn pick_highest_fixed_empty_returns_none() {
        let got = pick_highest_fixed(DependencyEcosystem::Npm, &[]);
        assert_eq!(got, None);
    }

    #[test]
    fn vuln_api_stub_serves_advisory_fixture() {
        // Wire-shape fixture: `id`, `source_url`, no `remediation`.
        // Exercises the rename mapping in `AdvisoryResponse`.
        let mut advisory_fixtures = HashMap::new();
        advisory_fixtures.insert(
            "GHSA-foo".to_string(),
            serde_json::json!({
                "id": "GHSA-foo",
                "aliases": ["CVE-2026-0001"],
                "title": "test advisory",
                "severity_level": "high",
                "tier": 1,
                "source_url": "https://github.com/advisories/GHSA-foo",
            }),
        );
        let stub = spawn_vuln_api_stub_with_advisories(HashMap::new(), advisory_fixtures);

        let resp =
            crate::vuln_api::get_advisory(&stub.base_url, "test-token", "GHSA-foo").expect("ok");
        assert_eq!(resp.advisory_id, "GHSA-foo");
        assert_eq!(
            resp.url.as_deref(),
            Some("https://github.com/advisories/GHSA-foo")
        );

        let hits = stub.advisory_hits.lock().unwrap().clone();
        assert_eq!(hits.get("GHSA-foo").copied(), Some(1));
    }

    #[test]
    fn vuln_api_stub_returns_404_for_missing_advisory() {
        let stub = spawn_vuln_api_stub_with_advisories(HashMap::new(), HashMap::new());
        let err = crate::vuln_api::get_advisory(&stub.base_url, "test-token", "GHSA-missing")
            .unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("404"), "expected 404 in error, got: {}", msg);

        // The /check route still works against the same stub.
        let resp = crate::vuln_api::check_package_version(
            &stub.base_url,
            "test-token",
            "npm",
            "lodash",
            "4.17.20",
        )
        .expect("clean fallback");
        assert!(!resp.is_vulnerable);
    }

    #[test]
    fn parse_threshold_units() {
        assert_eq!(
            parse_threshold("2d").unwrap(),
            Duration::from_secs(2 * 86400)
        );
        assert_eq!(
            parse_threshold("48h").unwrap(),
            Duration::from_secs(48 * 3600)
        );
        assert_eq!(
            parse_threshold("30m").unwrap(),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(parse_threshold("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(
            parse_threshold("1w").unwrap(),
            Duration::from_secs(7 * 86400)
        );
        assert_eq!(
            parse_threshold("3").unwrap(),
            Duration::from_secs(3 * 86400)
        );
        assert_eq!(parse_threshold("0.5d").unwrap(), Duration::from_secs(43200));
    }

    #[test]
    fn parse_threshold_rejects_garbage() {
        assert!(parse_threshold("").is_err());
        assert!(parse_threshold("abc").is_err());
        assert!(parse_threshold("-1d").is_err());
        assert!(parse_threshold("1y").is_err());
    }

    #[test]
    fn format_duration_short() {
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_secs(120)), "2m");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(3700)), "1h 1m");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d");
        assert_eq!(format_duration(Duration::from_secs(90000)), "1d 1h");
    }

    #[test]
    fn ecosystem_parse_aliases() {
        assert_eq!(Ecosystem::parse("npm").unwrap(), Ecosystem::Npm);
        assert_eq!(Ecosystem::parse("Python").unwrap(), Ecosystem::Python);
        assert_eq!(Ecosystem::parse("all").unwrap(), Ecosystem::All);
        assert!(Ecosystem::parse("ruby").is_err());
    }

    #[test]
    fn verify_options_default_fail_cve_is_false() {
        let opts = VerifyOptions::default();
        assert!(!opts.fail_cve);
    }

    #[test]
    fn run_without_check_cve_has_empty_cve_outcomes() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
            "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": { "name": "demo", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#,
        )
        .unwrap();

        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: false,
            vuln_api_url: None,
            ..Default::default()
        };

        let report = run(&opts).expect("run should succeed");
        assert!(!report.check_cve);
        assert!(report.cve_outcomes.is_empty());
    }

    #[test]
    fn check_cve_reports_vulnerabilities_from_stub() {
        use crate::verify_deps::report::format_cve_finding;

        let mut fixtures = HashMap::new();
        fixtures.insert(
            ("npm".into(), "lodash".into(), "4.17.20".into()),
            crate::vuln_api::VulnCheckResponse {
                ecosystem: "npm".into(),
                package_name: "lodash".into(),
                version: "4.17.20".into(),
                is_vulnerable: true,
                matches: vec![crate::vuln_api::VulnMatch {
                    advisory_id: "GHSA-integration-test".into(),
                    severity_level: "high".into(),
                    tier: 1,
                    vulnerable_version_range: Some("<4.17.21".into()),
                    fixed_version: Some("4.17.21".into()),
                }],
            },
        );

        let stub = spawn_vuln_api_stub(fixtures);

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
            "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": { "name": "demo", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.20" }
            }
        }"#,
        )
        .unwrap();

        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: true,
            vuln_api_url: Some(stub.base_url.clone()),
            vuln_api_token: Some("test-token".into()),
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };

        let report = run(&opts).expect("run should succeed");
        assert_eq!(report.cve_findings().len(), 1);
        assert_eq!(
            report.cve_findings()[0].matches[0].advisory_id,
            "GHSA-integration-test"
        );
        let text_line = format_cve_finding(report.cve_findings()[0]);
        assert!(text_line.contains("GHSA-integration-test"));
        assert!(
            text_line.contains("fix: upgrade to 4.17.21"),
            "expected fix-version substring, got: {}",
            text_line
        );

        // Auth header must have been attached.
        let auth = stub.seen_auth.lock().unwrap().clone();
        assert!(
            auth.iter()
                .any(|h| h.to_ascii_lowercase().contains("corgea-token: test-token")),
            "expected CORGEA-TOKEN header, got: {:?}",
            auth
        );

        let opts_off = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: false,
            vuln_api_url: None,
            vuln_api_token: None,
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };
        let report_off = run(&opts_off).expect("run should succeed");
        assert!(!report_off.check_cve);
        assert!(report_off.cve_outcomes.is_empty());
    }

    #[test]
    fn check_cve_renders_advisory_url_and_fix_version() {
        use crate::verify_deps::report::format_cve_finding;

        let mut fixtures = HashMap::new();
        fixtures.insert(
            ("npm".into(), "lodash".into(), "4.17.20".into()),
            crate::vuln_api::VulnCheckResponse {
                ecosystem: "npm".into(),
                package_name: "lodash".into(),
                version: "4.17.20".into(),
                is_vulnerable: true,
                matches: vec![crate::vuln_api::VulnMatch {
                    advisory_id: "GHSA-integration-test".into(),
                    severity_level: "high".into(),
                    tier: 1,
                    vulnerable_version_range: Some("<4.17.21".into()),
                    fixed_version: Some("4.17.21".into()),
                }],
            },
        );
        let mut advisories = HashMap::new();
        advisories.insert(
            "GHSA-integration-test".to_string(),
            serde_json::json!({
                "id": "GHSA-integration-test",
                "severity_level": "high",
                "tier": 1,
                "source_url": "https://github.com/advisories/GHSA-integration-test",
            }),
        );
        let stub = spawn_vuln_api_stub_with_advisories(fixtures, advisories);

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "1.0.0" },
                    "node_modules/lodash": { "version": "4.17.20" }
                }
            }"#,
        )
        .unwrap();

        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: true,
            vuln_api_url: Some(stub.base_url.clone()),
            vuln_api_token: Some("test-token".into()),
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };

        let report = run(&opts).expect("run ok");
        assert_eq!(report.cve_findings().len(), 1);
        let finding = report.cve_findings()[0];
        assert_eq!(finding.advisory_details.len(), finding.matches.len());
        assert!(finding.advisory_details[0].is_some());

        let line = format_cve_finding(finding);
        assert!(line.contains("fix: upgrade to 4.17.21"), "got: {}", line);
        assert!(
            line.contains("https://github.com/advisories/GHSA-integration-test"),
            "got: {}",
            line
        );

        let hits = stub.advisory_hits.lock().unwrap().clone();
        assert_eq!(hits.get("GHSA-integration-test").copied(), Some(1));
    }

    #[test]
    fn check_cve_dedupes_shared_advisory_lookups() {
        let mut fixtures = HashMap::new();
        let mk = |name: &str| crate::vuln_api::VulnCheckResponse {
            ecosystem: "npm".into(),
            package_name: name.into(),
            version: "1.0.0".into(),
            is_vulnerable: true,
            matches: vec![crate::vuln_api::VulnMatch {
                advisory_id: "GHSA-shared".into(),
                severity_level: "high".into(),
                tier: 1,
                vulnerable_version_range: Some("<2.0.0".into()),
                fixed_version: Some("2.0.0".into()),
            }],
        };
        fixtures.insert(("npm".into(), "alpha".into(), "1.0.0".into()), mk("alpha"));
        fixtures.insert(("npm".into(), "beta".into(), "1.0.0".into()), mk("beta"));

        let mut advisories = HashMap::new();
        advisories.insert(
            "GHSA-shared".to_string(),
            serde_json::json!({
                "id": "GHSA-shared",
                "severity_level": "high",
                "tier": 1,
                "source_url": "https://github.com/advisories/GHSA-shared",
            }),
        );
        let stub = spawn_vuln_api_stub_with_advisories(fixtures, advisories);

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "1.0.0" },
                    "node_modules/alpha": { "version": "1.0.0" },
                    "node_modules/beta":  { "version": "1.0.0" }
                }
            }"#,
        )
        .unwrap();

        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: true,
            vuln_api_url: Some(stub.base_url.clone()),
            vuln_api_token: Some("test-token".into()),
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };
        let report = run(&opts).expect("run ok");
        assert_eq!(report.cve_findings().len(), 2);

        let hits = stub.advisory_hits.lock().unwrap().clone();
        assert_eq!(
            hits.get("GHSA-shared").copied(),
            Some(1),
            "hits = {:?}",
            hits
        );

        // Both findings carry the same URL via the cache.
        for f in report.cve_findings() {
            let detail = f.advisory_details[0].as_ref().expect("detail present");
            assert_eq!(
                detail.url.as_deref(),
                Some("https://github.com/advisories/GHSA-shared")
            );
        }
    }

    #[test]
    fn check_cve_handles_advisory_lookup_failure() {
        use crate::verify_deps::report::format_cve_finding;

        let mut fixtures = HashMap::new();
        fixtures.insert(
            ("npm".into(), "lodash".into(), "4.17.20".into()),
            crate::vuln_api::VulnCheckResponse {
                ecosystem: "npm".into(),
                package_name: "lodash".into(),
                version: "4.17.20".into(),
                is_vulnerable: true,
                matches: vec![crate::vuln_api::VulnMatch {
                    advisory_id: "GHSA-no-detail".into(),
                    severity_level: "high".into(),
                    tier: 1,
                    vulnerable_version_range: Some("<4.17.21".into()),
                    fixed_version: Some("4.17.21".into()),
                }],
            },
        );
        // Note: no advisory fixture for GHSA-no-detail — stub returns 404.
        let stub = spawn_vuln_api_stub_with_advisories(fixtures, HashMap::new());

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "1.0.0" },
                    "node_modules/lodash": { "version": "4.17.20" }
                }
            }"#,
        )
        .unwrap();
        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: true,
            vuln_api_url: Some(stub.base_url.clone()),
            vuln_api_token: Some("test-token".into()),
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };
        let report = run(&opts).expect("run ok");
        assert_eq!(report.cve_findings().len(), 1);
        let f = report.cve_findings()[0];
        assert!(
            f.advisory_details[0].is_none(),
            "expected detail to be None on 404"
        );

        let line = format_cve_finding(f);
        assert!(line.contains("GHSA-no-detail"), "got: {}", line);
        assert!(line.contains("fix: upgrade to 4.17.21"), "got: {}", line);
        assert!(
            !line.contains("https://"),
            "should not render URL: {}",
            line
        );
    }

    #[test]
    fn check_cve_json_includes_advisory_url() {
        let mut fixtures = HashMap::new();
        fixtures.insert(
            ("npm".into(), "lodash".into(), "4.17.20".into()),
            crate::vuln_api::VulnCheckResponse {
                ecosystem: "npm".into(),
                package_name: "lodash".into(),
                version: "4.17.20".into(),
                is_vulnerable: true,
                matches: vec![crate::vuln_api::VulnMatch {
                    advisory_id: "GHSA-json".into(),
                    severity_level: "high".into(),
                    tier: 1,
                    vulnerable_version_range: Some("<4.17.21".into()),
                    fixed_version: Some("4.17.21".into()),
                }],
            },
        );
        let mut advisories = HashMap::new();
        advisories.insert(
            "GHSA-json".to_string(),
            serde_json::json!({
                "id": "GHSA-json",
                "severity_level": "high",
                "tier": 1,
                "source_url": "https://github.com/advisories/GHSA-json",
            }),
        );
        let stub = spawn_vuln_api_stub_with_advisories(fixtures, advisories);

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "1.0.0" },
                    "node_modules/lodash": { "version": "4.17.20" }
                }
            }"#,
        )
        .unwrap();
        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: true,
            vuln_api_url: Some(stub.base_url.clone()),
            vuln_api_token: Some("test-token".into()),
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };
        let report = run(&opts).expect("run ok");
        let finding = report.cve_findings()[0];

        // Re-serialise the per-match JSON entry inline (mirrors print_json).
        let detail = finding.advisory_details[0].as_ref();
        let m = &finding.matches[0];
        let entry = serde_json::json!({
            "advisory_id": m.advisory_id,
            "severity_level": m.severity_level,
            "tier": m.tier,
            "vulnerable_version_range": m.vulnerable_version_range,
            "fixed_version": m.fixed_version,
            "advisory_url": detail.and_then(|d| d.url.clone()),
        });
        assert_eq!(
            entry["advisory_url"].as_str(),
            Some("https://github.com/advisories/GHSA-json")
        );
        assert_eq!(entry["fixed_version"].as_str(), Some("4.17.21"));
        assert!(
            entry.get("remediation").is_none(),
            "remediation should not appear in CVE JSON output"
        );
    }

    fn fixture_deps_dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/deps")
            .join(name)
    }

    #[test]
    fn deps_dogfood_npm_discovers_pins() {
        let result = npm::discover(&fixture_deps_dir("npm"), false).expect("discover npm");
        assert!(result.warnings.is_empty());
        assert_eq!(result.deps.len(), 3);
        let names: Vec<_> = result.deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"semver"));
        assert!(names.contains(&"json5"));
    }

    #[test]
    fn deps_dogfood_npm_unpinned() {
        let result =
            npm::discover(&fixture_deps_dir("npm-unpinned"), false).expect("discover npm-unpinned");
        assert!(result.deps.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].manifest.ends_with("package.json"));

        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: fixture_deps_dir("npm-unpinned"),
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };
        let report = run(&opts).expect("run should succeed");
        assert!(report.has_unpinned());
    }

    #[test]
    fn deps_dogfood_npm_cve_with_stub() {
        let mut fixtures = HashMap::new();
        fixtures.insert(
            ("npm".into(), "lodash".into(), "4.17.20".into()),
            crate::vuln_api::VulnCheckResponse {
                ecosystem: "npm".into(),
                package_name: "lodash".into(),
                version: "4.17.20".into(),
                is_vulnerable: true,
                matches: vec![crate::vuln_api::VulnMatch {
                    advisory_id: "GHSA-dogfood-fixture".into(),
                    severity_level: "high".into(),
                    tier: 1,
                    vulnerable_version_range: Some("<4.17.21".into()),
                    fixed_version: Some("4.17.21".into()),
                }],
            },
        );
        let mut advisories = HashMap::new();
        advisories.insert(
            "GHSA-dogfood-fixture".to_string(),
            serde_json::json!({
                "id": "GHSA-dogfood-fixture",
                "severity_level": "high",
                "tier": 1,
                "source_url": "https://github.com/advisories/GHSA-dogfood-fixture",
            }),
        );
        let stub = spawn_vuln_api_stub_with_advisories(fixtures, advisories);

        let opts = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: fixture_deps_dir("npm"),
            check_cve: true,
            vuln_api_url: Some(stub.base_url),
            vuln_api_token: Some("test-token".into()),
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };

        let report = run(&opts).expect("run should succeed");
        assert_eq!(report.cve_findings().len(), 1);
        assert_eq!(report.cve_findings()[0].dep.name, "lodash");
        assert_eq!(
            report.cve_findings()[0].matches[0].advisory_id,
            "GHSA-dogfood-fixture"
        );
    }

    #[test]
    fn deps_dogfood_yarn_lock_parses() {
        let result = npm::discover(&fixture_deps_dir("yarn"), false).expect("discover yarn");
        assert!(result.warnings.is_empty());
        assert_eq!(result.deps.len(), 3);
        assert!(result.source.ends_with("yarn.lock"));
    }

    #[test]
    fn deps_dogfood_pnpm_lock_parses() {
        let result = npm::discover(&fixture_deps_dir("pnpm"), false).expect("discover pnpm");
        assert!(result.warnings.is_empty());
        assert_eq!(result.deps.len(), 3);
        assert!(result.source.ends_with("pnpm-lock.yaml"));
    }

    #[test]
    fn deps_dogfood_python_requirements_discovers() {
        let result = python::discover(&fixture_deps_dir("python-requirements"), false)
            .expect("discover python-requirements");
        assert!(result.warnings.is_empty());
        assert_eq!(result.deps.len(), 4);
        let names: Vec<_> = result.deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"django"));
        assert!(names.contains(&"pyyaml"));
        assert!(names.contains(&"urllib3"));
        assert!(names.contains(&"pillow"));
    }

    #[test]
    fn deps_dogfood_python_poetry_discovers() {
        let result = python::discover(&fixture_deps_dir("python-poetry"), false)
            .expect("discover python-poetry");
        assert!(result.warnings.is_empty());
        assert_eq!(result.deps.len(), 2);
        let names: Vec<_> = result.deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"django"));
        assert!(names.contains(&"pyyaml"));
    }

    #[test]
    fn deps_dogfood_python_uv_discovers() {
        let result =
            python::discover(&fixture_deps_dir("python-uv"), false).expect("discover python-uv");
        assert!(result.warnings.is_empty());
        assert_eq!(result.deps.len(), 2);
        let names: Vec<_> = result.deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"django"));
        assert!(names.contains(&"urllib3"));
    }
}
