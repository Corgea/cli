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
    pub json: bool,
    pub path: PathBuf,
    /// Optional registry overrides (used in tests).
    pub npm_registry: Option<String>,
    pub pypi_registry: Option<String>,
    /// When true, query vuln-api for known CVEs/advisories per dependency.
    pub check_cve: bool,
    /// Base URL for vuln-api (resolved from env/config in main.rs).
    pub vuln_api_url: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            ecosystem: Ecosystem::All,
            threshold: Duration::from_secs(2 * 24 * 60 * 60),
            include_dev: false,
            fail: false,
            fail_unpinned: false,
            json: false,
            path: PathBuf::from("."),
            npm_registry: None,
            pypi_registry: None,
            check_cve: false,
            vuln_api_url: None,
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

    for dep in deps {
        let dep_for_cve = dep.clone();

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

        if opts.check_cve {
            if let Some(base_url) = opts.vuln_api_url.as_deref() {
                match crate::vuln_api::check_package_version(
                    base_url,
                    dep_for_cve.ecosystem.vuln_api_ecosystem(),
                    &dep_for_cve.name,
                    &dep_for_cve.version,
                ) {
                    Ok(response) if response.is_vulnerable && !response.matches.is_empty() => {
                        cve_outcomes.push(CveLookupOutcome::Vulnerable(CveFinding {
                            dep: dep_for_cve,
                            matches: response.matches,
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
        _handle: thread::JoinHandle<()>,
    }

    fn spawn_vuln_api_stub(
        fixtures: HashMap<(String, String, String), crate::vuln_api::VulnCheckResponse>,
    ) -> VulnApiStub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);
        let fixtures = Arc::new(Mutex::new(fixtures));

        let handle = thread::spawn(move || {
            for stream in listener.incoming().take(32) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                let response_body = if let Some(path) =
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
                        let ver = parts[5].to_string();
                        fixtures
                            .lock()
                            .unwrap()
                            .get(&(eco, name, ver))
                            .map(|r| serde_json::to_string(r).unwrap())
                            .unwrap_or_else(|| {
                                r#"{"is_vulnerable":false,"matches":[]}"#.to_string()
                            })
                    } else {
                        r#"{"error":"not found"}"#.to_string()
                    }
                } else {
                    r#"{"error":"bad request"}"#.to_string()
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        thread::sleep(Duration::from_millis(50));

        VulnApiStub {
            base_url,
            _handle: handle,
        }
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
        use crate::utils::api::set_auth_token;
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
        set_auth_token("test-token");

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

        let opts_off = VerifyOptions {
            ecosystem: Ecosystem::Npm,
            path: dir.path().to_path_buf(),
            check_cve: false,
            vuln_api_url: None,
            npm_registry: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        };
        let report_off = run(&opts_off).expect("run should succeed");
        assert!(!report_off.check_cve);
        assert!(report_off.cve_outcomes.is_empty());
    }
}
