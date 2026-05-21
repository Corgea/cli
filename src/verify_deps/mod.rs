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

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub ecosystem: Ecosystem,
    pub threshold: Duration,
    pub include_dev: bool,
    pub fail: bool,
    pub json: bool,
    pub path: PathBuf,
    /// Optional registry overrides (used in tests).
    pub npm_registry: Option<String>,
    pub pypi_registry: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            ecosystem: Ecosystem::All,
            threshold: Duration::from_secs(2 * 24 * 60 * 60),
            include_dev: false,
            fail: false,
            json: false,
            path: PathBuf::from("."),
            npm_registry: None,
            pypi_registry: None,
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
        Some(c) if c.is_ascii_alphabetic() => (&s[..s.len() - c.len_utf8()], c.to_ascii_lowercase()),
        _ => (s, 'd'),
    };

    let value: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid threshold number: '{}'", num_str))?;

    if value < 0.0 || !value.is_finite() {
        return Err(format!("threshold must be a non-negative finite number: '{}'", input));
    }

    let secs = match unit {
        's' => value,
        'm' => value * 60.0,
        'h' => value * 3600.0,
        'd' => value * 86400.0,
        'w' => value * 7.0 * 86400.0,
        other => return Err(format!("unknown threshold unit '{}'. Use s, m, h, d, or w.", other)),
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

    if matches!(opts.ecosystem, Ecosystem::Npm | Ecosystem::All) {
        match npm::discover(path, opts.include_dev) {
            Ok(mut found) => {
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

    if deps.is_empty() {
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
    deps.dedup_by(|a, b| {
        a.name == b.name && a.version == b.version && a.ecosystem == b.ecosystem
    });

    let now = Utc::now();
    let threshold = chrono::Duration::from_std(opts.threshold)
        .map_err(|e| format!("invalid threshold: {}", e))?;

    let mut outcomes: Vec<LookupOutcome> = Vec::with_capacity(deps.len());

    for dep in deps {
        let published = match dep.ecosystem {
            DependencyEcosystem::Npm => registry::npm_publish_time(
                &dep.name,
                &dep.version,
                opts.npm_registry.as_deref(),
            ),
            DependencyEcosystem::Python => registry::pypi_publish_time(
                &dep.name,
                &dep.version,
                opts.pypi_registry.as_deref(),
            ),
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
    }

    Ok(VerifyReport {
        sources,
        outcomes,
        threshold: opts.threshold,
        scanned_at: now,
    })
}

/// Aggregated result of a verification run.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub sources: Vec<String>,
    pub outcomes: Vec<LookupOutcome>,
    pub threshold: Duration,
    pub scanned_at: DateTime<Utc>,
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
}

/// Helper used by lockfile parsers to bundle their result.
#[derive(Debug, Clone)]
pub struct DiscoverResult {
    pub deps: Vec<Dependency>,
    pub source: String,
}

/// Read the file at `path` into a String, returning an informative error.
pub(crate) fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_threshold_units() {
        assert_eq!(parse_threshold("2d").unwrap(), Duration::from_secs(2 * 86400));
        assert_eq!(parse_threshold("48h").unwrap(), Duration::from_secs(48 * 3600));
        assert_eq!(parse_threshold("30m").unwrap(), Duration::from_secs(30 * 60));
        assert_eq!(parse_threshold("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_threshold("1w").unwrap(), Duration::from_secs(7 * 86400));
        assert_eq!(parse_threshold("3").unwrap(), Duration::from_secs(3 * 86400));
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
}
