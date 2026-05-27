//! CLI args for `corgea deps verify` (registry freshness + optional CVE check).
//!
//! Execution lives in the binary (`main.rs`) via the internal freshness engine module
//! at `src/verify_deps/` (binary-only; depends on `utils` and `vuln_api`).

use clap::Args;

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    #[arg(
        long,
        short = 'e',
        default_value = "all",
        help = "Which ecosystem(s) to verify. Valid options are 'npm', 'python', or 'all' (default)."
    )]
    pub ecosystem: String,

    #[arg(
        long,
        short = 't',
        default_value = "2d",
        help = "Recency threshold. Any dependency published within this window is flagged. Examples: '2d' (default), '48h', '30m', '1w'. Bare numbers are interpreted as days."
    )]
    pub threshold: String,

    #[arg(
        long,
        help = "Include development dependencies (default: production only)."
    )]
    pub include_dev: bool,

    #[arg(
        long,
        short = 'f',
        help = "Exit with a non-zero status code if any recently published dependency is found."
    )]
    pub fail: bool,

    #[arg(
        long,
        help = "Exit with a non-zero status code if any dependency is unpinned (e.g. package.json without a lockfile, pyproject.toml/Pipfile without a matching lockfile, or unpinned `requirements.txt` lines). Independent of --fail."
    )]
    pub fail_unpinned: bool,

    #[arg(
        long,
        help = "Output the result as JSON instead of human-readable text."
    )]
    pub json: bool,

    #[arg(
        long,
        short = 'p',
        help = "Path to the project to verify. Defaults to the current directory."
    )]
    pub path: Option<String>,

    #[arg(
        long,
        help = "Check each dependency against the Corgea vulnerability database for known CVEs/advisories. Requires corgea login (or CORGEA_TOKEN). See https://docs.corgea.app/cli/deps#check-cve."
    )]
    pub check_cve: bool,

    #[arg(
        long,
        env = "CORGEA_CVE_CONCURRENCY",
        default_value = "8",
        value_parser = clap::value_parser!(u8).range(1..=32),
        help = "Max in-flight vuln-api requests when --check-cve is set (1..32). Tune down for slow networks or vuln-api rate limits."
    )]
    pub cve_concurrency: u8,

    #[arg(
        long,
        requires = "check_cve",
        help = "Exit with a non-zero status code if any known CVE is found. Requires --check-cve. Independent of --fail and --fail-unpinned. See https://docs.corgea.app/cli/deps#check-cve."
    )]
    pub fail_cve: bool,

    #[arg(
        long,
        default_value = "any",
        help = "Minimum severity required to trip --fail-cve. Single value (critical|high|medium|low|info) matches that level and above; comma-separated list (e.g. critical,high) matches exactly those levels; 'any' (default) matches everything. Requires --fail-cve when set to a non-'any' value. See https://docs.corgea.app/cli/deps#severity."
    )]
    pub severity: String,
}
