//! Install wrappers: `corgea npm`, `corgea pip`.
//!
//! Wraps an install command from a supported package manager, resolves the
//! named install targets against the public registry, and either blocks the
//! install or runs it transparently.
//!
//! Two independent blocks:
//!   * recency — the resolved version was published within `--threshold`
//!     (default `2d`); `--no-fail` demotes this to a warning;
//!   * vuln verdict — the vuln-api knows the resolved version is vulnerable
//!     or malicious; only `--force` overrides this.
//!
//! Verdict lookups are public and fail open: a vuln-api outage warns and the
//! install continues.

mod exec;
mod parse;
mod render;
mod verdict;

#[cfg(test)]
mod test_support;

use std::time::Duration;

use chrono::Utc;

/// Supported package managers. Each one shares enough behaviour with
/// the others that we only need a small per-manager dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Npm,
    Pip,
}

impl PackageManager {
    pub fn binary_name(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pip => "pip",
        }
    }

    /// Subcommands that this manager treats as "install something new"
    /// — the only ones we need to verify before running.
    pub fn is_install_subcommand(self, sub: &str) -> bool {
        match self {
            PackageManager::Npm => matches!(sub, "install" | "i" | "add"),
            PackageManager::Pip => matches!(sub, "install"),
        }
    }

    /// vuln-api ecosystem for this manager's registry.
    pub fn ecosystem(self) -> crate::vuln_api::Ecosystem {
        match self {
            PackageManager::Npm => crate::vuln_api::Ecosystem::Npm,
            PackageManager::Pip => crate::vuln_api::Ecosystem::Pypi,
        }
    }
}

/// Connection details for the vuln-api verdict pass. Lookups are public
/// (no auth) and fail open: known vulnerable/malicious verdicts block,
/// while lookup errors warn and continue.
#[derive(Debug, Clone)]
pub struct VerdictConfig {
    pub base_url: String,
}

/// Threat verdict for one resolved target.
#[derive(Debug, Clone)]
pub enum VerdictStatus {
    /// vuln-api answered: no known advisories for this exact version.
    Clean,
    /// vuln-api answered: known vulnerable or malicious — blocks.
    Vulnerable(Vec<crate::vuln_api::VulnMatch>),
    /// The verdict could not be obtained (network/5xx/integrity).
    /// Public mode fails open: warns, never blocks.
    Unverifiable(String),
    /// Verdict never attempted (no `VerdictConfig`).
    NotChecked,
}

impl VerdictStatus {
    /// Whether this verdict blocks the install. The single definition of
    /// "blocking finding", used by `verdict::block_reason`.
    fn blocks(&self) -> bool {
        matches!(self, VerdictStatus::Vulnerable(_))
    }
}

#[derive(Debug, Clone)]
pub struct PrecheckOptions {
    pub threshold: Duration,
    /// If true, demote a recent finding from "block" to "warn-and-run".
    pub no_fail: bool,
    /// If true, never block: print findings (recent, vulnerable,
    /// unverifiable) and run the install anyway.
    pub force: bool,
    /// `Some` ⇒ run the vuln-api verdict pass against this endpoint.
    /// `None` is retained for tests and direct library callers that want
    /// recency-only behavior.
    pub verdict: Option<VerdictConfig>,
    /// Optional registry overrides, used by tests.
    pub npm_registry: Option<String>,
    pub pypi_registry: Option<String>,
}

/// Each item the user asked us to install.
#[derive(Debug, Clone)]
pub struct InstallTarget {
    pub name: String,
    /// Display form, e.g. `axios@^1.0.0` or `requests==2.31.0`.
    pub display: String,
    /// What we'll feed into the resolver.
    pub kind: TargetKind,
}

#[derive(Debug, Clone)]
pub enum TargetKind {
    Npm(crate::verify_deps::registry::NpmSpec),
    Pypi(crate::verify_deps::registry::PypiSpec),
    /// Something we can't verify (URL/git/file/path) — we surface this
    /// as a warning but never block on it.
    Unverifiable {
        reason: String,
    },
}

/// Outcome of resolving + verifying a single target.
#[derive(Debug, Clone)]
pub enum TargetOutcome {
    /// Resolved cleanly. The blocking recency condition is derived from
    /// `age` against the report's threshold (`PrecheckReport::is_recent`).
    Resolved {
        target: InstallTarget,
        resolved: crate::verify_deps::registry::ResolvedPackage,
        age: Duration,
        verdict: VerdictStatus,
    },
    /// We deliberately couldn't verify this target (URL / git / etc.).
    Skipped {
        target: InstallTarget,
        reason: String,
    },
    /// Resolution failed (network, unknown package, bad spec).
    Error {
        target: InstallTarget,
        error: String,
    },
}

#[derive(Debug)]
pub struct PrecheckReport {
    pub manager: PackageManager,
    pub subcommand: String,
    pub original_args: Vec<String>,
    pub outcomes: Vec<TargetOutcome>,
    pub threshold: Duration,
}

impl PrecheckReport {
    fn count(&self, pred: impl Fn(&TargetOutcome) -> bool) -> usize {
        self.outcomes.iter().filter(|o| pred(o)).count()
    }
    /// True when this age is within the recency threshold (the blocking
    /// condition). The single definition of "recent".
    fn is_recent(&self, age: Duration) -> bool {
        age < self.threshold
    }
    pub fn ok_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Resolved { age, .. } if !self.is_recent(*age)))
    }
    pub fn recent_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Resolved { age, .. } if self.is_recent(*age)))
    }
    /// Verdicts on the resolved named targets.
    fn verdicts(&self) -> impl Iterator<Item = &VerdictStatus> {
        self.outcomes.iter().filter_map(|o| match o {
            TargetOutcome::Resolved { verdict, .. } => Some(verdict),
            _ => None,
        })
    }
    pub fn vulnerable_count(&self) -> usize {
        self.verdicts()
            .filter(|v| matches!(v, VerdictStatus::Vulnerable(_)))
            .count()
    }
    pub fn unverifiable_count(&self) -> usize {
        self.verdicts()
            .filter(|v| matches!(v, VerdictStatus::Unverifiable(_)))
            .count()
    }
    pub fn skipped_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Skipped { .. }))
    }
    pub fn error_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Error { .. }))
    }
}

/// Canonical entry for ecosystem commands (`corgea npm install …`).
///
/// `cmd` is everything after the ecosystem name, e.g.
/// `["install", "axios@^1.0.0", "--save-dev"]`. An empty `cmd` execs the
/// package manager with no arguments.
pub fn run_install(manager: PackageManager, cmd: &[String], opts: PrecheckOptions) -> i32 {
    if cmd.is_empty() {
        return exec::exec_command(manager.binary_name(), &[]);
    }

    // The install verb may follow global flags (`npm --silent install x`);
    // route on the first non-flag token so flags-before-verb can't slip
    // past the gate ungated.
    let Some(verb_idx) = find_subcommand(manager, cmd) else {
        return exec::exec_command(manager.binary_name(), cmd);
    };
    let subcommand = &cmd[verb_idx];
    let rest_vec: Vec<String> = cmd[..verb_idx]
        .iter()
        .chain(&cmd[verb_idx + 1..])
        .cloned()
        .collect();
    let rest = rest_vec.as_slice();

    if manager == PackageManager::Pip && subcommand == "add" {
        eprintln!("{}", unsupported_pip_add_message(rest));
        return 1;
    }

    if !manager.is_install_subcommand(subcommand) {
        // Non-install subcommand: transparent passthrough, args untouched.
        return exec::exec_command(manager.binary_name(), cmd);
    }

    let parsed = match parse::parse_install_args(manager, rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to parse install args: {}", e);
            return 2;
        }
    };

    run_parsed_install(
        manager,
        subcommand,
        rest,
        parsed,
        || exec::exec_install_with_args(manager, subcommand, rest),
        opts,
    )
}

/// Index of the first non-flag token in `cmd` — the subcommand verb.
/// Skips flag values with the same `takes_value` table as the arg parsers,
/// so `npm --loglevel silent install x` routes on `install`, not `silent`.
/// `None` ⇒ no subcommand at all (flags only, e.g. `npm --version`).
fn find_subcommand(manager: PackageManager, cmd: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < cmd.len() {
        let a = &cmd[i];
        if a == "--" {
            return (i + 1 < cmd.len()).then_some(i + 1);
        }
        if !a.starts_with('-') {
            return Some(i);
        }
        i += if !a.contains('=') && parse::takes_value(manager, a) {
            2
        } else {
            1
        };
    }
    None
}

/// `corgea <words…> <rest…>` — the suggested-command string used by the
/// "Did you mean …" messages.
fn corgea_cmd(words: &[&str], rest: &[String]) -> String {
    let mut parts = vec!["corgea".to_string()];
    parts.extend(words.iter().map(|w| w.to_string()));
    parts.extend(rest.iter().cloned());
    parts.join(" ")
}

pub fn pip3_alias_message(args: &[String]) -> Option<String> {
    let rest = args.strip_prefix(&["pip3".to_string()])?;
    Some(format!(
        "error: unknown package manager `pip3`.\nDid you mean `{}`?",
        corgea_cmd(&["pip"], rest)
    ))
}

fn unsupported_pip_add_message(rest: &[String]) -> String {
    format!(
        "error: pip does not support `add`.\nDid you mean `{}`?",
        corgea_cmd(&["pip", "install"], rest)
    )
}

/// Post-parse verification: resolve named targets, verdict them, render the
/// report, refuse (exit 1) when the block predicate fires, otherwise run
/// the install.
fn run_parsed_install(
    manager: PackageManager,
    subcommand_label: &str,
    rest: &[String],
    parsed: parse::ParsedInstall,
    exec: impl FnOnce() -> i32,
    opts: PrecheckOptions,
) -> i32 {
    if parsed.targets.is_empty() {
        // Nothing named: bare installs and requirements-only installs are
        // noted, never gated, by this phase.
        render::requirements_note(&parsed);
        return exec();
    }

    let now = Utc::now();
    let mut outcomes = verdict::verify_all(&parsed.targets, &opts, &now);
    verdict::run_verdict_pass(manager, &mut outcomes, &opts);
    render::requirements_note(&parsed);

    let report = PrecheckReport {
        manager,
        subcommand: subcommand_label.to_string(),
        original_args: rest.to_vec(),
        outcomes,
        threshold: opts.threshold,
    };

    render::print_text(&report);
    render::warn_public_lookup_failures(&report, &opts);
    if let Some(reason) = verdict::block_reason(&report, &opts) {
        render::print_refusal(reason);
        return 1;
    }
    exec()
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn install_subcommand_recognition() {
        assert!(PackageManager::Npm.is_install_subcommand("install"));
        assert!(PackageManager::Npm.is_install_subcommand("i"));
        assert!(PackageManager::Npm.is_install_subcommand("add"));
        assert!(!PackageManager::Npm.is_install_subcommand("update"));

        assert!(PackageManager::Pip.is_install_subcommand("install"));
        assert!(!PackageManager::Pip.is_install_subcommand("freeze"));
    }

    /// Run `run_parsed_install` for `pip install <args…>` with an exec
    /// closure that records whether it ran (returning 42 instead of
    /// spawning anything).
    fn gate_pip_install(args: &[&str], opts: PrecheckOptions) -> (i32, bool) {
        let rest: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let parsed = parse::parse_install_args(PackageManager::Pip, &rest).expect("parse");
        let mut exec_ran = false;
        let code = run_parsed_install(
            PackageManager::Pip,
            "install",
            &rest,
            parsed,
            || {
                exec_ran = true;
                42
            },
            opts,
        );
        (code, exec_ran)
    }

    #[test]
    fn unverifiable_target_skips_and_proceeds() {
        // git+ spec → Skipped outcome, no registry hit, install proceeds.
        let opts = stub_opts();
        let (code, exec_ran) = gate_pip_install(&["git+https://github.com/psf/requests.git"], opts);
        assert_eq!(code, 42);
        assert!(exec_ran);
    }

    #[test]
    fn bare_install_passes_through_without_verification() {
        // Bare `pip install` (no targets) → straight exec, no registry hit.
        let opts = stub_opts();
        let (code, exec_ran) = gate_pip_install(&[], opts);
        assert_eq!(code, 42);
        assert!(exec_ran);
    }

    #[test]
    fn requirements_files_note_then_exec() {
        // `-r reqs.txt` alone → printed note, no verification, exec runs.
        let opts = stub_opts();
        let (code, exec_ran) = gate_pip_install(&["-r", "reqs.txt"], opts);
        assert_eq!(code, 42);
        assert!(exec_ran);
    }

    #[test]
    fn ecosystem_mapping() {
        use crate::vuln_api::Ecosystem;
        assert_eq!(PackageManager::Pip.ecosystem(), Ecosystem::Pypi);
        assert_eq!(PackageManager::Npm.ecosystem(), Ecosystem::Npm);
    }
}
