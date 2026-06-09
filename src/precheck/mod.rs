//! Install wrappers: `corgea npm`, `corgea yarn`, `corgea pnpm`, `corgea pip`, `corgea uv`.
//!
//! Wraps an install command from a supported package manager, resolves what
//! the package manager *would* install against the public registry, and either
//! blocks the install or runs it transparently.
//!
//! Verification rule: a package is rejected if the resolved version
//! was published within `--threshold` (default `2d`). This mirrors
//! the `deps` flow but applies to the install-time set of
//! packages instead of the already-locked set.
//!
//! By default a "recent" finding makes the wrapper exit with status 1
//! *without* running the install. Use `--no-fail` to demote this to a
//! warning (the install runs anyway).

pub mod parse;

use std::ffi::OsString;
use std::process::Command;
use std::time::Duration;

use chrono::Utc;

use crate::verify_deps;

/// Supported package managers. Each one shares enough behaviour with
/// the others that we only need a small per-manager dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
    Pip,
    Uv,
}

impl PackageManager {
    pub fn binary_name(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Yarn => "yarn",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Pip => "pip",
            PackageManager::Uv => "uv",
        }
    }

    /// Subcommands that this manager treats as "install something new"
    /// — the only ones we need to verify before running.
    pub fn is_install_subcommand(self, sub: &str) -> bool {
        match self {
            PackageManager::Npm => matches!(sub, "install" | "i" | "add"),
            PackageManager::Yarn => matches!(sub, "add" | "install"),
            PackageManager::Pnpm => matches!(sub, "add" | "install" | "i"),
            PackageManager::Pip => matches!(sub, "install"),
            PackageManager::Uv => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrecheckOptions {
    pub threshold: Duration,
    /// If true, demote a recent finding from "block" to "warn-and-run".
    pub no_fail: bool,
    pub json: bool,
    /// Optional registry overrides, used by tests.
    pub npm_registry: Option<String>,
    pub pypi_registry: Option<String>,
}

/// Each item the user (or a `-r` requirements file) asked us to install.
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
    /// Resolved cleanly. `recent` is true when the version was
    /// published within the threshold (the blocking condition).
    Resolved {
        target: InstallTarget,
        resolved: crate::verify_deps::registry::ResolvedPackage,
        age: Duration,
        recent: bool,
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
    pub fn ok_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Resolved { recent: false, .. }))
    }
    pub fn recent_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Resolved { recent: true, .. }))
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
    if manager == PackageManager::Uv {
        return run_uv(cmd, opts);
    }

    if cmd.is_empty() {
        return exec_command(manager.binary_name(), &[]);
    }

    let subcommand = &cmd[0];
    let rest = &cmd[1..];

    if !manager.is_install_subcommand(subcommand) {
        return exec_install_with_args(manager, subcommand, rest);
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
        || exec_install_with_args(manager, subcommand, rest),
        opts,
    )
}

fn run_uv(cmd: &[String], opts: PrecheckOptions) -> i32 {
    let exec = || exec_command("uv", cmd);

    match parse::classify_uv_command(cmd) {
        parse::UvCommand::Passthrough => exec(),
        parse::UvCommand::PipInstall { install_args } => {
            let parsed = match parse::parse_pip_install_args(install_args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("failed to parse install args: {}", e);
                    return 2;
                }
            };
            run_parsed_install(
                PackageManager::Uv,
                "pip install",
                install_args,
                parsed,
                exec,
                opts,
            )
        }
        parse::UvCommand::Add { add_args } => run_parsed_install(
            PackageManager::Uv,
            "add",
            add_args,
            parse::parse_pypi_positionals_args(add_args),
            exec,
            opts,
        ),
    }
}

/// Post-parse verification shared by npm/yarn/pnpm/pip and uv install paths.
fn run_parsed_install(
    manager: PackageManager,
    subcommand_label: &str,
    rest: &[String],
    parsed: parse::ParsedInstall,
    exec: impl FnOnce() -> i32,
    opts: PrecheckOptions,
) -> i32 {
    if !parsed.requirements_files.is_empty() {
        let files: Vec<String> = parsed
            .requirements_files
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        eprintln!(
            "note: requirements files ({}) are not recency-checked by the baseline gate",
            files.join(", ")
        );
    }

    if parsed.targets.is_empty() {
        return exec();
    }

    let now = Utc::now();
    let threshold =
        chrono::Duration::from_std(opts.threshold).expect("threshold validated before run_install");

    let outcomes: Vec<_> = parsed
        .targets
        .iter()
        .map(|target| verify_one(target, &opts, &now, threshold))
        .collect();

    let report = PrecheckReport {
        manager,
        subcommand: subcommand_label.to_string(),
        original_args: rest.to_vec(),
        outcomes,
        threshold: opts.threshold,
    };

    if opts.json {
        print_json(&report);
    } else {
        print_text(&report);
    }

    if should_block_install(&report, &opts) {
        if !opts.json {
            eprintln!("Refusing to run install. Pass --no-fail to proceed anyway.");
        }
        return 1;
    }

    exec()
}

fn should_block_install(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
    !opts.no_fail && report.recent_count() > 0
}

fn verify_one(
    target: &InstallTarget,
    opts: &PrecheckOptions,
    now: &chrono::DateTime<chrono::Utc>,
    threshold: chrono::Duration,
) -> TargetOutcome {
    use crate::verify_deps::registry;

    let resolved = match &target.kind {
        TargetKind::Unverifiable { reason } => {
            return TargetOutcome::Skipped {
                target: target.clone(),
                reason: reason.clone(),
            };
        }
        TargetKind::Npm(spec) => {
            registry::npm_resolve(&target.name, spec, opts.npm_registry.as_deref())
        }
        TargetKind::Pypi(spec) => {
            registry::pypi_resolve(&target.name, spec, opts.pypi_registry.as_deref())
        }
    };

    match resolved {
        Ok(resolved) => {
            let age_chrono = now.signed_duration_since(resolved.published_at);
            let age = age_chrono
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(0));
            TargetOutcome::Resolved {
                target: target.clone(),
                resolved,
                age,
                recent: age_chrono < threshold,
            }
        }
        Err(e) => TargetOutcome::Error {
            target: target.clone(),
            error: e,
        },
    }
}

fn exec_install_with_args(manager: PackageManager, subcommand: &str, rest: &[String]) -> i32 {
    let mut full = Vec::with_capacity(rest.len() + 1);
    full.push(subcommand.to_string());
    full.extend(rest.iter().cloned());
    exec_command(manager.binary_name(), &full)
}

fn exec_command(binary: &str, args: &[String]) -> i32 {
    // Resolve the binary on PATH. On Windows this finds `.cmd` shims.
    let resolved = match which::which(binary) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "could not find '{}' on PATH ({}). Make sure the package manager is installed.",
                binary, e
            );
            return 127;
        }
    };

    let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();

    match Command::new(&resolved).args(&os_args).status() {
        Ok(status) => status.code().unwrap_or_else(|| {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    return 128 + sig;
                }
            }
            1
        }),
        Err(e) => {
            eprintln!("failed to exec {}: {}", binary, e);
            1
        }
    }
}

fn print_text(report: &PrecheckReport) {
    println!(
        "Pre-checking `{} {} {}` (threshold {})",
        report.manager.binary_name(),
        report.subcommand,
        report.original_args.join(" "),
        verify_deps::format_duration(report.threshold)
    );
    println!(
        "  {} ok, {} recent, {} skipped, {} errors",
        report.ok_count(),
        report.recent_count(),
        report.skipped_count(),
        report.error_count(),
    );

    for o in &report.outcomes {
        match o {
            TargetOutcome::Resolved {
                target,
                resolved,
                age,
                recent,
            } => {
                if *recent {
                    println!(
                        "  ⚠ {} → {}@{}  published {} ago at {} (within threshold)",
                        target.display,
                        resolved.name,
                        resolved.version,
                        verify_deps::format_duration(*age),
                        resolved.published_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    );
                } else {
                    println!(
                        "  ✓ {} → {}@{}  published {} ago",
                        target.display,
                        resolved.name,
                        resolved.version,
                        verify_deps::format_duration(*age),
                    );
                }
            }
            TargetOutcome::Skipped { target, reason } => {
                println!("  ? {}: {}", target.display, reason);
            }
            TargetOutcome::Error { target, error } => {
                println!("  ✗ {}: {}", target.display, error);
            }
        }
    }
}

fn print_json(report: &PrecheckReport) {
    use serde_json::json;
    let outcomes: Vec<_> = report
        .outcomes
        .iter()
        .map(|o| match o {
            TargetOutcome::Resolved {
                target,
                resolved,
                age,
                recent,
            } => json!({
                "status": if *recent { "recent" } else { "ok" },
                "spec": target.display,
                "name": resolved.name,
                "resolved_version": resolved.version,
                "published_at": resolved.published_at.to_rfc3339(),
                "age_seconds": age.as_secs(),
            }),
            TargetOutcome::Skipped { target, reason } => json!({
                "status": "skipped",
                "spec": target.display,
                "name": target.name,
                "reason": reason,
            }),
            TargetOutcome::Error { target, error } => json!({
                "status": "error",
                "spec": target.display,
                "name": target.name,
                "error": error,
            }),
        })
        .collect();

    let body = json!({
        "manager": report.manager.binary_name(),
        "subcommand": report.subcommand,
        "args": report.original_args,
        "threshold_seconds": report.threshold.as_secs(),
        "summary": {
            "ok": report.ok_count(),
            "recent": report.recent_count(),
            "skipped": report.skipped_count(),
            "errors": report.error_count(),
        },
        "results": outcomes,
    });

    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_subcommand_recognition() {
        assert!(PackageManager::Npm.is_install_subcommand("install"));
        assert!(PackageManager::Npm.is_install_subcommand("i"));
        assert!(PackageManager::Npm.is_install_subcommand("add"));
        assert!(!PackageManager::Npm.is_install_subcommand("update"));

        assert!(PackageManager::Yarn.is_install_subcommand("add"));
        assert!(PackageManager::Yarn.is_install_subcommand("install"));

        assert!(PackageManager::Pnpm.is_install_subcommand("add"));
        assert!(PackageManager::Pnpm.is_install_subcommand("install"));
        assert!(PackageManager::Pnpm.is_install_subcommand("i"));

        assert!(PackageManager::Pip.is_install_subcommand("install"));
        assert!(!PackageManager::Pip.is_install_subcommand("freeze"));
    }

    fn stub_opts(pypi_registry: String, no_fail: bool) -> PrecheckOptions {
        PrecheckOptions {
            threshold: Duration::from_secs(2 * 86400),
            no_fail,
            json: false,
            npm_registry: None,
            pypi_registry: Some(pypi_registry),
        }
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
        let opts = stub_opts("http://127.0.0.1:9".to_string(), false);
        let (code, exec_ran) = gate_pip_install(&["git+https://github.com/psf/requests.git"], opts);
        assert_eq!(code, 42);
        assert!(exec_ran);
    }

    #[test]
    fn bare_install_passes_through_without_verification() {
        // Bare `pip install` (no targets) → straight exec, no registry hit.
        let opts = stub_opts("http://127.0.0.1:9".to_string(), false);
        let (code, exec_ran) = gate_pip_install(&[], opts);
        assert_eq!(code, 42);
        assert!(exec_ran);
    }

    #[test]
    fn requirements_files_note_then_exec() {
        // `-r reqs.txt` alone → printed note, no verification, exec runs.
        let opts = stub_opts("http://127.0.0.1:9".to_string(), false);
        let (code, exec_ran) = gate_pip_install(&["-r", "reqs.txt"], opts);
        assert_eq!(code, 42);
        assert!(exec_ran);
    }
}
