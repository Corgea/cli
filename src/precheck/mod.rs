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
//! warning (the install runs anyway), or `--check-only` to skip the
//! install regardless of verification result.

pub mod parse;

use std::ffi::OsString;
use std::process::Command;
use std::time::Duration;

use chrono::Utc;

use crate::utils::terminal::{set_text_color, TerminalColor};
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

    fn lockfile_mode(self) -> LockfileMode {
        match self {
            PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm => LockfileMode::Npm,
            PackageManager::Pip | PackageManager::Uv => LockfileMode::Python,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockfileMode {
    Npm,
    Python,
}

#[derive(Debug, Clone)]
pub struct PrecheckOptions {
    pub threshold: Duration,
    /// If true, demote a recent finding from "block" to "warn-and-run".
    pub no_fail: bool,
    /// If true, never exec the underlying install command.
    pub check_only: bool,
    /// If true, also fail on unpinned-style warnings (URL specs,
    /// unparseable specs, missing `requirements.txt` reference).
    pub fail_unpinned: bool,
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
    /// Resolved cleanly, version is older than the threshold.
    Ok {
        target: InstallTarget,
        resolved: crate::verify_deps::registry::ResolvedPackage,
        age: Duration,
    },
    /// Resolved cleanly but version was published within the threshold.
    Recent {
        target: InstallTarget,
        resolved: crate::verify_deps::registry::ResolvedPackage,
        age: Duration,
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
    pub fn recent_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, TargetOutcome::Recent { .. }))
            .count()
    }
    pub fn error_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, TargetOutcome::Error { .. }))
            .count()
    }
    pub fn skipped_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, TargetOutcome::Skipped { .. }))
            .count()
    }
    pub fn ok_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, TargetOutcome::Ok { .. }))
            .count()
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
        return exec_install(manager, &[], opts.check_only);
    }

    let subcommand = &cmd[0];
    let rest = &cmd[1..];

    if !manager.is_install_subcommand(subcommand) {
        return exec_install_with_args(manager, subcommand, rest, opts.check_only);
    }

    let parsed = match parse::parse_install_args(manager, rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to parse install args: {}", e);
            return 2;
        }
    };

    let check_only = opts.check_only;
    run_parsed_install(
        manager,
        subcommand,
        rest,
        parsed,
        || exec_install_with_args(manager, subcommand, rest, check_only),
        opts,
        manager.lockfile_mode(),
    )
}

fn run_uv(cmd: &[String], opts: PrecheckOptions) -> i32 {
    if cmd.is_empty() {
        return exec_uv(cmd, opts.check_only);
    }

    let check_only = opts.check_only;
    let exec = || exec_uv(cmd, check_only);

    match parse::classify_uv_command(cmd) {
        parse::UvCommand::Passthrough => exec_uv(cmd, opts.check_only),
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
                LockfileMode::Python,
            )
        }
        parse::UvCommand::Add { add_args } => run_parsed_install(
            PackageManager::Uv,
            "add",
            add_args,
            parse::parse_pypi_positionals_args(add_args),
            exec,
            opts,
            LockfileMode::Python,
        ),
        parse::UvCommand::Sync { sync_args } => run_parsed_install(
            PackageManager::Uv,
            "sync",
            sync_args,
            parse::parse_pypi_positionals_args(sync_args),
            exec,
            opts,
            LockfileMode::Python,
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
    lockfile_mode: LockfileMode,
) -> i32 {
    if !parsed.requirements_files.is_empty() {
        let code = verify_lockfile_or_requirements(&opts, &parsed.requirements_files);
        if code != 0 && !opts.no_fail {
            return code;
        }
    }

    if parsed.targets.is_empty() && !parsed.bare_install {
        return exec();
    }

    if parsed.bare_install {
        let exit_from_lockfile = verify_project_lockfile(&opts, lockfile_mode);
        if exit_from_lockfile != 0 && !opts.no_fail {
            return exit_from_lockfile;
        }
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
            eprintln!(
                "{}",
                set_text_color(
                    "Refusing to run install. Pass --no-fail to proceed anyway.",
                    TerminalColor::Red,
                )
            );
        }
        return 1;
    }

    exec()
}

fn should_block_install(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
    if opts.no_fail {
        return false;
    }
    report.recent_count() > 0 || (report.error_count() > 0 && opts.fail_unpinned)
}

fn exec_uv(args: &[String], check_only: bool) -> i32 {
    if check_only {
        return 0;
    }
    exec_command("uv", args)
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
            if age_chrono < threshold {
                TargetOutcome::Recent {
                    target: target.clone(),
                    resolved,
                    age,
                }
            } else {
                TargetOutcome::Ok {
                    target: target.clone(),
                    resolved,
                    age,
                }
            }
        }
        Err(e) => TargetOutcome::Error {
            target: target.clone(),
            error: e,
        },
    }
}

fn verify_project_lockfile(opts: &PrecheckOptions, mode: LockfileMode) -> i32 {
    let ecosystem = match mode {
        LockfileMode::Npm => verify_deps::Ecosystem::Npm,
        LockfileMode::Python => verify_deps::Ecosystem::Python,
    };
    delegate_to_verify_deps(install_wrap_verify_opts(
        opts,
        ecosystem,
        std::path::PathBuf::from("."),
    ))
}

fn install_wrap_verify_opts(
    opts: &PrecheckOptions,
    ecosystem: verify_deps::Ecosystem,
    path: std::path::PathBuf,
) -> verify_deps::VerifyOptions {
    verify_deps::VerifyOptions::for_install_wrap(
        ecosystem,
        path,
        opts.threshold,
        !opts.no_fail,
        opts.fail_unpinned,
        opts.json,
        opts.npm_registry.clone(),
        opts.pypi_registry.clone(),
    )
}

fn verify_lockfile_or_requirements(
    opts: &PrecheckOptions,
    requirements_files: &[std::path::PathBuf],
) -> i32 {
    if requirements_files.is_empty() {
        return verify_project_lockfile(opts, LockfileMode::Python);
    }

    let mut overall: i32 = 0;
    for req in requirements_files {
        let parent = req
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        // `deps` only discovers a file named `requirements.txt`; other
        // `-r` paths are parsed and checked directly.
        let file_name = req
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if file_name != "requirements.txt" {
            // Parse the file ourselves and run the registry checks.
            let code = verify_arbitrary_requirements(req, opts);
            if code != 0 {
                overall = code;
            }
            continue;
        }
        let code = delegate_to_verify_deps(install_wrap_verify_opts(
            opts,
            verify_deps::Ecosystem::Python,
            parent,
        ));
        if code != 0 {
            overall = code;
        }
    }
    overall
}

/// Read a requirements file at an arbitrary path, parse it, and run
/// the same registry verification we'd run for a project's
/// `requirements.txt`. Used when the user passes
/// `pip install -r dev-reqs.txt` (a non-default name).
fn verify_arbitrary_requirements(req_path: &std::path::Path, opts: &PrecheckOptions) -> i32 {
    let content = match std::fs::read_to_string(req_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("deps: failed to read {}: {}", req_path.display(), e);
            return 2;
        }
    };
    let (deps, unpinned) = crate::verify_deps::python::parse_requirements_with_warnings(&content);

    if deps.is_empty() && unpinned.is_empty() {
        return 0;
    }

    let now = chrono::Utc::now();
    let threshold = match chrono::Duration::from_std(opts.threshold) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("invalid threshold: {}", e);
            return 2;
        }
    };

    let mut recent_count: usize = 0;
    let mut error_count: usize = 0;
    println!(
        "Pre-checking {} (threshold {})",
        req_path.display(),
        verify_deps::format_duration(opts.threshold)
    );
    for dep in &deps {
        match crate::verify_deps::registry::pypi_publish_time(
            &dep.name,
            &dep.version,
            opts.pypi_registry.as_deref(),
        ) {
            Ok(published_at) => {
                let age_chrono = now.signed_duration_since(published_at);
                let age = age_chrono
                    .to_std()
                    .unwrap_or_else(|_| Duration::from_secs(0));
                if age_chrono < threshold {
                    println!(
                        "  {} {}@{}  published {} ago at {} (within threshold)",
                        set_text_color("⚠", TerminalColor::Yellow),
                        dep.name,
                        dep.version,
                        set_text_color(&verify_deps::format_duration(age), TerminalColor::Yellow,),
                        published_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    );
                    recent_count += 1;
                } else {
                    println!(
                        "  {} {}@{}  published {} ago",
                        set_text_color("✓", TerminalColor::Green),
                        dep.name,
                        dep.version,
                        verify_deps::format_duration(age),
                    );
                }
            }
            Err(e) => {
                println!(
                    "  {} {}@{}: {}",
                    set_text_color("✗", TerminalColor::Red),
                    dep.name,
                    dep.version,
                    e
                );
                error_count += 1;
            }
        }
    }
    if !unpinned.is_empty() {
        println!(
            "{}",
            set_text_color(
                "Unpinned lines (cannot be verified):",
                TerminalColor::Yellow,
            )
        );
        for line in &unpinned {
            println!("  {} {}", set_text_color("?", TerminalColor::Yellow), line);
        }
    }
    if recent_count > 0 && !opts.no_fail {
        return 1;
    }
    if !unpinned.is_empty() && opts.fail_unpinned {
        return 1;
    }
    if error_count > 0 && opts.fail_unpinned {
        return 1;
    }
    0
}

fn delegate_to_verify_deps(opts: verify_deps::VerifyOptions) -> i32 {
    match verify_deps::run(&opts) {
        Ok(report) => {
            if opts.json {
                verify_deps::report::print_json(&report);
            } else {
                verify_deps::report::print_text(&report);
            }
            let recent = !report.recent().is_empty();
            let unpinned = report.has_unpinned();
            if recent && opts.fail {
                return 1;
            }
            if unpinned && opts.fail_unpinned {
                return 1;
            }
            0
        }
        Err(e) => {
            eprintln!("deps failed: {}", e);
            2
        }
    }
}

fn exec_install(manager: PackageManager, args: &[String], check_only: bool) -> i32 {
    if check_only {
        return 0;
    }
    exec_command(manager.binary_name(), args)
}

fn exec_install_with_args(
    manager: PackageManager,
    subcommand: &str,
    rest: &[String],
    check_only: bool,
) -> i32 {
    if check_only {
        return 0;
    }
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
    let label = report.manager.binary_name();
    let display: Vec<&str> = report.original_args.iter().map(String::as_str).collect();
    println!(
        "Pre-checking `{} {} {}` (threshold {})",
        label,
        report.subcommand,
        display.join(" "),
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
            TargetOutcome::Ok {
                target,
                resolved,
                age,
            } => {
                println!(
                    "  {} {} → {}@{}  published {} ago",
                    set_text_color("✓", TerminalColor::Green),
                    target.display,
                    resolved.name,
                    resolved.version,
                    verify_deps::format_duration(*age),
                );
            }
            TargetOutcome::Recent {
                target,
                resolved,
                age,
            } => {
                println!(
                    "  {} {} → {}@{}  published {} ago at {} (within threshold)",
                    set_text_color("⚠", TerminalColor::Yellow),
                    target.display,
                    resolved.name,
                    resolved.version,
                    set_text_color(&verify_deps::format_duration(*age), TerminalColor::Yellow),
                    resolved.published_at.format("%Y-%m-%d %H:%M:%S UTC"),
                );
            }
            TargetOutcome::Skipped { target, reason } => {
                println!(
                    "  {} {}: {}",
                    set_text_color("?", TerminalColor::Yellow),
                    target.display,
                    reason,
                );
            }
            TargetOutcome::Error { target, error } => {
                println!(
                    "  {} {}: {}",
                    set_text_color("✗", TerminalColor::Red),
                    target.display,
                    error,
                );
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
            TargetOutcome::Ok {
                target,
                resolved,
                age,
            } => json!({
                "status": "ok",
                "spec": target.display,
                "name": resolved.name,
                "resolved_version": resolved.version,
                "published_at": resolved.published_at.to_rfc3339(),
                "age_seconds": age.as_secs(),
            }),
            TargetOutcome::Recent {
                target,
                resolved,
                age,
            } => json!({
                "status": "recent",
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

    #[test]
    fn run_install_passthrough_non_install_subcommand() {
        let opts = PrecheckOptions {
            threshold: Duration::from_secs(86400),
            no_fail: true,
            check_only: true,
            fail_unpinned: false,
            json: false,
            npm_registry: None,
            pypi_registry: None,
        };
        // `view` is not an install subcommand — should return 0 in check_only mode
        // without needing network or npm on PATH for resolution.
        let code = run_install(
            PackageManager::Npm,
            &[
                "view".to_string(),
                "lodash".to_string(),
                "version".to_string(),
            ],
            opts,
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn run_uv_passthrough_check_only() {
        let opts = PrecheckOptions {
            threshold: Duration::from_secs(86400),
            no_fail: true,
            check_only: true,
            fail_unpinned: false,
            json: false,
            npm_registry: None,
            pypi_registry: None,
        };
        assert_eq!(
            run_install(
                PackageManager::Uv,
                &["run".to_string(), "pytest".to_string()],
                opts
            ),
            0
        );
    }

    #[test]
    fn run_install_empty_cmd_check_only() {
        let opts = PrecheckOptions {
            threshold: Duration::from_secs(86400),
            no_fail: false,
            check_only: true,
            fail_unpinned: false,
            json: false,
            npm_registry: None,
            pypi_registry: None,
        };
        assert_eq!(run_install(PackageManager::Npm, &[], opts), 0);
    }
}
