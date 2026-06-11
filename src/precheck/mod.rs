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

mod detect;
mod exec;
mod parse;
mod render;
mod tree;
mod uv;
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

    /// vuln-api ecosystem for this manager's registry.
    pub fn ecosystem(self) -> crate::vuln_api::Ecosystem {
        match self {
            PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm => {
                crate::vuln_api::Ecosystem::Npm
            }
            PackageManager::Pip | PackageManager::Uv => crate::vuln_api::Ecosystem::Pypi,
        }
    }

    /// Canonical package name for dedup/matching across spec spellings —
    /// the ecosystem's rule (`vuln_api::Ecosystem::normalize_name`).
    ///
    /// Invariant: request-time normalization is owned by the vuln-api
    /// client (`vuln_api::check_package_version`); comparison sites
    /// (`verdict::apply_verdicts` / tree dedup) normalize here. Parsers
    /// and resolvers carry raw names.
    pub fn normalize_name(self, name: &str) -> String {
        self.ecosystem().normalize_name(name)
    }
}

/// Auth and failure policy for the vuln-api verdict pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictMode {
    /// No auth header; vuln-api lookup errors warn and fail open.
    Public,
    /// Auth header sent; vuln-api lookup errors fail closed.
    Authenticated { token: String },
}

impl VerdictMode {
    fn auth_token(&self) -> Option<&str> {
        match self {
            VerdictMode::Public => None,
            VerdictMode::Authenticated { token } => Some(token.as_str()),
        }
    }
}

/// Connection details for the vuln-api verdict pass.
/// Public mode is still a verdict pass: known vulnerable/malicious verdicts
/// block, while lookup errors warn and continue.
#[derive(Debug, Clone)]
pub struct VerdictConfig {
    pub base_url: String,
    pub mode: VerdictMode,
    /// Print the tokenless public-mode hint after a check is attempted.
    pub public_login_hint: bool,
}

/// Threat verdict for one resolved target.
#[derive(Debug, Clone)]
pub enum VerdictStatus {
    /// vuln-api answered: no known advisories for this exact version.
    Clean,
    /// vuln-api answered: known vulnerable or malicious — blocks.
    Vulnerable(Vec<crate::vuln_api::VulnMatch>),
    /// The verdict could not be obtained (network/5xx/auth/integrity).
    /// Blocks only in authenticated mode.
    Unverifiable(String),
    /// Verdict never attempted. The constant reason (`NO_VERDICT_REASON`)
    /// is attached at render time.
    NotChecked,
}

impl VerdictStatus {
    /// Whether this verdict blocks the install: vulnerable always;
    /// unverifiable only when the mode fails closed (authenticated).
    /// The single definition of "blocking finding", shared by
    /// `verdict::block_reason` and the refusal-blame test.
    fn blocks(&self, fail_closed: bool) -> bool {
        match self {
            VerdictStatus::Vulnerable(_) => true,
            VerdictStatus::Unverifiable(_) => fail_closed,
            VerdictStatus::Clean | VerdictStatus::NotChecked => false,
        }
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
    pub json: bool,
    /// `Some` ⇒ run the vuln-api verdict pass against this endpoint.
    /// `None` is retained for tests and direct library callers that want
    /// recency-only behavior.
    pub verdict: Option<VerdictConfig>,
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

/// Why a tree-pass finding is in the would-install set. Drives the
/// provenance label so a package the user asked for (or already depends on)
/// is never mislabeled "(transitive)".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeOrigin {
    /// Pulled in as a dependency of something else.
    Transitive,
    /// Explicitly requested (pip report `"requested"` — CLI arg or
    /// requirements file; leftovers here come from `-r` files since named
    /// CLI targets match a named outcome instead).
    Requested,
    /// Already a direct dependency in the project's `package.json`.
    PreExisting,
    /// Pinned by the project's lockfile (`uv sync` from `uv.lock`).
    Locked,
}

impl TreeOrigin {
    fn label(self) -> &'static str {
        match self {
            TreeOrigin::Transitive => "(transitive)",
            TreeOrigin::Requested => "(from requirements)",
            TreeOrigin::PreExisting => "(already in package.json)",
            TreeOrigin::Locked => "(locked)",
        }
    }

    fn json_name(self) -> &'static str {
        match self {
            TreeOrigin::Transitive => "transitive",
            TreeOrigin::Requested => "requested",
            TreeOrigin::PreExisting => "pre-existing",
            TreeOrigin::Locked => "locked",
        }
    }
}

/// Verdict for one package the tree pass resolved beyond the named targets.
#[derive(Debug)]
pub struct TreeOutcome {
    pub name: String,
    pub version: String,
    pub origin: TreeOrigin,
    pub verdict: VerdictStatus,
}

/// Result of the tree pass. `PrecheckReport.tree` is `None` when the pass
/// never ran (named-only managers, or verdicts disabled).
#[derive(Debug)]
pub enum TreeReport {
    /// The full would-install set was resolved and verdicted.
    Full {
        /// Distinct packages the dry-run resolved (named + transitive).
        resolved_count: usize,
        /// Verdicts for resolved packages beyond the named targets.
        transitive: Vec<TreeOutcome>,
    },
    /// Resolution unavailable or failed — only named targets were verified.
    NamedOnly { reason: String },
}

#[derive(Debug)]
pub struct PrecheckReport {
    pub manager: PackageManager,
    pub subcommand: String,
    pub original_args: Vec<String>,
    pub outcomes: Vec<TargetOutcome>,
    pub threshold: Duration,
    /// `None` ⇒ no tree pass ran.
    pub tree: Option<TreeReport>,
    /// True when the command named nothing — no CLI targets and no
    /// requirements files — so everything the tree pass resolved predates
    /// this command (bare `npm install`). Distinct from
    /// `outcomes.is_empty()`: a requirements-only install also has no named
    /// outcomes, but its resolved set IS added by the command.
    pub bare_install: bool,
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
    /// Every verdict in the report: named (resolved) outcomes, then
    /// transitive tree findings.
    fn verdicts(&self) -> impl Iterator<Item = &VerdictStatus> {
        self.named_verdicts().chain(self.tree_verdicts())
    }
    /// Verdicts on the named targets this command adds.
    fn named_verdicts(&self) -> impl Iterator<Item = &VerdictStatus> {
        self.outcomes.iter().filter_map(|o| match o {
            TargetOutcome::Resolved { verdict, .. } => Some(verdict),
            _ => None,
        })
    }
    /// Verdicts beyond the named targets (the resolved tree).
    fn tree_verdicts(&self) -> impl Iterator<Item = &VerdictStatus> {
        match &self.tree {
            Some(TreeReport::Full { transitive, .. }) => transitive.as_slice(),
            Some(TreeReport::NamedOnly { .. }) | None => &[],
        }
        .iter()
        .map(|o| &o.verdict)
    }
    pub fn vulnerable_count(&self) -> usize {
        count_vulnerable(self.verdicts())
    }
    pub fn unverifiable_count(&self) -> usize {
        count_unverifiable(self.verdicts())
    }
    /// Vulnerable findings beyond the named targets (the resolved tree).
    pub fn tree_vulnerable_count(&self) -> usize {
        count_vulnerable(self.tree_verdicts())
    }
    /// Unverifiable findings beyond the named targets (the resolved tree).
    pub fn tree_unverifiable_count(&self) -> usize {
        count_unverifiable(self.tree_verdicts())
    }
    pub fn skipped_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Skipped { .. }))
    }
    pub fn error_count(&self) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Error { .. }))
    }
}

fn count_vulnerable<'a>(verdicts: impl Iterator<Item = &'a VerdictStatus>) -> usize {
    verdicts
        .filter(|v| matches!(v, VerdictStatus::Vulnerable(_)))
        .count()
}

fn count_unverifiable<'a>(verdicts: impl Iterator<Item = &'a VerdictStatus>) -> usize {
    verdicts
        .filter(|v| matches!(v, VerdictStatus::Unverifiable(_)))
        .count()
}

/// Canonical entry for ecosystem commands (`corgea npm install …`).
///
/// `cmd` is everything after the ecosystem name, e.g.
/// `["install", "axios@^1.0.0", "--save-dev"]`. An empty `cmd` execs the
/// package manager with no arguments.
pub fn run_install(manager: PackageManager, cmd: &[String], opts: PrecheckOptions) -> i32 {
    if manager == PackageManager::Uv {
        return uv::run_uv(cmd, opts);
    }

    if cmd.is_empty() {
        return exec::exec_command(manager.binary_name(), &[]);
    }

    let subcommand = &cmd[0];
    let rest = &cmd[1..];

    if manager == PackageManager::Pip && subcommand == "add" {
        eprintln!("{}", unsupported_pip_add_message(rest));
        return 1;
    }

    if !manager.is_install_subcommand(subcommand) {
        return exec::exec_install_with_args(manager, subcommand, rest);
    }

    let parsed = match parse::parse_install_args(manager, rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to parse install args: {}", e);
            return 2;
        }
    };

    if let Some(message) = detect::wrong_package_manager_message(manager, rest, &parsed) {
        eprintln!("{message}");
        return 1;
    }

    if let Some(message) = detect::externally_managed_pip_message(manager, rest, &parsed) {
        eprintln!("{message}");
        return 1;
    }

    run_parsed_install(
        manager,
        subcommand,
        rest,
        parsed,
        || exec::exec_install_with_args(manager, subcommand, rest),
        opts,
    )
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

/// Shared tail of every gated path: render the report, refuse (exit 1) when
/// the block predicate fires, otherwise run the install.
fn report_and_exec(
    report: &PrecheckReport,
    opts: &PrecheckOptions,
    exec: impl FnOnce() -> i32,
) -> i32 {
    if opts.json {
        render::print_json(report, opts);
    } else {
        render::print_text(report);
    }
    render::warn_public_lookup_failures(report, opts);
    if let Some(reason) = verdict::block_reason(report, opts) {
        if !opts.json {
            render::print_refusal(reason);
        }
        return 1;
    }
    exec()
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
    // With a verdict config, the tree pass resolves the full would-install
    // set; `tree::covers_input` owns what each manager's resolver can chew on.
    let tree_eligible = opts.verdict.is_some() && tree::covers_input(manager, &parsed);
    let bare_install = parsed.targets.is_empty() && parsed.requirements_files.is_empty();

    if parsed.targets.is_empty() && !tree_eligible {
        // Only a truly bare install gets the bare note. A `-r requirements.txt`
        // install is covered by `requirements_note`.
        if bare_install {
            render::bare_install_note(manager, subcommand_label);
        }
        render::requirements_note(&parsed);
        return exec();
    }

    // The named-target registry lookups and the tree dry-run are independent
    // network/subprocess work — overlap them; verdicts need both.
    let now = Utc::now();
    let (mut outcomes, tree_resolution) = std::thread::scope(|s| {
        let tree = tree_eligible.then(|| s.spawn(|| tree::resolve_tree(manager, rest, &parsed)));
        let outcomes = verdict::verify_all(&parsed.targets, &opts, &now);
        (
            outcomes,
            tree.map(|handle| handle.join().expect("tree resolution thread panicked")),
        )
    });

    let tree = if let Some(resolution) = tree_resolution {
        Some(run_tree_pass(manager, resolution, &mut outcomes, &opts))
    } else {
        run_verdict_pass(manager, &mut outcomes, &opts);
        None
    };

    // The mandatory loud warning when the tree pass fell back to named-only.
    if let Some(TreeReport::NamedOnly { reason }) = &tree {
        eprintln!(
            "warning: transitive dependencies not checked ({reason}); only named packages were verified."
        );
    }
    // The requirements note only matters when the tree pass did *not* cover
    // those files (fallback to named-only, or verdicts disabled).
    if !matches!(&tree, Some(TreeReport::Full { .. })) {
        render::requirements_note(&parsed);
    }
    if opts
        .verdict
        .as_ref()
        .is_some_and(|cfg| matches!(cfg.mode, VerdictMode::Public) && cfg.public_login_hint)
    {
        eprintln!(
            "warning: using public CVE checks; login enables authenticated enforcement and private Corgea intelligence."
        );
    }

    let report = PrecheckReport {
        manager,
        subcommand: subcommand_label.to_string(),
        original_args: rest.to_vec(),
        outcomes,
        threshold: opts.threshold,
        tree,
        bare_install,
    };

    report_and_exec(&report, &opts, exec)
}

/// Verdict the resolved would-install set (`tree::resolve_tree`'s result).
/// On any resolution failure, fall back to the named-only verdict pass; the
/// caller renders the loud warning from the returned `NamedOnly` reason.
/// Only called when `opts.verdict.is_some()`.
fn run_tree_pass(
    manager: PackageManager,
    resolution: Result<Vec<tree::TreePackage>, String>,
    outcomes: &mut [TargetOutcome],
    opts: &PrecheckOptions,
) -> TreeReport {
    let set = match resolution {
        Ok(set) => set,
        Err(reason) => {
            run_verdict_pass(manager, outcomes, opts);
            return TreeReport::NamedOnly { reason };
        }
    };

    // Dedup the dry-run set (npm lockfiles repeat the same name@version at
    // multiple nested paths), then union in the named-resolved targets — a
    // named target already installed is absent from the dry-run delta but
    // must still be verdicted.
    let norm = |n: &str| manager.normalize_name(n);
    let mut seen = std::collections::HashSet::new();
    let mut jobs: Vec<tree::TreePackage> = Vec::with_capacity(set.len());
    for p in set {
        if seen.insert((norm(&p.name), p.version.clone())) {
            jobs.push(p);
        }
    }
    let resolved_count = jobs.len();
    for o in outcomes.iter() {
        if let TargetOutcome::Resolved { resolved, .. } = o {
            if seen.insert((norm(&resolved.name), resolved.version.clone())) {
                jobs.push(tree::TreePackage {
                    name: resolved.name.clone(),
                    version: resolved.version.clone(),
                    requested: true,
                });
            }
        }
    }

    // npm leftovers that are direct deps of the project manifest are
    // pre-existing, not transitive. pip carries `requested` instead.
    let direct_deps = if manager == PackageManager::Npm {
        tree::project_direct_deps()
    } else {
        Default::default()
    };

    let cfg = opts
        .verdict
        .as_ref()
        .expect("tree pass requires verdict config");
    let results = verdict::verdict_pool(jobs, cfg, manager);
    let transitive = verdict::apply_verdicts(manager, results, outcomes, &direct_deps);
    TreeReport::Full {
        resolved_count,
        transitive,
    }
}

/// Vuln-api verdict pass over resolved targets, run through the bounded
/// worker pool. No-op without a `VerdictConfig` (direct recency-only callers).
/// Any client/call failure becomes `Unverifiable`; authenticated mode blocks
/// on that and public mode warns but continues.
fn run_verdict_pass(
    manager: PackageManager,
    outcomes: &mut [TargetOutcome],
    opts: &PrecheckOptions,
) {
    let Some(cfg) = &opts.verdict else { return };

    // One job per resolved target, in outcome order; the pool preserves
    // order, so verdicts zip straight back onto the resolved outcomes.
    let jobs: Vec<tree::TreePackage> = outcomes
        .iter()
        .filter_map(|o| match o {
            TargetOutcome::Resolved { resolved, .. } => Some(tree::TreePackage {
                name: resolved.name.clone(),
                version: resolved.version.clone(),
                requested: true,
            }),
            _ => None,
        })
        .collect();

    let mut results = verdict::verdict_pool(jobs, cfg, manager).into_iter();
    for o in outcomes.iter_mut() {
        if let TargetOutcome::Resolved { verdict, .. } = o {
            *verdict = results.next().expect("one verdict per resolved outcome").1;
        }
    }
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

        assert!(PackageManager::Yarn.is_install_subcommand("add"));
        assert!(PackageManager::Yarn.is_install_subcommand("install"));

        assert!(PackageManager::Pnpm.is_install_subcommand("add"));
        assert!(PackageManager::Pnpm.is_install_subcommand("install"));
        assert!(PackageManager::Pnpm.is_install_subcommand("i"));

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
        assert_eq!(PackageManager::Uv.ecosystem(), Ecosystem::Pypi);
        assert_eq!(PackageManager::Npm.ecosystem(), Ecosystem::Npm);
        assert_eq!(PackageManager::Yarn.ecosystem(), Ecosystem::Npm);
        assert_eq!(PackageManager::Pnpm.ecosystem(), Ecosystem::Npm);
    }

    #[test]
    fn normalize_name_per_manager() {
        // pypi: PEP 503 — lowercase, separator runs collapse to one `-`.
        assert_eq!(
            PackageManager::Pip.normalize_name("Flask_Cors"),
            "flask-cors"
        );
        assert_eq!(
            PackageManager::Uv.normalize_name("zope.interface"),
            "zope-interface"
        );
        assert_eq!(PackageManager::Pip.normalize_name("a__b"), "a-b");
        // npm names are case-sensitive and pass through verbatim.
        assert_eq!(PackageManager::Npm.normalize_name("Left_Pad"), "Left_Pad");
    }
}
