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
pub mod tree;

use std::collections::HashMap;
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

    /// vuln-api ecosystem path segment for this manager's registry.
    pub fn ecosystem(self) -> &'static str {
        match self {
            PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm => "npm",
            PackageManager::Pip | PackageManager::Uv => "pypi",
        }
    }

    /// Canonical package name for dedup/matching across spec spellings:
    /// PEP 503 for pypi (shared with `deps`), verbatim for npm.
    pub fn normalize_name(self, name: &str) -> String {
        match self {
            PackageManager::Pip | PackageManager::Uv => {
                crate::deps::ecosystems::pypi::normalize_pypi_name(name)
            }
            PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm => name.to_string(),
        }
    }
}

/// Connection details for the vuln-api verdict pass.
/// `None` in `PrecheckOptions.verdict` ⇒ tokenless mode: verdicts are
/// skipped and the gate degrades to recency-only cover.
#[derive(Debug, Clone)]
pub struct VerdictConfig {
    pub base_url: String,
    pub token: String,
}

/// Threat verdict for one resolved target.
#[derive(Debug, Clone)]
pub enum VerdictStatus {
    /// vuln-api answered: no known advisories for this exact version.
    Clean,
    /// vuln-api answered: known vulnerable or malicious — blocks.
    Vulnerable(Vec<crate::vuln_api::VulnMatch>),
    /// The verdict could not be obtained (network/5xx/auth/integrity).
    /// Blocks fail-closed.
    Unverifiable(String),
    /// Verdict never attempted (no token). Recency-only cover; the
    /// constant reason (`NO_TOKEN_REASON`) is attached at render time.
    NotChecked,
}

/// Result of re-verdicting a proposed `→ safe version` steer against
/// vuln-api before it prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteerCheck {
    /// vuln-api confirmed the proposed version is clean — print the steer.
    Verified,
    /// vuln-api flagged the proposed version too — print the rejection note.
    Rejected,
    /// The re-check failed (network/5xx/auth) — suppress the steer quietly.
    /// Never feeds counts or the block decision.
    Unverified,
}

/// Reason recorded on resolved targets when no token is configured.
const NO_TOKEN_REASON: &str = "no Corgea token; vulnerability verdict skipped";

#[derive(Debug, Clone)]
pub struct PrecheckOptions {
    pub threshold: Duration,
    /// If true, demote a recent finding from "block" to "warn-and-run".
    pub no_fail: bool,
    /// If true, never block: print findings (recent, vulnerable,
    /// unverifiable) and run the install anyway.
    pub force: bool,
    pub json: bool,
    /// `Some` ⇒ run the vuln-api verdict pass against this endpoint;
    /// `None` ⇒ tokenless recency-only mode.
    pub verdict: Option<VerdictConfig>,
    /// Optional registry overrides, used by tests.
    pub npm_registry: Option<String>,
    pub pypi_registry: Option<String>,
    /// Run the warn-only `npm audit` second opinion during the npm tree
    /// pass. Cleared by `CORGEA_NO_NPM_AUDIT` (read in `main`, like the
    /// registry overrides).
    pub npm_audit: bool,
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
}

impl TreeOrigin {
    fn label(self) -> &'static str {
        match self {
            TreeOrigin::Transitive => "(transitive)",
            TreeOrigin::Requested => "(from requirements)",
            TreeOrigin::PreExisting => "(already in package.json)",
        }
    }

    fn json_name(self) -> &'static str {
        match self {
            TreeOrigin::Transitive => "transitive",
            TreeOrigin::Requested => "requested",
            TreeOrigin::PreExisting => "pre-existing",
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
/// never ran (recency-only / tokenless mode).
#[derive(Debug)]
pub enum TreeReport {
    /// The full would-install set was resolved and verdicted.
    Full {
        /// Distinct packages the dry-run resolved (named + transitive).
        resolved_count: usize,
        /// Verdicts for resolved packages beyond the named targets.
        transitive: Vec<TreeOutcome>,
        /// Warn-only `npm audit` second opinion (npm only; `None` when
        /// unavailable, disabled, or failed). Never consulted for blocking.
        audit: Option<tree::AuditSummary>,
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
    /// `None` ⇒ recency-only mode, the tree pass never ran.
    pub tree: Option<TreeReport>,
    /// Verification results for proposed safe-version steers, keyed by
    /// (normalized name, proposed version). Populated by `verify_steers`;
    /// consulted only at render time, never by the block predicate.
    pub steers: HashMap<(String, String), SteerCheck>,
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
    pub fn vulnerable_count(&self) -> usize {
        self.named_vulnerable_count() + self.tree_vulnerable_count()
    }
    pub fn unverifiable_count(&self) -> usize {
        self.named_unverifiable_count() + self.tree_unverifiable_count()
    }
    /// Vulnerable findings among the named targets this command adds.
    pub fn named_vulnerable_count(&self) -> usize {
        self.named_finding_count(|v| matches!(v, VerdictStatus::Vulnerable(_)))
    }
    /// Unverifiable findings among the named targets this command adds.
    pub fn named_unverifiable_count(&self) -> usize {
        self.named_finding_count(|v| matches!(v, VerdictStatus::Unverifiable(_)))
    }
    /// Count named (resolved) outcomes whose verdict matches `pred`.
    fn named_finding_count(&self, pred: impl Fn(&VerdictStatus) -> bool) -> usize {
        self.count(|o| matches!(o, TargetOutcome::Resolved { verdict, .. } if pred(verdict)))
    }
    /// Vulnerable findings beyond the named targets (the resolved tree).
    pub fn tree_vulnerable_count(&self) -> usize {
        self.tree_finding_count(|v| matches!(v, VerdictStatus::Vulnerable(_)))
    }
    /// Unverifiable findings beyond the named targets (the resolved tree).
    pub fn tree_unverifiable_count(&self) -> usize {
        self.tree_finding_count(|v| matches!(v, VerdictStatus::Unverifiable(_)))
    }
    /// Count transitive tree findings whose verdict matches `pred`.
    fn tree_finding_count(&self, pred: impl Fn(&VerdictStatus) -> bool) -> usize {
        match &self.tree {
            Some(TreeReport::Full { transitive, .. }) => {
                transitive.iter().filter(|o| pred(&o.verdict)).count()
            }
            Some(TreeReport::NamedOnly { .. }) | None => 0,
        }
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
    // With a verdict config, the tree pass resolves the full would-install
    // set; `tree::covers_input` owns what each manager's resolver can chew on.
    let tree_eligible = opts.verdict.is_some() && tree::covers_input(manager, &parsed);
    let bare_install = parsed.targets.is_empty() && parsed.requirements_files.is_empty();

    if parsed.targets.is_empty() && !tree_eligible {
        bare_install_note(manager, subcommand_label);
        requirements_note(&parsed);
        return exec();
    }

    let now = Utc::now();
    let mut outcomes: Vec<_> = parsed
        .targets
        .iter()
        .map(|target| verify_one(target, &opts, &now))
        .collect();

    let tree = if tree_eligible {
        Some(run_tree_pass(manager, rest, &mut outcomes, &opts))
    } else {
        run_verdict_pass(manager, &mut outcomes, &opts); // no-op tokenless
        None
    };

    // The mandatory loud warning when the tree pass fell back to named-only.
    if let Some(TreeReport::NamedOnly { reason }) = &tree {
        eprintln!(
            "warning: transitive dependencies not checked ({reason}); only named packages were verified."
        );
    }
    // Warn-only npm audit second opinion: never blocks, never changes
    // exit codes (`should_block_install` ignores it by design).
    if let Some(TreeReport::Full {
        audit: Some(audit), ..
    }) = &tree
    {
        if audit.total > 0 {
            eprintln!(
                "note: npm audit reports {} advisories ({} high/critical) — supplementary signal, not blocking",
                audit.total,
                audit.high + audit.critical
            );
        }
    }
    // The requirements note only matters when the tree pass did *not* cover
    // those files (fallback to named-only, or recency-only mode).
    if !matches!(&tree, Some(TreeReport::Full { .. })) {
        requirements_note(&parsed);
    }
    if opts.verdict.is_none() {
        eprintln!(
            "warning: no Corgea token — known-vulnerable packages will NOT be blocked (recency-only). Run 'corgea login' for the full gate."
        );
    }

    let mut report = PrecheckReport {
        manager,
        subcommand: subcommand_label.to_string(),
        original_args: rest.to_vec(),
        outcomes,
        threshold: opts.threshold,
        tree,
        steers: HashMap::new(),
        bare_install,
    };
    verify_steers(&mut report, &opts);

    if opts.json {
        print_json(&report, &opts);
    } else {
        print_text(&report);
    }

    if should_block_install(&report, &opts) {
        if !opts.json {
            print_refusal(&report);
        }
        return 1;
    }

    exec()
}

/// One honest stderr line when a zero-spec install can't be gated:
/// yarn/pnpm/uv have no safe dry-run, so a bare install pulls its whole
/// dependency set unchecked. No-op for other managers (bare npm is gated
/// via the tree pass; bare pip installs nothing).
fn bare_install_note(manager: PackageManager, subcommand_label: &str) {
    if matches!(
        manager,
        PackageManager::Yarn | PackageManager::Pnpm | PackageManager::Uv
    ) {
        eprintln!(
            "note: bare '{} {}' is not gated (no safe dry-run) — dependencies install unchecked",
            manager.binary_name(),
            subcommand_label
        );
    }
}

/// The refusal line on stderr. When vulnerable findings exist but none sit on
/// a named target — and no named target is unverifiable either — the block is
/// entirely the existing tree's doing, so say that instead of implying the
/// package the user typed is at fault. Messaging only; the block decision
/// stays with `should_block_install`.
fn print_refusal(report: &PrecheckReport) {
    if refusal_blames_existing_tree(report) {
        eprintln!(
            "Refusing to run install: your existing dependency tree has known-vulnerable packages (none were added by this command). Fix them or pass --force."
        );
    } else if report.vulnerable_count() > 0 || report.unverifiable_count() > 0 {
        eprintln!("Refusing to run install. Pass --force to proceed despite findings.");
    } else {
        eprintln!("Refusing to run install. Pass --no-fail to proceed anyway.");
    }
}

/// True when the block is entirely the existing tree's doing: vulnerable
/// findings exist, none sit on a named target (or block as unverifiable
/// there), and every *blocking* tree finding — vulnerable or unverifiable,
/// since `should_block_install` refuses on both — genuinely predates this
/// command. A `Requested` finding (pip `-r`) is added by this command and
/// renders as `(from requirements)`; a `Transitive` finding on any install
/// that names targets or requirements files is being pulled in by them
/// right now. Only a truly bare install (`report.bare_install`) or
/// manifest-declared `PreExisting` findings may blame the existing tree.
fn refusal_blames_existing_tree(report: &PrecheckReport) -> bool {
    let named_findings = report.named_vulnerable_count() + report.named_unverifiable_count();
    if report.vulnerable_count() == 0 || named_findings > 0 {
        return false;
    }
    let Some(TreeReport::Full { transitive, .. }) = &report.tree else {
        return false;
    };
    transitive
        .iter()
        .filter(|t| {
            matches!(
                t.verdict,
                VerdictStatus::Vulnerable(_) | VerdictStatus::Unverifiable(_)
            )
        })
        .all(|t| match t.origin {
            TreeOrigin::PreExisting => true,
            TreeOrigin::Requested => false,
            TreeOrigin::Transitive => report.bare_install,
        })
}

/// Print the "requirements files are not recency-checked" note when the
/// install carried any `-r` files. No-op otherwise.
fn requirements_note(parsed: &parse::ParsedInstall) {
    if parsed.requirements_files.is_empty() {
        return;
    }
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

/// Resolve the full would-install set and verdict it. On any resolution
/// failure, fall back to the named-only verdict pass; the caller renders the
/// loud warning from the returned `NamedOnly` reason. Only called when
/// `opts.verdict.is_some()`.
fn run_tree_pass(
    manager: PackageManager,
    rest: &[String],
    outcomes: &mut [TargetOutcome],
    opts: &PrecheckOptions,
) -> TreeReport {
    let tree::TreeResolution {
        packages: set,
        audit: audit_rx,
    } = match tree::resolve_tree(manager, rest, opts.npm_audit) {
        Ok(Some(resolution)) => resolution,
        Ok(None) => {
            run_verdict_pass(manager, outcomes, opts);
            return TreeReport::NamedOnly {
                reason: format!("{} has no safe dry-run", manager.binary_name()),
            };
        }
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
    let results = verdict_pool(jobs, cfg, manager, VERDICT_CONCURRENCY);
    // Collect the warn-only npm audit second opinion only after the verdict
    // pool so the two truly overlap. The wait is capped tight: this signal
    // never changes the outcome, so a finished gate won't stall long for it —
    // a slow audit is killed and skipped (collect also reaps the subprocess,
    // so nothing outlives the CLI).
    let audit = audit_rx.and_then(|handle| handle.collect(Duration::from_secs(1)));
    let transitive = apply_verdicts(manager, results, outcomes, &direct_deps);
    TreeReport::Full {
        resolved_count,
        transitive,
        audit,
    }
}

/// Above this many verdict jobs, print a stderr progress line so a big tree
/// pass doesn't look hung.
const VERDICT_PROGRESS_THRESHOLD: usize = 8;

/// Max parallel vuln-api verdict requests.
const VERDICT_CONCURRENCY: usize = 8;

/// Bounded worker pool over the verdict jobs — owns client creation and the
/// fail-closed policy: on client failure every job comes back `Unverifiable`.
/// Plain work queue, no new crates; `reqwest::blocking::Client` is
/// `Send + Sync`. Result order is not preserved; callers match results back
/// by `(name, version)`.
fn verdict_pool(
    jobs: Vec<tree::TreePackage>,
    cfg: &VerdictConfig,
    manager: PackageManager,
    concurrency: usize,
) -> Vec<(tree::TreePackage, VerdictStatus)> {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    let client = match crate::vuln_api::http_client() {
        Ok(c) => c,
        Err(e) => {
            return jobs
                .into_iter()
                .map(|j| (j, VerdictStatus::Unverifiable(e.clone())))
                .collect();
        }
    };

    if jobs.len() > VERDICT_PROGRESS_THRESHOLD {
        eprintln!("checking {} packages against Corgea vuln-api…", jobs.len());
    }

    let ecosystem = manager.ecosystem();
    let workers = concurrency.min(jobs.len()).max(1);
    let queue = Mutex::new(VecDeque::from(jobs));
    let results = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let Some(job) = queue.lock().unwrap().pop_front() else {
                    break;
                };
                let verdict = match crate::vuln_api::check_package_version(
                    &client,
                    &cfg.base_url,
                    &cfg.token,
                    ecosystem,
                    &job.name,
                    &job.version,
                ) {
                    Ok(resp) if resp.is_vulnerable => VerdictStatus::Vulnerable(resp.matches),
                    Ok(_) => VerdictStatus::Clean,
                    Err(e) => VerdictStatus::Unverifiable(e.to_string()),
                };
                results.lock().unwrap().push((job, verdict));
            });
        }
    });
    results.into_inner().unwrap()
}

/// Assign pooled verdicts onto matching named outcomes (by normalized
/// name + version) and return the unmatched leftovers — the tree findings.
/// Each leftover carries its provenance: pip's `requested` flag, membership
/// in the project manifest's direct deps (`direct_deps`), or transitive.
fn apply_verdicts(
    manager: PackageManager,
    results: Vec<(tree::TreePackage, VerdictStatus)>,
    outcomes: &mut [TargetOutcome],
    direct_deps: &std::collections::HashSet<String>,
) -> Vec<TreeOutcome> {
    let norm = |n: &str| manager.normalize_name(n);
    // Index named outcomes by (normalized name, version) so matching the
    // pooled results stays linear on big trees.
    let mut named: std::collections::HashMap<(String, String), Vec<usize>> =
        std::collections::HashMap::new();
    for (i, o) in outcomes.iter().enumerate() {
        if let TargetOutcome::Resolved { resolved, .. } = o {
            named
                .entry((norm(&resolved.name), resolved.version.clone()))
                .or_default()
                .push(i);
        }
    }

    let mut transitive = Vec::new();
    for (pkg, verdict) in results {
        if let Some(indices) = named.get(&(norm(&pkg.name), pkg.version.clone())) {
            for &i in indices {
                if let TargetOutcome::Resolved { verdict: v, .. } = &mut outcomes[i] {
                    *v = verdict.clone();
                }
            }
        } else {
            let origin = if pkg.requested {
                TreeOrigin::Requested
            } else if direct_deps.contains(&pkg.name) {
                TreeOrigin::PreExisting
            } else {
                TreeOrigin::Transitive
            };
            transitive.push(TreeOutcome {
                name: pkg.name,
                version: pkg.version,
                origin,
                verdict,
            });
        }
    }
    transitive
}

/// Vuln-api verdict pass over resolved targets, run through the bounded
/// worker pool. No-op without a `VerdictConfig` (tokenless mode — `verify_one`
/// already marked every resolved target `NotChecked`). Any client/call failure
/// is fail-closed: the target becomes `Unverifiable`, which blocks unless
/// `--force`.
fn run_verdict_pass(
    manager: PackageManager,
    outcomes: &mut [TargetOutcome],
    opts: &PrecheckOptions,
) {
    let Some(cfg) = &opts.verdict else { return };

    // One job per resolved target; jobs are 1:1 with outcomes, so
    // `apply_verdicts` matches everything and returns no leftovers.
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

    let results = verdict_pool(jobs, cfg, manager, VERDICT_CONCURRENCY);
    apply_verdicts(manager, results, outcomes, &Default::default());
}

/// Re-verdict every proposed `→ safe version` steer before anything prints.
/// Populates `report.steers` keyed by (normalized name, proposed version):
/// `Clean` ⇒ `Verified`, flagged ⇒ `Rejected`, request failure ⇒ `Unverified`
/// (suppressed quietly — never feeds counts or exit codes). Sends requests
/// only when a token is configured and at least one vulnerable verdict
/// proposed a steer; proposals dedup by normalized (name, version).
fn verify_steers(report: &mut PrecheckReport, opts: &PrecheckOptions) {
    let Some(cfg) = &opts.verdict else { return };
    let manager = report.manager;

    let mut proposals: Vec<(&str, &[crate::vuln_api::VulnMatch])> = Vec::new();
    for o in &report.outcomes {
        if let TargetOutcome::Resolved {
            resolved,
            verdict: VerdictStatus::Vulnerable(matches),
            ..
        } = o
        {
            proposals.push((&resolved.name, matches));
        }
    }
    if let Some(TreeReport::Full { transitive, .. }) = &report.tree {
        for t in transitive {
            if let VerdictStatus::Vulnerable(matches) = &t.verdict {
                proposals.push((&t.name, matches));
            }
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut jobs: Vec<tree::TreePackage> = Vec::new();
    for (name, matches) in proposals {
        let Some(safe) = safe_version(matches) else {
            continue;
        };
        if seen.insert((manager.normalize_name(name), safe.clone())) {
            jobs.push(tree::TreePackage {
                name: name.to_string(),
                version: safe,
                // Steer re-check jobs are synthetic, not user-requested.
                requested: false,
            });
        }
    }
    if jobs.is_empty() {
        return;
    }

    let results = verdict_pool(jobs, cfg, manager, VERDICT_CONCURRENCY);
    report.steers = results
        .into_iter()
        .map(|(pkg, verdict)| {
            let check = match verdict {
                VerdictStatus::Clean => SteerCheck::Verified,
                VerdictStatus::Vulnerable(_) => SteerCheck::Rejected,
                VerdictStatus::Unverifiable(_) | VerdictStatus::NotChecked => {
                    SteerCheck::Unverified
                }
            };
            ((manager.normalize_name(&pkg.name), pkg.version), check)
        })
        .collect();
}

fn should_block_install(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
    if opts.force {
        return false;
    }
    report.vulnerable_count() > 0
        || report.unverifiable_count() > 0
        || (!opts.no_fail && report.recent_count() > 0)
}

fn verify_one(
    target: &InstallTarget,
    opts: &PrecheckOptions,
    now: &chrono::DateTime<chrono::Utc>,
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
            // Future publish dates clamp to zero — maximally recent.
            let age = now
                .signed_duration_since(resolved.published_at)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(0));
            TargetOutcome::Resolved {
                target: target.clone(),
                resolved,
                age,
                verdict: VerdictStatus::NotChecked,
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

/// Resolve `binary` on PATH. On Windows this finds `.cmd` shims. pip is the
/// one manager with a conventional alias, so a missing `pip` retries `pip3`.
/// The error names the binary and any fallback tried.
fn resolve_binary(binary: &str) -> Result<std::path::PathBuf, String> {
    if let Ok(p) = which::which(binary) {
        return Ok(p);
    }
    if binary == "pip" {
        if let Ok(p) = which::which("pip3") {
            return Ok(p);
        }
        return Err("error: 'pip' not found on PATH (also tried 'pip3')".to_string());
    }
    Err(format!("error: '{binary}' not found on PATH"))
}

fn exec_command(binary: &str, args: &[String]) -> i32 {
    let resolved = match resolve_binary(binary) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
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
            // Name the resolved path: it may be the pip3 fallback, not `binary`.
            eprintln!("failed to exec {}: {}", resolved.display(), e);
            1
        }
    }
}

/// Suffix for a vulnerable match line: the advisory's fix, if known.
fn fix_note(m: &crate::vuln_api::VulnMatch) -> String {
    match &m.fixed_version {
        Some(v) => format!(" — fixed in {v}"),
        None => " — no fixed version known".to_string(),
    }
}

/// Highest of `fixes` after sort/dedup: a single distinct value is returned
/// as-is (no parsing — preserves odd-but-unambiguous forms); several distinct
/// values compare by lenient semver. With `all_must_parse`, one unparsable
/// candidate among several poisons the answer (`None`); otherwise unparsable
/// candidates are skipped.
fn highest_fix(mut fixes: Vec<&str>, all_must_parse: bool) -> Option<String> {
    fixes.sort_unstable();
    fixes.dedup();
    match fixes.as_slice() {
        [] => None,
        [only] => Some((*only).to_string()),
        many => {
            let mut best: Option<(semver::Version, &str)> = None;
            for raw in many {
                let v =
                    match semver::Version::parse(&verify_deps::registry::normalize_for_semver(raw))
                    {
                        Ok(v) => v,
                        Err(_) if all_must_parse => return None,
                        Err(_) => continue,
                    };
                match &best {
                    Some((cur, _)) if cur >= &v => {}
                    _ => best = Some((v, raw)),
                }
            }
            best.map(|(_, raw)| (*raw).to_string())
        }
    }
}

/// The one version certified to clear every match. Requires every match to
/// carry a `fixed_version`; any match without one — or an unparsable
/// candidate among several — means no version can be certified, so `None`.
fn safe_version(matches: &[crate::vuln_api::VulnMatch]) -> Option<String> {
    let fixes: Vec<&str> = matches
        .iter()
        .map(|m| m.fixed_version.as_deref())
        .collect::<Option<_>>()?;
    highest_fix(fixes, true)
}

/// The safe-version proposal for a vulnerable package, paired with its
/// `verify_steers` re-check. `None` when no version can be proposed at all;
/// a proposal absent from the steer map counts as `Unverified` so callers
/// suppress it.
fn steer_for(
    report: &PrecheckReport,
    name: &str,
    matches: &[crate::vuln_api::VulnMatch],
) -> Option<(String, SteerCheck)> {
    let safe = safe_version(matches)?;
    let check = report
        .steers
        .get(&(report.manager.normalize_name(name), safe.clone()))
        .copied()
        .unwrap_or(SteerCheck::Unverified);
    Some((safe, check))
}

/// Highest `fixed_version` the advisories advertise, by lenient semver.
/// Unlike `safe_version` this is *not* a certification: matches without a
/// fix are ignored, so the result may still be vulnerable to them. `None`
/// only when no match advertises a fix (or no candidate parses).
fn advertised_fix(matches: &[crate::vuln_api::VulnMatch]) -> Option<String> {
    let fixes: Vec<&str> = matches
        .iter()
        .filter_map(|m| m.fixed_version.as_deref())
        .collect();
    highest_fix(fixes, false)
}

/// Per-match advisory lines plus the verified safe-version steer, shared by
/// the named-target and transitive vulnerable render arms.
fn print_vulnerable_matches(
    report: &PrecheckReport,
    name: &str,
    matches: &[crate::vuln_api::VulnMatch],
) {
    for m in matches {
        println!(
            "      {} ({}){}",
            m.advisory_id,
            m.severity_level,
            fix_note(m)
        );
    }
    match steer_for(report, name, matches) {
        Some((safe, SteerCheck::Verified)) => {
            println!("      → safe version: {name}@{safe}");
        }
        Some((safe, SteerCheck::Rejected)) => {
            println!("      → advertised fix {safe} is also flagged — no safe version to suggest");
        }
        Some((_, SteerCheck::Unverified)) | None => {}
    }
}

/// One summary-line segment, e.g. `"2 vulnerable (2 from resolved tree)"`.
/// The parenthetical separates findings the resolved tree carried in from
/// findings on the targets this command names; omitted when the tree
/// contributed none.
fn summary_segment(total: usize, from_tree: usize, label: &str) -> String {
    if from_tree > 0 {
        format!("{total} {label} ({from_tree} from resolved tree)")
    } else {
        format!("{total} {label}")
    }
}

/// More than this many unverifiable findings with the same error-prefix
/// render as one collapsed line instead of one line per package.
const UNVERIFIABLE_COLLAPSE_THRESHOLD: usize = 3;

/// Group key for collapsing repeated unverifiable errors: the text before
/// the first `(` — strips per-package detail (URLs, status codes) so one
/// outage groups under one key.
fn error_prefix(error: &str) -> &str {
    match error.find('(') {
        Some(i) => error[..i].trim_end(),
        None => error,
    }
}

/// Unverifiable error strings across transitive tree findings and named
/// outcomes, in render order.
fn unverifiable_errors(report: &PrecheckReport) -> Vec<&str> {
    let mut errors = Vec::new();
    if let Some(TreeReport::Full { transitive, .. }) = &report.tree {
        for t in transitive {
            if let VerdictStatus::Unverifiable(e) = &t.verdict {
                errors.push(e.as_str());
            }
        }
    }
    for o in &report.outcomes {
        if let TargetOutcome::Resolved {
            verdict: VerdictStatus::Unverifiable(e),
            ..
        } = o
        {
            errors.push(e.as_str());
        }
    }
    errors
}

/// `(prefix, count, first error)` groups of unverifiable findings large
/// enough to collapse (> `UNVERIFIABLE_COLLAPSE_THRESHOLD` per prefix) —
/// the vuln-api outage case, where every package fails the same way.
/// Display-only: counts and exit codes never change.
fn collapsed_unverifiable_groups(report: &PrecheckReport) -> Vec<(&str, usize, &str)> {
    let mut groups: Vec<(&str, usize, &str)> = Vec::new();
    for e in unverifiable_errors(report) {
        let prefix = error_prefix(e);
        match groups.iter_mut().find(|(p, _, _)| *p == prefix) {
            Some((_, count, _)) => *count += 1,
            None => groups.push((prefix, 1, e)),
        }
    }
    groups.retain(|(_, count, _)| *count > UNVERIFIABLE_COLLAPSE_THRESHOLD);
    groups
}

fn print_text(report: &PrecheckReport) {
    // Build the echoed command from non-empty parts: a bare gated install
    // (e.g. `npm install` with zero specs) has no args to append.
    let mut command = format!("{} {}", report.manager.binary_name(), report.subcommand);
    if !report.original_args.is_empty() {
        command.push(' ');
        command.push_str(&report.original_args.join(" "));
    }

    let collapsed = collapsed_unverifiable_groups(report);
    let is_collapsed = |error: &str| {
        collapsed
            .iter()
            .any(|(prefix, _, _)| *prefix == error_prefix(error))
    };

    println!(
        "Pre-checking `{}` (threshold {})",
        command,
        verify_deps::format_duration(report.threshold)
    );
    println!(
        "  {} ok, {} recent, {}, {}, {} skipped, {} errors",
        report.ok_count(),
        report.recent_count(),
        summary_segment(
            report.vulnerable_count(),
            report.tree_vulnerable_count(),
            "vulnerable"
        ),
        summary_segment(
            report.unverifiable_count(),
            report.tree_unverifiable_count(),
            "unverifiable"
        ),
        report.skipped_count(),
        report.error_count(),
    );

    match &report.tree {
        Some(TreeReport::Full {
            resolved_count,
            transitive,
            ..
        }) => {
            println!(
                "  tree: {} packages resolved, {} transitive checked",
                resolved_count,
                transitive.len()
            );
            for t in transitive {
                match &t.verdict {
                    VerdictStatus::Vulnerable(matches) => {
                        println!(
                            "  ✗ {}@{} {}  known vulnerable:",
                            t.name,
                            t.version,
                            t.origin.label()
                        );
                        print_vulnerable_matches(report, &t.name, matches);
                        // A vulnerable dep the project already declares can be
                        // bumped directly — point at the fix as a command. The
                        // caveat follows the steer check above: a Verified
                        // steer certified this same version (when `safe_version`
                        // is `Some` it equals `advertised_fix`), a Rejected one
                        // already said the fix is flagged, so only an
                        // unverified proposal keeps the "(advertised fix)"
                        // hedge.
                        if t.origin == TreeOrigin::PreExisting {
                            if let Some(fix) = advertised_fix(matches) {
                                match steer_for(report, &t.name, matches) {
                                    Some((_, SteerCheck::Rejected)) => {}
                                    Some((_, SteerCheck::Verified)) => println!(
                                        "      fix with: corgea {} install {}@{}",
                                        report.manager.binary_name(),
                                        t.name,
                                        fix
                                    ),
                                    Some((_, SteerCheck::Unverified)) | None => println!(
                                        "      fix with: corgea {} install {}@{} (advertised fix)",
                                        report.manager.binary_name(),
                                        t.name,
                                        fix
                                    ),
                                }
                            }
                        }
                    }
                    VerdictStatus::Unverifiable(error) => {
                        if !is_collapsed(error) {
                            println!(
                                "  ⚠ {}@{} {}  could not be verified: {}",
                                t.name,
                                t.version,
                                t.origin.label(),
                                error
                            );
                        }
                    }
                    // Clean / not-checked tree entries stay quiet in text mode.
                    VerdictStatus::Clean | VerdictStatus::NotChecked => {}
                }
            }
        }
        Some(TreeReport::NamedOnly { reason }) => {
            println!("  tree: transitive dependencies NOT checked ({reason})");
        }
        None => {}
    }

    // One line per collapsed outage group instead of one per package.
    for (_, count, first_error) in &collapsed {
        println!(
            "  ⚠ {count} packages could not be verified (vuln-api unreachable: {first_error})"
        );
    }

    for o in &report.outcomes {
        match o {
            TargetOutcome::Resolved {
                target,
                resolved,
                age,
                verdict,
            } => match verdict {
                VerdictStatus::Vulnerable(matches) => {
                    println!(
                        "  ✗ {} → {}@{}  known vulnerable:",
                        target.display, resolved.name, resolved.version,
                    );
                    print_vulnerable_matches(report, &resolved.name, matches);
                }
                VerdictStatus::Unverifiable(error) => {
                    if !is_collapsed(error) {
                        println!(
                            "  ⚠ {} → {}@{}  could not be verified: {}",
                            target.display, resolved.name, resolved.version, error,
                        );
                    }
                }
                VerdictStatus::Clean | VerdictStatus::NotChecked => {
                    if report.is_recent(*age) {
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
            },
            TargetOutcome::Skipped { target, reason } => {
                println!("  ? {}: {}", target.display, reason);
            }
            TargetOutcome::Error { target, error } => {
                println!("  ✗ {}: {}", target.display, error);
            }
        }
    }
}

/// JSON shape for a single verdict. Shared by named outcomes and tree
/// (transitive) outcomes so both render verdicts identically.
/// `remediation` carries the safe version only when its steer re-check
/// came back `Verified`; rejected/unverified steers emit `null`.
fn verdict_json(report: &PrecheckReport, name: &str, verdict: &VerdictStatus) -> serde_json::Value {
    use serde_json::json;
    match verdict {
        VerdictStatus::Clean => json!({ "status": "clean" }),
        VerdictStatus::Vulnerable(matches) => {
            let remediation = match steer_for(report, name, matches) {
                Some((safe, SteerCheck::Verified)) => Some(safe),
                _ => None,
            };
            json!({
                "status": "vulnerable",
                "matches": matches,
                "remediation": remediation,
            })
        }
        VerdictStatus::Unverifiable(error) => {
            json!({ "status": "unverifiable", "error": error })
        }
        VerdictStatus::NotChecked => {
            json!({ "status": "not_checked", "reason": NO_TOKEN_REASON })
        }
    }
}

/// JSON shape for the warn-only npm audit second opinion in the tree arm.
fn npm_audit_json(audit: &tree::AuditSummary) -> serde_json::Value {
    use serde_json::json;
    json!({
        "total": audit.total,
        "critical": audit.critical,
        "high": audit.high,
        "moderate": audit.moderate,
        "low": audit.low,
        "info": audit.info,
        "top": audit.top.iter().map(|(name, severity)| json!({
            "name": name,
            "severity": severity,
        })).collect::<Vec<_>>(),
    })
}

fn print_json(report: &PrecheckReport, opts: &PrecheckOptions) {
    use serde_json::json;
    let outcomes: Vec<_> = report
        .outcomes
        .iter()
        .map(|o| match o {
            TargetOutcome::Resolved {
                target,
                resolved,
                age,
                verdict,
            } => {
                let verdict_json = verdict_json(report, &resolved.name, verdict);
                json!({
                    "status": if report.is_recent(*age) { "recent" } else { "ok" },
                    "spec": target.display,
                    "name": resolved.name,
                    "resolved_version": resolved.version,
                    "published_at": resolved.published_at.to_rfc3339(),
                    "age_seconds": age.as_secs(),
                    "verdict": verdict_json,
                })
            }
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
            "vulnerable": report.vulnerable_count(),
            "unverifiable": report.unverifiable_count(),
            "skipped": report.skipped_count(),
            "errors": report.error_count(),
        },
        "verdict_mode": if opts.verdict.is_some() { "full" } else { "recency-only" },
        "results": outcomes,
        "tree": report.tree.as_ref().map(|t| match t {
            TreeReport::Full { resolved_count, transitive, audit } => json!({
                "mode": "full",
                "reason": serde_json::Value::Null,
                "resolved_count": resolved_count,
                "transitive": transitive.iter().map(|o| json!({
                    "name": o.name,
                    "version": o.version,
                    "origin": o.origin.json_name(),
                    "verdict": verdict_json(report, &o.name, &o.verdict),
                })).collect::<Vec<_>>(),
                "npm_audit": audit.as_ref().map(npm_audit_json),
            }),
            TreeReport::NamedOnly { reason } => json!({
                "mode": "named-only",
                "reason": reason,
                "resolved_count": 0,
                "transitive": [],
                "npm_audit": serde_json::Value::Null,
            }),
        }),
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

    /// Baseline options: pypi registry at a dead address (a port that
    /// refuses connections — these tests never dial it), no verdict config.
    /// Override fields per test via struct update.
    fn stub_opts() -> PrecheckOptions {
        PrecheckOptions {
            threshold: Duration::from_secs(2 * 86400),
            no_fail: false,
            force: false,
            json: false,
            verdict: None,
            npm_registry: None,
            pypi_registry: Some("http://127.0.0.1:9".to_string()),
            // Unit tests never want the real `npm audit` subprocess.
            npm_audit: false,
        }
    }

    /// `stub_opts()` plus a verdict config pointing at `base_url`.
    fn verdict_opts(base_url: &str) -> PrecheckOptions {
        PrecheckOptions {
            verdict: Some(VerdictConfig {
                base_url: base_url.to_string(),
                token: "test-token".to_string(),
            }),
            ..stub_opts()
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

    fn resolved_outcome(name: &str, version: &str, recent: bool) -> TargetOutcome {
        // Recency derives from age vs `report_with`'s 2-day threshold:
        // one hour ⇒ recent, a year ⇒ not.
        let age = if recent {
            Duration::from_secs(3600)
        } else {
            Duration::from_secs(365 * 86400)
        };
        TargetOutcome::Resolved {
            target: InstallTarget {
                name: name.to_string(),
                display: format!("{name}=={version}"),
                kind: TargetKind::Unverifiable {
                    reason: "test".to_string(),
                },
            },
            resolved: crate::verify_deps::registry::ResolvedPackage {
                name: name.to_string(),
                version: version.to_string(),
                published_at: Utc::now() - chrono::Duration::from_std(age).unwrap(),
            },
            age,
            verdict: VerdictStatus::NotChecked,
        }
    }

    fn report_with(outcomes: Vec<TargetOutcome>) -> PrecheckReport {
        PrecheckReport {
            manager: PackageManager::Pip,
            subcommand: "install".to_string(),
            original_args: vec![],
            outcomes,
            threshold: Duration::from_secs(2 * 86400),
            tree: None,
            steers: HashMap::new(),
            // Most tests model an install that named something; bare-install
            // cases set this explicitly.
            bare_install: false,
        }
    }

    fn set_verdict(outcome: &mut TargetOutcome, v: VerdictStatus) {
        if let TargetOutcome::Resolved { verdict, .. } = outcome {
            *verdict = v;
        }
    }

    #[test]
    fn ecosystem_mapping() {
        assert_eq!(PackageManager::Pip.ecosystem(), "pypi");
        assert_eq!(PackageManager::Uv.ecosystem(), "pypi");
        assert_eq!(PackageManager::Npm.ecosystem(), "npm");
        assert_eq!(PackageManager::Yarn.ecosystem(), "npm");
        assert_eq!(PackageManager::Pnpm.ecosystem(), "npm");
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

    /// Full predicate matrix: force ⇒ never block; vulnerable and
    /// unverifiable block regardless of --no-fail; recency keeps its
    /// task-2 --no-fail demotion.
    #[test]
    fn block_predicate_matrix() {
        let opts = |no_fail: bool, force: bool| PrecheckOptions {
            no_fail,
            force,
            ..stub_opts()
        };

        let clean = {
            let mut o = resolved_outcome("pkg", "1.0.0", false);
            set_verdict(&mut o, VerdictStatus::Clean);
            report_with(vec![o])
        };
        let recent = report_with(vec![resolved_outcome("pkg", "1.0.0", true)]);
        let vulnerable = {
            let mut o = resolved_outcome("pkg", "1.0.0", false);
            set_verdict(&mut o, VerdictStatus::Vulnerable(vec![]));
            report_with(vec![o])
        };
        let unverifiable = {
            let mut o = resolved_outcome("pkg", "1.0.0", false);
            set_verdict(&mut o, VerdictStatus::Unverifiable("503".to_string()));
            report_with(vec![o])
        };

        assert!(!should_block_install(&clean, &opts(false, false)));
        assert!(should_block_install(&recent, &opts(false, false)));
        assert!(!should_block_install(&recent, &opts(true, false)));
        assert!(should_block_install(&vulnerable, &opts(false, false)));
        assert!(
            should_block_install(&vulnerable, &opts(true, false)),
            "--no-fail must not waive a vulnerable block"
        );
        assert!(
            should_block_install(&unverifiable, &opts(true, false)),
            "--no-fail must not waive an unverifiable block"
        );
        for report in [&clean, &recent, &vulnerable, &unverifiable] {
            assert!(
                !should_block_install(report, &opts(false, true)),
                "--force must never block"
            );
            assert!(!should_block_install(report, &opts(true, true)));
        }
    }

    /// A clean named outcome plus a vulnerable transitive tree finding must
    /// roll into the block counts: `vulnerable_count() == 1`,
    /// `should_block_install` true without `--force`, false with it.
    #[test]
    fn tree_findings_extend_block_counts() {
        let mut named = resolved_outcome("pkg", "1.0.0", false);
        set_verdict(&mut named, VerdictStatus::Clean);
        let mut report = report_with(vec![named]);
        report.tree = Some(TreeReport::Full {
            resolved_count: 2,
            transitive: vec![TreeOutcome {
                name: "evildep".to_string(),
                version: "0.4.2".to_string(),
                origin: TreeOrigin::Transitive,
                verdict: VerdictStatus::Vulnerable(vec![]),
            }],
            audit: None,
        });

        assert_eq!(report.vulnerable_count(), 1);
        let opts = |force: bool| PrecheckOptions {
            force,
            ..stub_opts()
        };
        assert!(should_block_install(&report, &opts(false)));
        assert!(!should_block_install(&report, &opts(true)));
    }

    /// Verdict pass against an in-process stub: vulnerable body → Vulnerable
    /// with matches; 503 override → Unverifiable; no VerdictConfig → outcomes
    /// keep NotChecked.
    #[test]
    fn verdict_pass_maps_stub_responses() {
        use std::collections::HashMap;

        let key = |name: &str| ("pypi".to_string(), name.to_string(), "1.0.0".to_string());
        let mut checks = HashMap::new();
        checks.insert(
            key("evil"),
            r#"{"ecosystem":"pypi","package_name":"evil","version":"1.0.0","is_vulnerable":true,
                "matches":[{"advisory_id":"MAL-2024-0001","severity_level":"critical","tier":1,
                            "vulnerable_version_range":null,"fixed_version":null}]}"#
                .to_string(),
        );
        checks.insert(key("flaky"), "{}".to_string());
        let mut statuses = HashMap::new();
        statuses.insert(key("flaky"), 503u16);
        let stub = crate::vuln_api_stub::spawn_with_statuses(checks, statuses);

        let opts = verdict_opts(&stub.base_url);

        let mut outcomes = vec![
            resolved_outcome("evil", "1.0.0", false),
            resolved_outcome("flaky", "1.0.0", false),
            resolved_outcome("goodpkg", "1.0.0", false), // unknown → stub default clean
        ];
        run_verdict_pass(PackageManager::Pip, &mut outcomes, &opts);

        let verdicts: Vec<_> = outcomes
            .iter()
            .map(|o| match o {
                TargetOutcome::Resolved { verdict, .. } => verdict.clone(),
                _ => unreachable!(),
            })
            .collect();
        assert!(
            matches!(&verdicts[0], VerdictStatus::Vulnerable(m) if m[0].advisory_id == "MAL-2024-0001")
        );
        assert!(matches!(&verdicts[1], VerdictStatus::Unverifiable(_)));
        assert!(matches!(&verdicts[2], VerdictStatus::Clean));

        // Without a VerdictConfig the pass is a no-op.
        let mut untouched = vec![resolved_outcome("evil", "1.0.0", false)];
        let no_verdict = stub_opts();
        run_verdict_pass(PackageManager::Pip, &mut untouched, &no_verdict);
        assert!(matches!(
            &untouched[0],
            TargetOutcome::Resolved {
                verdict: VerdictStatus::NotChecked,
                ..
            }
        ));
    }

    /// The pool must verdict every job exactly once and return the flagged
    /// job `Vulnerable` with the rest `Clean`, regardless of `concurrency`
    /// (1 = serial, 8 > job count = all workers spawn but some drain empty).
    #[test]
    fn verdict_pool_returns_all_results() {
        use std::collections::HashMap;

        let key = |name: &str| ("pypi".to_string(), name.to_string(), "1.0.0".to_string());
        let mut checks = HashMap::new();
        checks.insert(
            key("evil"),
            r#"{"ecosystem":"pypi","package_name":"evil","version":"1.0.0","is_vulnerable":true,
                "matches":[{"advisory_id":"MAL-2024-0001","severity_level":"critical","tier":1,
                            "vulnerable_version_range":null,"fixed_version":null}]}"#
                .to_string(),
        );
        let stub = crate::vuln_api_stub::spawn_with_statuses(checks, HashMap::new());

        let cfg = VerdictConfig {
            base_url: stub.base_url.clone(),
            token: "test-token".to_string(),
        };

        let jobs: Vec<tree::TreePackage> = ["a", "b", "evil", "c", "d", "e"]
            .iter()
            .map(|n| tree::TreePackage {
                name: n.to_string(),
                version: "1.0.0".to_string(),
                requested: false,
            })
            .collect();

        for concurrency in [1usize, 8] {
            let results = verdict_pool(jobs.clone(), &cfg, PackageManager::Pip, concurrency);
            assert_eq!(
                results.len(),
                6,
                "concurrency {concurrency}: all jobs verdicted"
            );
            let flagged = results
                .iter()
                .filter(|(_, v)| matches!(v, VerdictStatus::Vulnerable(_)))
                .count();
            let clean = results
                .iter()
                .filter(|(_, v)| matches!(v, VerdictStatus::Clean))
                .count();
            assert_eq!(flagged, 1, "concurrency {concurrency}: only evil flagged");
            assert_eq!(clean, 5, "concurrency {concurrency}: rest clean");
            let evil = results
                .iter()
                .find(|(p, _)| p.name == "evil")
                .expect("evil present");
            assert!(
                matches!(&evil.1, VerdictStatus::Vulnerable(m) if m[0].advisory_id == "MAL-2024-0001")
            );
        }
    }

    fn vm(advisory: &str, fixed: Option<&str>) -> crate::vuln_api::VulnMatch {
        crate::vuln_api::VulnMatch {
            advisory_id: advisory.to_string(),
            severity_level: "high".to_string(),
            tier: 1,
            vulnerable_version_range: None,
            fixed_version: fixed.map(str::to_string),
        }
    }

    #[test]
    fn safe_version_single_fix() {
        assert_eq!(
            safe_version(&[vm("A-1", Some("2.0.0"))]),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn safe_version_duplicate_fixes_collapse_without_parsing() {
        // "1.0rc1" is unparsable, but a single distinct value needs no parse.
        assert_eq!(
            safe_version(&[vm("A-1", Some("1.0rc1")), vm("A-2", Some("1.0rc1"))]),
            Some("1.0rc1".to_string())
        );
    }

    #[test]
    fn safe_version_picks_highest_of_distinct_fixes() {
        // Semver order, not lexical ("1.2.0" > "1.10.0" lexically).
        assert_eq!(
            safe_version(&[vm("A-1", Some("1.2.0")), vm("A-2", Some("1.10.0"))]),
            Some("1.10.0".to_string())
        );
    }

    #[test]
    fn safe_version_two_component_versions_normalize() {
        assert_eq!(
            safe_version(&[vm("A-1", Some("4.0")), vm("A-2", Some("3.2.5"))]),
            Some("4.0".to_string())
        );
    }

    #[test]
    fn safe_version_mixed_fix_and_none_is_none() {
        assert_eq!(
            safe_version(&[vm("A-1", Some("2.0.0")), vm("A-2", None)]),
            None
        );
    }

    #[test]
    fn safe_version_unparsable_among_distinct_is_none() {
        assert_eq!(
            safe_version(&[vm("A-1", Some("2!1.0")), vm("A-2", Some("1.0.0"))]),
            None
        );
    }

    #[test]
    fn safe_version_empty_matches_is_none() {
        assert_eq!(safe_version(&[]), None);
    }

    fn vulnerable_outcome(name: &str, version: &str, fixed: Option<&str>) -> TargetOutcome {
        let mut o = resolved_outcome(name, version, false);
        set_verdict(&mut o, VerdictStatus::Vulnerable(vec![vm("A-1", fixed)]));
        o
    }

    /// `verify_steers` re-verdicts each proposed fix, from named and
    /// transitive findings alike: clean → Verified, flagged → Rejected,
    /// 5xx → Unverified. Counts and the block predicate never move.
    #[test]
    fn verify_steers_maps_reverdicts() {
        let key = |name: &str, ver: &str| ("pypi".to_string(), name.to_string(), ver.to_string());
        let mut checks = HashMap::new();
        checks.insert(
            key("badfix", "3.0.0"),
            r#"{"ecosystem":"pypi","package_name":"badfix","version":"3.0.0","is_vulnerable":true,
                "matches":[{"advisory_id":"MAL-2024-0009","severity_level":"critical","tier":1,
                            "vulnerable_version_range":null,"fixed_version":null}]}"#
                .to_string(),
        );
        checks.insert(key("flaky", "4.0.0"), "{}".to_string());
        let mut statuses = HashMap::new();
        statuses.insert(key("flaky", "4.0.0"), 503u16);
        let stub = crate::vuln_api_stub::spawn_with_statuses(checks, statuses);

        let opts = verdict_opts(&stub.base_url);

        // oldpkg's fix is unknown to the stub → default clean; badfix's fix is
        // flagged; flaky's fix 503s. badfix arrives via the transitive arm.
        let mut report = report_with(vec![
            vulnerable_outcome("oldpkg", "1.0.0", Some("2.0.0")),
            vulnerable_outcome("flaky", "1.0.0", Some("4.0.0")),
        ]);
        report.tree = Some(TreeReport::Full {
            resolved_count: 3,
            transitive: vec![TreeOutcome {
                name: "badfix".to_string(),
                version: "0.1.0".to_string(),
                verdict: VerdictStatus::Vulnerable(vec![vm("A-2", Some("3.0.0"))]),
                origin: TreeOrigin::Transitive,
            }],
            audit: None,
        });
        verify_steers(&mut report, &opts);

        let steer = |name: &str, ver: &str| {
            report
                .steers
                .get(&(name.to_string(), ver.to_string()))
                .copied()
        };
        assert_eq!(steer("oldpkg", "2.0.0"), Some(SteerCheck::Verified));
        assert_eq!(steer("badfix", "3.0.0"), Some(SteerCheck::Rejected));
        assert_eq!(steer("flaky", "4.0.0"), Some(SteerCheck::Unverified));

        // Steer re-checks never feed counts or the block decision.
        assert_eq!(report.vulnerable_count(), 3);
        assert_eq!(report.unverifiable_count(), 0);
    }

    /// Tokenless mode never sends steer requests; `steer_for` treats a
    /// missing map entry as Unverified.
    #[test]
    fn verify_steers_noop_without_token() {
        let opts = stub_opts();
        let mut report = report_with(vec![vulnerable_outcome("oldpkg", "1.0.0", Some("2.0.0"))]);
        verify_steers(&mut report, &opts);
        assert!(report.steers.is_empty());
        assert_eq!(
            steer_for(&report, "oldpkg", &[vm("A-1", Some("2.0.0"))]),
            Some(("2.0.0".to_string(), SteerCheck::Unverified))
        );
    }

    /// No proposal (fix unknown) ⇒ no requests at all: with the vuln-api at a
    /// dead address, an attempted request would land as Unverified.
    #[test]
    fn verify_steers_skips_requests_without_proposals() {
        let opts = verdict_opts("http://127.0.0.1:9");
        let mut report = report_with(vec![vulnerable_outcome("oldpkg", "1.0.0", None)]);
        verify_steers(&mut report, &opts);
        assert!(report.steers.is_empty());
    }

    /// Proposals dedup by normalized (name, version): two pypi spellings of
    /// the same package produce one steer entry, and `steer_for` resolves it
    /// for either spelling.
    #[test]
    fn verify_steers_dedups_by_normalized_name() {
        let stub = crate::vuln_api_stub::spawn_with_statuses(HashMap::new(), HashMap::new());
        let opts = verdict_opts(&stub.base_url);
        let mut report = report_with(vec![
            vulnerable_outcome("Flask_Cors", "1.0.0", Some("2.0.0")),
            vulnerable_outcome("flask-cors", "1.0.0", Some("2.0.0")),
        ]);
        verify_steers(&mut report, &opts);
        assert_eq!(report.steers.len(), 1);
        for spelling in ["Flask_Cors", "flask-cors"] {
            assert_eq!(
                steer_for(&report, spelling, &[vm("A-1", Some("2.0.0"))]),
                Some(("2.0.0".to_string(), SteerCheck::Verified)),
                "spelling {spelling}"
            );
        }
    }

    #[test]
    fn error_prefix_strips_parenthesized_detail() {
        // The reqwest network-failure shape: per-package URL in parens.
        assert_eq!(
            error_prefix("Failed to send vuln-api request: error sending request for url (http://x/v1/packages/pypi/a/versions/1.0.0/check)"),
            "Failed to send vuln-api request: error sending request for url"
        );
        assert_eq!(
            error_prefix("vuln-api unavailable (HTTP 503)"),
            "vuln-api unavailable"
        );
        assert_eq!(error_prefix("no parens here"), "no parens here");
    }

    /// Four unverifiable findings sharing a prefix collapse into one group
    /// (named + transitive both count); three do not.
    #[test]
    fn collapsed_groups_require_more_than_threshold() {
        let unverifiable = |name: &str| {
            let mut o = resolved_outcome(name, "1.0.0", false);
            set_verdict(
                &mut o,
                VerdictStatus::Unverifiable(format!("vuln-api unavailable (HTTP 503: {name})")),
            );
            o
        };

        let mut report = report_with(vec![
            unverifiable("a"),
            unverifiable("b"),
            unverifiable("c"),
        ]);
        assert!(collapsed_unverifiable_groups(&report).is_empty());

        report.tree = Some(TreeReport::Full {
            resolved_count: 4,
            transitive: vec![TreeOutcome {
                name: "d".to_string(),
                version: "1.0.0".to_string(),
                verdict: VerdictStatus::Unverifiable(
                    "vuln-api unavailable (HTTP 503: d)".to_string(),
                ),
                origin: TreeOrigin::Transitive,
            }],
            audit: None,
        });
        let groups = collapsed_unverifiable_groups(&report);
        assert_eq!(groups.len(), 1);
        let (prefix, count, first) = groups[0];
        assert_eq!(prefix, "vuln-api unavailable");
        assert_eq!(count, 4);
        // Render order is transitive-first, so the tree finding leads.
        assert_eq!(first, "vuln-api unavailable (HTTP 503: d)");
    }

    #[test]
    fn advertised_fix_ignores_matches_without_fix() {
        // safe_version returns None here; the advertised fix still surfaces.
        assert_eq!(
            advertised_fix(&[vm("A-1", Some("2.0.0")), vm("A-2", None)]),
            Some("2.0.0".to_string())
        );
        assert_eq!(advertised_fix(&[vm("A-1", None)]), None);
        assert_eq!(advertised_fix(&[]), None);
    }

    #[test]
    fn advertised_fix_picks_highest_by_semver() {
        assert_eq!(
            advertised_fix(&[vm("A-1", Some("1.2.0")), vm("A-2", Some("1.10.0"))]),
            Some("1.10.0".to_string())
        );
    }

    /// Leftover origin assignment: pip `requested` ⇒ Requested; manifest
    /// direct dep ⇒ PreExisting; otherwise Transitive. Requested wins over
    /// a direct-dep hit.
    #[test]
    fn apply_verdicts_assigns_origins() {
        let pkg = |name: &str, requested: bool| tree::TreePackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            requested,
        };
        let results = vec![
            (pkg("reqdep", true), VerdictStatus::Clean),
            (pkg("predep", false), VerdictStatus::Clean),
            (pkg("deepdep", false), VerdictStatus::Clean),
        ];
        let direct_deps = std::collections::HashSet::from(["predep".to_string()]);
        let mut outcomes = [];
        let mut tree = apply_verdicts(PackageManager::Npm, results, &mut outcomes, &direct_deps);
        tree.sort_by(|a, b| a.name.cmp(&b.name));
        let origins: Vec<(&str, TreeOrigin)> =
            tree.iter().map(|t| (t.name.as_str(), t.origin)).collect();
        assert_eq!(
            origins,
            vec![
                ("deepdep", TreeOrigin::Transitive),
                ("predep", TreeOrigin::PreExisting),
                ("reqdep", TreeOrigin::Requested),
            ]
        );
    }

    /// The existing-tree refusal fires only when every vulnerable finding
    /// predates the command: a `Requested` finding (pip `-r`) is added by
    /// this command, and a `Transitive` finding is being pulled in right
    /// now unless the install is truly bare. `bare_install` is the explicit
    /// discriminator — a requirements-only install also has no named
    /// outcomes, but its resolved set is the command's doing.
    #[test]
    fn refusal_blame_respects_finding_origin() {
        let tree_vulnerable = |origin| TreeOutcome {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            verdict: VerdictStatus::Vulnerable(vec![vm("A-1", None)]),
            origin,
        };
        // (origin, named outcomes present, bare_install, expected).
        // (origin, named=false, bare=false) is the requirements-only shape.
        let cases = [
            (TreeOrigin::PreExisting, false, true, true),
            (TreeOrigin::PreExisting, false, false, true),
            (TreeOrigin::PreExisting, true, false, true),
            (TreeOrigin::Transitive, false, true, true),
            (TreeOrigin::Transitive, false, false, false),
            (TreeOrigin::Transitive, true, false, false),
            (TreeOrigin::Requested, false, true, false),
            (TreeOrigin::Requested, false, false, false),
            (TreeOrigin::Requested, true, false, false),
        ];
        for (origin, with_named, bare_install, blames_tree) in cases {
            let outcomes = if with_named {
                vec![resolved_outcome("cleanpkg", "1.0.0", false)]
            } else {
                vec![]
            };
            let mut report = report_with(outcomes);
            report.bare_install = bare_install;
            report.tree = Some(TreeReport::Full {
                resolved_count: 1,
                transitive: vec![tree_vulnerable(origin)],
                audit: None,
            });
            assert_eq!(
                refusal_blames_existing_tree(&report),
                blames_tree,
                "origin {origin:?}, with_named {with_named}, bare {bare_install}"
            );
        }
    }

    /// Unverifiable tree findings block too (`should_block_install`), so
    /// they must pass the same origin test before the refusal may blame the
    /// existing tree: a command-added unverifiable transitive alongside a
    /// pre-existing vulnerable dep keeps the generic refusal on a named
    /// install, while on a bare install everything still predates the
    /// command.
    #[test]
    fn refusal_blame_considers_unverifiable_tree_findings() {
        let tree_finding = |name: &str, verdict, origin| TreeOutcome {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            verdict,
            origin,
        };
        let mixed_tree = || {
            Some(TreeReport::Full {
                resolved_count: 2,
                transitive: vec![
                    tree_finding(
                        "stickydep",
                        VerdictStatus::Vulnerable(vec![vm("A-1", None)]),
                        TreeOrigin::PreExisting,
                    ),
                    tree_finding(
                        "newdep",
                        VerdictStatus::Unverifiable("vuln-api unavailable".to_string()),
                        TreeOrigin::Transitive,
                    ),
                ],
                audit: None,
            })
        };

        // Named install: the unverifiable transitive is being added by this
        // command, so "none were added by this command" would lie.
        let mut report = report_with(vec![resolved_outcome("cleanpkg", "1.0.0", false)]);
        report.tree = mixed_tree();
        assert!(!refusal_blames_existing_tree(&report));

        // Bare install: nothing named, everything resolved predates the
        // command — the mixed findings still blame the existing tree.
        let mut report = report_with(vec![]);
        report.bare_install = true;
        report.tree = mixed_tree();
        assert!(refusal_blames_existing_tree(&report));
    }
}
