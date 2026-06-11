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

mod detect;
mod exec;
mod render;

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

    fn is_authenticated(&self) -> bool {
        matches!(self, VerdictMode::Authenticated { .. })
    }

    fn is_public(&self) -> bool {
        matches!(self, VerdictMode::Public)
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

fn run_uv(cmd: &[String], opts: PrecheckOptions) -> i32 {
    let exec = || exec::exec_command("uv", cmd);

    if matches!(cmd.first().map(String::as_str), Some("install" | "i")) {
        eprintln!("{}", unsupported_uv_install_message(&cmd[1..]));
        return 1;
    }

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
        parse::UvCommand::Add { add_args } => {
            let parsed = parse::parse_pypi_positionals_args(add_args);
            if let Some(message) =
                detect::wrong_package_manager_message(PackageManager::Uv, add_args, &parsed)
            {
                eprintln!("{message}");
                return 1;
            }
            run_parsed_install(PackageManager::Uv, "add", add_args, parsed, exec, opts)
        }
        parse::UvCommand::Sync => run_uv_sync(cmd, opts, exec),
    }
}

fn unsupported_uv_install_message(rest: &[String]) -> String {
    format!(
        "error: uv does not support top-level `install`.\nDid you mean `{}`?",
        corgea_cmd(&["uv", "pip", "install"], rest)
    )
}

/// Gate `uv sync` from the project's `uv.lock`. The lockfile is the full
/// locked universe (all groups/extras) — a superset of what sync installs,
/// conservative in the blocking direction; a stale lock that sync would
/// re-resolve is gated as written. Recency isn't checked (locked versions
/// aren't newly chosen by this command); the verdict pass is the gate. We
/// never run `uv lock` ourselves — locking can build sdists, which would
/// execute package code before any verdict.
fn run_uv_sync(cmd: &[String], opts: PrecheckOptions, exec: impl FnOnce() -> i32) -> i32 {
    let Some(cfg) = &opts.verdict else {
        // Direct callers may still disable verdicts completely.
        return exec();
    };
    let lock = match std::fs::read_to_string("uv.lock") {
        Ok(content) => content,
        Err(_) => {
            eprintln!(
                "note: no uv.lock here — 'uv sync' is not gated; dependencies install unchecked (run 'uv lock' first to enable the gate)"
            );
            return exec();
        }
    };
    let jobs = match parse_uv_lock(&lock) {
        Ok(jobs) => jobs,
        Err(e) if opts.force => {
            eprintln!("warning: cannot verify 'uv sync' ({e}); proceeding under --force");
            return exec();
        }
        Err(e) => {
            eprintln!("error: cannot verify 'uv sync': {e} (pass --force to proceed unchecked)");
            return 1;
        }
    };

    let resolved_count = jobs.len();
    let results = verdict_pool(jobs, cfg, PackageManager::Uv, VERDICT_CONCURRENCY);
    let transitive = results
        .into_iter()
        .map(|(pkg, verdict)| TreeOutcome {
            name: pkg.name,
            version: pkg.version,
            origin: TreeOrigin::Locked,
            verdict,
        })
        .collect();
    let report = PrecheckReport {
        manager: PackageManager::Uv,
        subcommand: "sync".to_string(),
        original_args: cmd[1..].to_vec(),
        outcomes: Vec::new(),
        threshold: opts.threshold,
        tree: Some(TreeReport::Full {
            resolved_count,
            transitive,
        }),
        bare_install: true,
    };

    report_and_exec(&report, &opts, exec)
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
    if should_block_install(report, opts) {
        if !opts.json {
            render::print_refusal(report, opts);
        }
        return 1;
    }
    exec()
}

/// Packages from `uv.lock` that `uv sync` installs from an index. Local
/// stanzas (the project itself and path deps: editable / virtual /
/// directory / path sources) carry no registry identity and are skipped.
fn parse_uv_lock(content: &str) -> Result<Vec<tree::TreePackage>, String> {
    #[derive(serde::Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Pkg>,
    }
    #[derive(serde::Deserialize)]
    struct Pkg {
        name: String,
        version: Option<String>,
        #[serde(default)]
        source: std::collections::BTreeMap<String, toml::Value>,
    }
    const LOCAL_SOURCES: [&str; 4] = ["editable", "virtual", "directory", "path"];

    let lock: Lock = toml::from_str(content).map_err(|e| format!("parse uv.lock: {e}"))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| !LOCAL_SOURCES.iter().any(|k| p.source.contains_key(*k)))
        .filter_map(|p| {
            Some(tree::TreePackage {
                name: p.name,
                version: p.version?,
                requested: false,
            })
        })
        .collect())
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
        let outcomes: Vec<_> = parsed
            .targets
            .iter()
            .map(|target| verify_one(target, &opts, &now))
            .collect();
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
        .is_some_and(|cfg| cfg.mode.is_public() && cfg.public_login_hint)
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
    resolution: Result<Option<Vec<tree::TreePackage>>, String>,
    outcomes: &mut [TargetOutcome],
    opts: &PrecheckOptions,
) -> TreeReport {
    let set = match resolution {
        Ok(Some(set)) => set,
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
    let transitive = apply_verdicts(manager, results, outcomes, &direct_deps);
    TreeReport::Full {
        resolved_count,
        transitive,
    }
}

/// Above this many verdict jobs, print a stderr progress line so a big tree
/// pass doesn't look hung.
const VERDICT_PROGRESS_THRESHOLD: usize = 8;

/// Max parallel vuln-api verdict requests.
const VERDICT_CONCURRENCY: usize = 8;

/// Bounded worker pool over the verdict jobs. On client/request failure every
/// job comes back `Unverifiable`; `should_block_install` decides whether that
/// fails closed for the selected mode.
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
                // vuln-api advisories are keyed by canonical names; an
                // alternate spelling (PEP 503: `Flask_Cors` ≡ `flask-cors`)
                // would miss and read as clean.
                let verdict = match crate::vuln_api::check_package_version(
                    &client,
                    &cfg.base_url,
                    cfg.mode.auth_token(),
                    ecosystem,
                    &manager.normalize_name(&job.name),
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
/// worker pool. No-op without a `VerdictConfig` (direct recency-only callers).
/// Any client/call failure becomes `Unverifiable`; authenticated mode blocks
/// on that and public mode warns but continues.
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
    let leftovers = apply_verdicts(manager, results, outcomes, &Default::default());
    debug_assert!(
        leftovers.is_empty(),
        "named verdict pass left tree leftovers"
    );
}

fn authenticated_verdict(opts: &PrecheckOptions) -> bool {
    opts.verdict
        .as_ref()
        .is_some_and(|cfg| cfg.mode.is_authenticated())
}

fn public_verdict(opts: &PrecheckOptions) -> bool {
    opts.verdict
        .as_ref()
        .is_some_and(|cfg| cfg.mode.is_public())
}

fn should_block_install(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
    if opts.force {
        return false;
    }
    // A resolution error means no verdict was obtained for that target, so
    // in authenticated mode it fails closed like `Unverifiable` — otherwise a
    // registry outage silently bypasses the gate.
    let fail_closed = authenticated_verdict(opts);
    report.vulnerable_count() > 0
        || (fail_closed && report.unverifiable_count() > 0)
        || (fail_closed && report.error_count() > 0)
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

    #[test]
    fn parse_uv_lock_keeps_index_packages_and_skips_local_sources() {
        let lock = r#"
version = 1

[[package]]
name = "proj"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "evildep"
version = "0.4.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "gitdep"
version = "1.2.3"
source = { git = "https://example.com/repo?rev=abc#abc" }
"#;
        let pkgs = parse_uv_lock(lock).expect("parse uv.lock");
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["evildep", "gitdep"]);
        assert_eq!(pkgs[0].version, "0.4.2");
    }

    #[test]
    fn parse_uv_lock_rejects_invalid_toml() {
        let err = parse_uv_lock("not = [valid").expect_err("invalid toml");
        assert!(err.contains("parse uv.lock"), "got: {err}");
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

    /// Predicate matrix: force ⇒ never block; vulnerable blocks in every
    /// verdict mode; unverifiable/error findings block only in authenticated
    /// mode; recency keeps its task-2 --no-fail demotion.
    #[test]
    fn block_predicate_matrix() {
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
        let resolution_error = report_with(vec![TargetOutcome::Error {
            target: InstallTarget {
                name: "pkg".to_string(),
                display: "pkg==1.0.0".to_string(),
                kind: TargetKind::Unverifiable {
                    reason: "test".to_string(),
                },
            },
            error: "registry unavailable".to_string(),
        }]);

        assert!(!should_block_install(&clean, &public_opts(false, false)));
        assert!(should_block_install(&recent, &public_opts(false, false)));
        assert!(!should_block_install(&recent, &public_opts(true, false)));
        assert!(should_block_install(
            &vulnerable,
            &public_opts(false, false)
        ));
        assert!(
            should_block_install(&vulnerable, &public_opts(true, false)),
            "--no-fail must not waive a vulnerable block"
        );
        assert!(
            !should_block_install(&unverifiable, &public_opts(false, false)),
            "public mode must fail open on lookup errors"
        );
        assert!(
            should_block_install(&unverifiable, &authenticated_opts(true, false)),
            "authenticated mode must fail closed on lookup errors"
        );
        assert!(
            !should_block_install(&resolution_error, &public_opts(false, false)),
            "public mode must fail open when no verdict can be obtained"
        );
        assert!(
            should_block_install(&resolution_error, &authenticated_opts(false, false)),
            "authenticated mode must fail closed when no verdict can be obtained"
        );
        for report in [
            &clean,
            &recent,
            &vulnerable,
            &unverifiable,
            &resolution_error,
        ] {
            assert!(
                !should_block_install(report, &public_opts(false, true)),
                "--force must never block"
            );
            assert!(!should_block_install(
                report,
                &authenticated_opts(true, true)
            ));
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
            mode: VerdictMode::Authenticated {
                token: "test-token".to_string(),
            },
            public_login_hint: false,
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
}
