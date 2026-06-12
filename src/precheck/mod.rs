//! Install wrappers: `corgea npm`, `corgea yarn`, `corgea pnpm`,
//! `corgea pip`, `corgea uv`.
//!
//! Wraps an install command from a supported package manager, resolves what
//! the package manager *would* install against the public registry, and
//! either blocks the install or runs it transparently.
//!
//! Two independent blocks:
//!   * recency — the resolved version was published within `--threshold`
//!     (default `2d`); `--no-fail` demotes this to a warning;
//!   * vuln verdict — the vuln-api knows a resolved version (named or
//!     transitive) is vulnerable or malicious; only `--force` overrides this.
//!
//! Verdict lookups are public and fail open: a vuln-api outage warns and the
//! install continues.

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
            // npm's install command accepts a wide alias set (and tolerates
            // common typos). Mirror npm's own `lib/utils/cmd-list.js` exactly
            // so none falls through to the ungated passthrough. `npm ci` and
            // its aliases are gated separately, *before* this check (see
            // `run_install`), so they are intentionally absent here.
            PackageManager::Npm => matches!(
                sub,
                "install"
                    | "i"
                    | "in"
                    | "ins"
                    | "inst"
                    | "insta"
                    | "instal"
                    | "isnt"
                    | "isnta"
                    | "isntal"
                    | "isntall"
                    | "add"
            ),
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
    /// "blocking finding", shared by `verdict::block_reason` and the
    /// refusal-blame predicate.
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
    /// Pinned by the project's lockfile (`npm ci`).
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
/// never ran (verdicts disabled, or nothing to resolve).
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
        self.verdicts()
            .filter(|v| matches!(v, VerdictStatus::Vulnerable(_)))
            .count()
    }
    pub fn unverifiable_count(&self) -> usize {
        self.verdicts()
            .filter(|v| matches!(v, VerdictStatus::Unverifiable(_)))
            .count()
    }
    /// Vulnerable findings beyond the named targets (the resolved tree).
    pub fn tree_vulnerable_count(&self) -> usize {
        self.tree_verdicts()
            .filter(|v| matches!(v, VerdictStatus::Vulnerable(_)))
            .count()
    }
    /// Unverifiable findings beyond the named targets (the resolved tree).
    pub fn tree_unverifiable_count(&self) -> usize {
        self.tree_verdicts()
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
    if manager == PackageManager::Uv {
        return uv::run_uv(cmd, opts);
    }

    if cmd.is_empty() {
        // Bare `yarn` IS `yarn install` — route it through the install
        // path so the bare-install note prints instead of a silent exec.
        if manager == PackageManager::Yarn {
            let install = ["install".to_string()];
            return run_install(manager, &install, opts);
        }
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

    // `npm ci` installs the lockfile exactly as written — gate it from the
    // project lockfile directly.
    if manager == PackageManager::Npm
        && matches!(
            subcommand.as_str(),
            "ci" | "ic" | "clean-install" | "install-clean" | "isntall-clean"
        )
    {
        return run_npm_ci(subcommand, rest, opts);
    }

    if !manager.is_install_subcommand(subcommand) {
        // Non-install subcommand: transparent passthrough, args untouched —
        // but `yarn global add` installs from the registry, so disclose
        // that it isn't gated rather than pass silently.
        if manager == PackageManager::Yarn
            && subcommand == "global"
            && cmd.get(verb_idx + 1).map(String::as_str) == Some("add")
        {
            eprintln!("note: 'yarn global add' is not gated; packages install unchecked");
        }
        return exec::exec_command(manager.binary_name(), cmd);
    }

    let parsed = match parse::parse_install_args(manager, rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to parse install args: {}", e);
            return 2;
        }
    };

    warn_registry_override(manager, rest, None);

    // Project guard. `--force` (documented as overriding every block) is
    // the escape hatch — a stray ancestor lockfile must not leave the
    // command permanently refused.
    if !opts.force {
        if let Some(message) = detect::wrong_package_manager_message(manager, rest, &parsed) {
            eprintln!("{message}");
            return 1;
        }
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

/// Warn when a custom registry/index is selected — via CLI flag or, for npm,
/// the project `.npmrc`. The gate resolves and verdicts against the default
/// (env/public) registry, so it cannot vouch that the artifact the manager
/// pulls from the override matches the advisory universe. Resolving against
/// the override (and multi-index cases like `--extra-index-url`) is a
/// documented limitation — registry allow-listing is future work, separate
/// PRD.
///
/// pip config-file (`pip.conf`) and `PIP_INDEX_URL`-style env detection is
/// future work: only pip CLI index flags are inspected here.
fn warn_registry_override(
    manager: PackageManager,
    rest: &[String],
    npm_root: Option<&std::path::Path>,
) {
    let flags: &[&str] = match manager {
        PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm => &["--registry"],
        PackageManager::Pip | PackageManager::Uv => &[
            "-i",
            "--index-url",
            "--extra-index-url",
            "--index",
            "--default-index",
            "-f",
            "--find-links",
        ],
    };
    if let Some(flag) = rest.iter().find(|a| {
        flags
            .iter()
            .any(|f| a.as_str() == *f || a.starts_with(&format!("{f}=")))
    }) {
        eprintln!(
            "warning: '{flag}' points {} at a custom registry/index; the gate resolves and verdicts against the default registry and cannot vouch the installed artifact matches.",
            manager.binary_name()
        );
    }

    // A project `.npmrc` `registry=` / `@scope:registry=` line redirects
    // resolution just like the CLI flag, but silently — the tree pass copies
    // the `.npmrc` into its temp dir so resolution honours it, so the verdict
    // would still be against the default advisory universe with no flag in
    // `rest` to catch. Warn on it so the redirect isn't silent.
    if manager == PackageManager::Npm {
        if let Some(path) = npmrc_registry_override_path(npm_root) {
            eprintln!(
                "warning: '{}' sets a custom registry; the gate resolves and verdicts against the default registry and cannot vouch the installed artifact matches.",
                path.display()
            );
        }
    }
}

/// The first `.npmrc` (CWD, then the npm project root) holding a `registry=`
/// or `@<scope>:registry=` line, if any. Best-effort: an absent or unreadable
/// `.npmrc` yields `None` — it can't redirect resolution if it can't be read.
///
/// `npm_root` lets a caller that already resolved the project root pass it in
/// so `tree::npm_project_root()` isn't walked twice (e.g. `run_npm_ci`); `None`
/// resolves it here.
fn npmrc_registry_override_path(npm_root: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok();
    // CWD first, then the project root npm would actually operate on; skip the
    // root when it equals the CWD so the same file isn't checked twice.
    let mut candidates: Vec<std::path::PathBuf> = cwd.iter().map(|d| d.join(".npmrc")).collect();
    let root = npm_root
        .map(std::path::Path::to_path_buf)
        .or_else(tree::npm_project_root);
    if let Some(root) = root {
        if cwd.as_deref() != Some(root.as_path()) {
            candidates.push(root.join(".npmrc"));
        }
    }
    candidates.into_iter().find(|path| {
        std::fs::read_to_string(path)
            .map(|c| npmrc_has_registry_override(&c))
            .unwrap_or(false)
    })
}

/// Does this `.npmrc` content select a custom registry? True when an
/// uncommented line's key is `registry` or ends with `:registry` (the
/// `@<scope>:registry=...` form). `.npmrc` is INI-ish `key=value`; lines
/// starting with `;` or `#` are comments.
fn npmrc_has_registry_override(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            return false;
        }
        let Some((key, _)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim();
        key == "registry" || key.ends_with(":registry")
    })
}

/// Shared tail of every gated path: render the report, refuse (exit 1) when
/// the block predicate fires, otherwise run the install.
fn report_and_exec(
    report: &PrecheckReport,
    opts: &PrecheckOptions,
    exec: impl FnOnce() -> i32,
) -> i32 {
    render::print_text(report);
    render::warn_public_lookup_failures(report, opts);
    if let Some(reason) = verdict::block_reason(report, opts) {
        render::print_refusal(reason);
        return 1;
    }
    exec()
}

/// Refuse an install the gate cannot verify *before* it can build a
/// `PrecheckReport` — so the decision can't run through `block_reason`. Prints a
/// uniform `cannot verify … (pass --force …)` line and exits 1; `--force` is the
/// single escape. These pre-report refusals are the deliberate, enumerated
/// exceptions to the "all blocking goes through `block_reason`" rule. Callers:
/// the bare-`npm install` and `npm ci` root-redirect guards (a redirected
/// project's tree can't be resolved from a copy of the CWD) and the `npm ci`
/// unparsable-lockfile guard (no lockfile to verdict).
fn refuse_unverifiable(detail: &str) -> i32 {
    eprintln!("error: cannot verify {detail} (pass --force to proceed unchecked)");
    1
}

/// Collapse a tree-resolution thread's join into the resolver's own `Result`.
/// A panic in the spawned thread becomes a resolution `Err` (which the caller
/// routes to the named-only fallback with a loud warning) instead of
/// re-panicking on the main thread. The gate's verdict path fails open, so an
/// unexpected resolver bug must degrade coverage, never abort the user's
/// install. (We join the handle, so `thread::scope` treats the panic as handled
/// and does not re-propagate it.)
fn tree_resolution_from_join(
    join: std::thread::Result<Result<Vec<tree::TreePackage>, String>>,
) -> Result<Vec<tree::TreePackage>, String> {
    join.unwrap_or_else(|_| Err("tree resolution panicked".to_string()))
}

/// Post-parse verification shared by the npm and pip install paths.
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

    // A BARE `npm install --prefix <other>` installs another project's whole
    // tree, but the gate can't safely resolve that redirected root from a copy
    // of the CWD. Nothing named verifies it either, so it would install wholly
    // unchecked — fail closed unless `--force`. (A NAMED install still verifies
    // its targets and degrades the tree pass to a loud named-only warning.)
    if manager == PackageManager::Npm && bare_install && opts.verdict.is_some() && !opts.force {
        if let Some(flag) = tree::npm_root_redirect_flag(rest) {
            return refuse_unverifiable(&format!(
                "a bare 'npm install' that redirects the project root ('{flag}'): the would-install tree is unknown"
            ));
        }
    }

    if parsed.targets.is_empty() && !tree_eligible {
        // Only a truly bare install gets the bare note. A `-r requirements.txt`
        // install is covered by `requirements_note`.
        if bare_install {
            render::bare_install_note(manager, subcommand_label);
        }
        // One bare-npm case lands here not because there's nothing to gate but
        // because the project root couldn't be resolved at all: an unreadable
        // CWD makes `npm_project_root()` (via `find_up`) return None, so
        // `covers_input` is false. Say so loudly instead of skipping the gate
        // silently. (npm will most likely fail on the same unreadable CWD; the
        // warning explains why nothing was verified.)
        if manager == PackageManager::Npm
            && opts.verdict.is_some()
            && std::env::current_dir().is_err()
        {
            eprintln!(
                "warning: cannot determine the npm project (current directory is unreadable); proceeding without tree verification."
            );
        }
        render::requirements_note(&parsed);
        return exec();
    }

    // The named-target registry lookups and the tree dry-run are independent
    // network/subprocess work — overlap them; verdicts need both.
    let now = Utc::now();
    let (mut outcomes, tree_resolution) = std::thread::scope(|s| {
        let tree = tree_eligible.then(|| s.spawn(|| tree::resolve_tree(manager, rest, &parsed)));
        let outcomes = verdict::verify_all(&parsed.targets, &opts, &now, parsed.allow_prerelease);
        (
            outcomes,
            tree.map(|handle| tree_resolution_from_join(handle.join())),
        )
    });

    let tree = if let Some(resolution) = tree_resolution {
        Some(run_tree_pass(
            manager,
            resolution,
            &mut outcomes,
            &parsed,
            &opts,
            &now,
        ))
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
    // The note is recency-specific, and recency never covers requirements-file
    // packages: even under a Full tree pass they are verdicted but become
    // `TreeOutcome`s with no `age` (recency only blocks named CLI targets), so
    // the caveat applies in every path. `requirements_note` self-guards when
    // there are no `-r` files.
    render::requirements_note(&parsed);

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

/// Gate a lockfile-pinned install (`npm ci`, `uv sync`): verdict every
/// locked package. Recency isn't checked — locked versions aren't newly
/// chosen by this command; the verdict pass is the gate.
fn run_locked_install(
    manager: PackageManager,
    subcommand: &str,
    original_args: Vec<String>,
    lock: Result<Vec<tree::TreePackage>, String>,
    opts: &PrecheckOptions,
    exec: impl FnOnce() -> i32,
) -> i32 {
    let Some(cfg) = &opts.verdict else {
        // Direct callers may still disable verdicts completely.
        return exec();
    };
    let jobs = match lock {
        Ok(jobs) => jobs,
        Err(e) if opts.force => {
            eprintln!(
                "warning: cannot verify '{} {}' ({e}); proceeding under --force",
                manager.binary_name(),
                subcommand
            );
            return exec();
        }
        Err(e) => {
            // The single documented bypass of the "all blocking goes through
            // `verdict::block_reason`" invariant: an unparsable lockfile
            // means there is no report to feed the predicate, so the gate
            // refuses directly (--force above is the only escape).
            eprintln!(
                "error: cannot verify '{} {}': {e} (pass --force to proceed unchecked)",
                manager.binary_name(),
                subcommand
            );
            return 1;
        }
    };

    let resolved_count = jobs.len();
    let results = verdict::verdict_pool(jobs, cfg, manager);
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
        manager,
        subcommand: subcommand.to_string(),
        original_args,
        outcomes: Vec::new(),
        threshold: opts.threshold,
        tree: Some(TreeReport::Full {
            resolved_count,
            transitive,
        }),
        bare_install: true,
    };

    report_and_exec(&report, opts, exec)
}

/// `npm ci` (and aliases): installs the project lockfile exactly as
/// written, so the gate verdicts the lockfile-pinned set directly — no
/// dry-run needed. Without a project or lockfile npm errors on its own;
/// the gate just execs.
fn run_npm_ci(subcommand: &str, rest: &[String], opts: PrecheckOptions) -> i32 {
    let exec = || exec::exec_install_with_args(PackageManager::Npm, subcommand, rest);

    }
    // Resolve the project root once and reuse it for both the registry-override
    // warning (its `.npmrc` lookup) and the lockfile read below.
    let root = tree::npm_project_root();
    // `npm ci --registry <url>` (or a project `.npmrc` `registry=` line) pulls
    // tarballs from an override while the gate verdicts the lockfile against
    // the default registry — same false-assurance gap as the named-install
    // path, so warn here too.
    warn_registry_override(PackageManager::Npm, rest, root.as_deref());
    // A root-redirect flag (`--prefix ../other`, `-C ../other`) makes npm ci
    // install a DIFFERENT project's lockfile than the CWD one we'd verdict, so
    // verifying the CWD lockfile would pass on the wrong project. Fail closed
    // unless `--force`.
    if !opts.force {
        if let Some(flag) = tree::npm_root_redirect_flag(rest) {
            return refuse_unverifiable(&format!(
                "'npm {subcommand}' with '{flag}': it installs a redirected project's lockfile, not this one"
            ));
        }
    }
    let Some(root) = root else {
        return exec();
    };
    let Some(lock_path) = tree::npm_lockfile_in(&root) else {
        return exec();
    };

    let lock = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("read {}: {e}", lock_path.display()))
        .and_then(|content| tree::parse_npm_lockfile(&content));
    run_locked_install(
        PackageManager::Npm,
        subcommand,
        rest.to_vec(),
        lock,
        &opts,
        exec,
    )
}

/// Collapse repeated packages to one verdict job each, keyed on
/// `(normalize_name(name), version)`, preserving first-seen order. npm
/// lockfiles repeat the same name@version across nested `node_modules` paths
/// (v2/v3) and diamond deps (v1 `dependencies` tree), so verdicting the raw
/// parse would hit the vuln-api — and count the package — once per copy.
fn dedup_packages(manager: PackageManager, jobs: Vec<tree::TreePackage>) -> Vec<tree::TreePackage> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(jobs.len());
    for p in jobs {
        if seen.insert((manager.normalize_name(&p.name), p.version.clone())) {
            out.push(p);
        }
    }
    out
}

/// One verdict job (`requested: true`) per named resolved target, in
/// outcome order.
fn resolved_jobs(outcomes: &[TargetOutcome]) -> impl Iterator<Item = tree::TreePackage> + '_ {
    outcomes.iter().filter_map(|o| match o {
        TargetOutcome::Resolved { resolved, .. } => Some(tree::TreePackage {
            name: resolved.name.clone(),
            version: resolved.version.clone(),
            requested: true,
        }),
        _ => None,
    })
}

/// Verdict the resolved would-install set (`tree::resolve_tree`'s result).
/// On any resolution failure, fall back to the named-only verdict pass; the
/// caller renders the loud warning from the returned `NamedOnly` reason.
/// Only called when `opts.verdict.is_some()`.
fn run_tree_pass(
    manager: PackageManager,
    resolution: Result<Vec<tree::TreePackage>, String>,
    outcomes: &mut Vec<TargetOutcome>,
    parsed: &parse::ParsedInstall,
    opts: &PrecheckOptions,
    now: &chrono::DateTime<Utc>,
) -> TreeReport {
    let set = match resolution {
        Ok(set) => set,
        Err(reason) => {
            outcomes.extend(requirements_fallback_outcomes(manager, parsed, opts, now));
            run_verdict_pass(manager, outcomes, opts);
            return TreeReport::NamedOnly { reason };
        }
    };

    // Dedup the dry-run set (npm lockfiles repeat the same name@version at
    // multiple nested paths), then union in the named-resolved targets — a
    // named target already installed is absent from the dry-run delta but
    // must still be verdicted.
    let norm = |n: &str| manager.normalize_name(n);
    let mut jobs = dedup_packages(manager, set);
    let resolved_count = jobs.len();
    let mut seen: std::collections::HashSet<(String, String)> = jobs
        .iter()
        .map(|p| (norm(&p.name), p.version.clone()))
        .collect();
    // Names the pip dry-run already covers as `requested` (the user named
    // them). When pip backtracked one to a different version than the CLI's
    // `pypi_resolve` picked, the dry-run's installed version is authoritative;
    // `apply_verdicts` collapses it onto the named outcome. Unioning the CLI
    // version in too would queue a redundant job that re-matches and could
    // clobber that authoritative verdict, so skip it. npm jobs are never
    // `requested`, so this set is empty and the npm union is unchanged.
    let requested_names: std::collections::HashSet<String> = jobs
        .iter()
        .filter(|p| p.requested)
        .map(|p| norm(&p.name))
        .collect();
    for p in resolved_jobs(outcomes) {
        if requested_names.contains(&norm(&p.name)) {
            continue;
        }
        if seen.insert((norm(&p.name), p.version.clone())) {
            jobs.push(p);
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

fn requirements_fallback_outcomes(
    manager: PackageManager,
    parsed: &parse::ParsedInstall,
    opts: &PrecheckOptions,
    now: &chrono::DateTime<Utc>,
) -> Vec<TargetOutcome> {
    if !matches!(manager, PackageManager::Pip | PackageManager::Uv)
        || parsed.requirements_files.is_empty()
    {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut outcomes = Vec::new();
    for file in &parsed.requirements_files {
        match parse::parse_requirement_file_targets(file) {
            Ok(mut file_targets) => targets.append(&mut file_targets),
            Err(error) => outcomes.push(TargetOutcome::Error {
                target: InstallTarget {
                    name: file.display().to_string(),
                    display: file.display().to_string(),
                    kind: TargetKind::Unverifiable {
                        reason: "requirements file could not be read".to_string(),
                    },
                },
                error,
            }),
        }
    }

    outcomes.extend(verdict::verify_all(
        &targets,
        opts,
        now,
        parsed.allow_prerelease,
    ));
    outcomes
}

/// Vuln-api verdict pass over resolved targets, run through the bounded
/// worker pool. No-op without a `VerdictConfig` (recency-only callers).
/// Any client/call failure becomes `Unverifiable`, which warns but never
/// blocks: public lookups fail open.
fn run_verdict_pass(
    manager: PackageManager,
    outcomes: &mut [TargetOutcome],
    opts: &PrecheckOptions,
) {
    let Some(cfg) = &opts.verdict else { return };

    // One job per resolved target, in outcome order; the pool preserves
    // order, so verdicts zip straight back onto the resolved outcomes.
    let jobs: Vec<tree::TreePackage> = resolved_jobs(outcomes).collect();

    let mut results = verdict::verdict_pool(jobs, cfg, manager).into_iter();
    for o in outcomes.iter_mut() {
        if let TargetOutcome::Resolved { verdict, .. } = o {
            *verdict = match results.next() {
                Some((_, v)) => v,
                // Pool invariant broken — fail safe instead of panicking:
                // Unverifiable warns instead of silently reading as clean.
                None => VerdictStatus::Unverifiable(
                    "internal error: verdict pool returned fewer results than outcomes".to_string(),
                ),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn install_subcommand_recognition() {
        // The full npm install alias set (including common typos) must gate;
        // none may fall through to the ungated passthrough.
        // The full npm install alias set per `lib/utils/cmd-list.js`.
        for alias in [
            "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
            "isntall", "add",
        ] {
            assert!(
                PackageManager::Npm.is_install_subcommand(alias),
                "npm `{alias}` must route through the gate"
            );
        }
        assert!(!PackageManager::Npm.is_install_subcommand("update"));
        // `installation` is not a real npm alias, and `innit` maps to npm
        // `init` (not `install`) — neither must be treated as an install.
        assert!(!PackageManager::Npm.is_install_subcommand("installation"));
        assert!(!PackageManager::Npm.is_install_subcommand("innit"));
        // `npm ci` aliases are gated by a separate dispatch that runs before
        // this check, so they must NOT be recognized here.
        for ci_alias in [
            "ci",
            "ic",
            "clean-install",
            "install-clean",
            "isntall-clean",
        ] {
            assert!(
                !PackageManager::Npm.is_install_subcommand(ci_alias),
                "npm `{ci_alias}` is handled by run_npm_ci, not this check"
            );
        }

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
        // `-r reqs.txt` alone, verdicts disabled → printed note, no
        // verification, exec runs.
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
    fn diamond_lockfile_parse_then_dedup_counts_each_package_once() {
        // A v1 `dependencies` tree where the same package@version is nested
        // under two parents (a DIAMOND): `parent-a` and `parent-b` both pull
        // `shared@2.0.0`. parse_npm_lockfile returns it once per parent — the
        // dedup the npm-ci path applies is what collapses it. Without dedup
        // the shared package would be verdicted (and counted) twice.
        const DIAMOND: &str = r#"{
            "name": "proj", "lockfileVersion": 1,
            "dependencies": {
                "parent-a": {"version": "1.0.0", "dependencies": {
                    "shared": {"version": "2.0.0"}
                }},
                "parent-b": {"version": "1.0.0", "dependencies": {
                    "shared": {"version": "2.0.0"}
                }}
            }
        }"#;

        // parse_npm_lockfile returns duplicates by design (one row per tree
        // position): `shared@2.0.0` appears twice.
        let parsed = tree::parse_npm_lockfile(DIAMOND).expect("parse v1 diamond lock");
        let shared_in_parse = parsed
            .iter()
            .filter(|p| p.name == "shared" && p.version == "2.0.0")
            .count();
        assert_eq!(shared_in_parse, 2, "parse keeps one row per tree position");

        // Dedup (the run_npm_ci path) collapses it to a single verdict job, so
        // `resolved_count` and the verdict list count it once.
        let jobs = dedup_packages(PackageManager::Npm, parsed);
        assert_eq!(
            jobs.iter()
                .filter(|p| p.name == "shared" && p.version == "2.0.0")
                .count(),
            1,
            "dedup yields the diamond package exactly once"
        );
        assert_eq!(jobs.len(), 3, "parent-a, parent-b, shared — no duplicates");
    }

    #[test]
    fn npmrc_registry_override_detection() {
        // A bare `registry=` line is an override.
        assert!(npmrc_has_registry_override(
            "registry=https://evil.example/\n"
        ));
        // The scoped form `@<scope>:registry=` is too.
        assert!(npmrc_has_registry_override(
            "@acme:registry=https://evil.example/\n"
        ));
        // Surrounding config lines and whitespace don't hide it.
        assert!(npmrc_has_registry_override(
            "save-exact=true\n  registry = https://evil.example/\nfund=false\n"
        ));
        // Commented-out lines (; and #) don't count.
        assert!(!npmrc_has_registry_override(
            "; registry=https://evil.example/\n# @acme:registry=https://evil.example/\n"
        ));
        // No registry directive at all.
        assert!(!npmrc_has_registry_override(
            "save-exact=true\nfund=false\n"
        ));
        // A key that merely contains "registry" but isn't `registry` /
        // `:registry` (e.g. npm's auth keys) must not trip the warning.
        assert!(!npmrc_has_registry_override(
            "//evil.example/:_authToken=abc\nregistry-other=x\n"
        ));
        assert!(!npmrc_has_registry_override(""));
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

    #[test]
    fn tree_resolution_panic_becomes_err_not_abort() {
        // A panicking tree-resolution thread must degrade to a resolution Err
        // (→ named-only fallback), never re-panic on the caller.
        let panicked = std::thread::spawn(|| -> Result<Vec<tree::TreePackage>, String> {
            panic!("simulated resolver bug");
        });
        assert_eq!(
            tree_resolution_from_join(panicked.join()),
            Err("tree resolution panicked".to_string())
        );
        // A normal result passes straight through.
        let ok = std::thread::spawn(|| Ok(Vec::new()));
        assert_eq!(tree_resolution_from_join(ok.join()), Ok(Vec::new()));
    }
}
