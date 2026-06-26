//! Report rendering: text output, refusal line, fix/steer helpers.

use crate::verify_deps;

use super::{
    PackageManager, PrecheckOptions, PrecheckReport, TargetOutcome, TreeOrigin, TreeReport,
    VerdictStatus,
};

/// Reason recorded on resolved targets when no verdict pass ran.
const NO_VERDICT_REASON: &str = "vulnerability verdict not checked";

/// Version stamped on every `--json` document Corgea owns on stdout — the
/// report body and every blocking `{"error"}` / `{"warning"}` document — so
/// machine consumers can branch on the shape across install-gate phases.
pub(super) const SCHEMA_VERSION: u32 = 1;

/// One honest stderr line when a zero-spec install can't be gated:
/// yarn/pnpm/uv have no safe dry-run, so a bare install pulls its whole
/// dependency set unchecked. No-op for other managers (bare npm is gated
/// via the tree pass; bare pip installs nothing).
pub(super) fn bare_install_note(manager: PackageManager, subcommand_label: &str) {
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

/// The refusal line on stderr. Messaging only; the block decision and the
/// choice of escape hatch live in `verdict::block_reason`.
///
/// Each block also prints the concrete escape invocation (`corgea npm --force
/// install …`). Wrapper flags are read *between* the manager and the verb, so a
/// `--force` typed after the verb is swallowed by clap's trailing-var-arg and
/// forwarded to the package manager — the gate never sees it. When that
/// misplacement is detected, a `note:` line spells out why the flag had no effect.
pub(super) fn print_refusal(reason: super::verdict::BlockReason, report: &PrecheckReport) {
    use super::verdict::BlockReason;
    match reason {
        BlockReason::ExistingTree => eprintln!(
            "Refusing to run install: your existing dependency tree has known-vulnerable packages (none were added by this command). Fix them or pass --force."
        ),
        BlockReason::Findings => {
            eprintln!("Refusing to run install. Pass --force to proceed despite findings.")
        }
        BlockReason::Recency { threshold_days } => {
            eprintln!(
                "Refusing to run install: package(s) published within the {threshold_days}-day recency window."
            );
            for o in super::verdict::fresh_named_targets(report, threshold_days) {
                if let TargetOutcome::Resolved {
                    resolved,
                    age: Some(age),
                    ..
                } = o
                {
                    eprintln!(
                        "  ✗ {}@{} published {} ago",
                        resolved.name,
                        resolved.version,
                        verify_deps::format_duration(*age),
                    );
                }
            }
            eprintln!(
                "  turn off the recency gate with `recency_gate = false` in ~/.corgea/config.toml"
            );
        }
    }
    print_escape_hint(report);
}

/// Spell out the concrete `--force` escape command, and — when `--force` was
/// typed after the install verb — explain that the package manager, not
/// Corgea, received it.
fn print_escape_hint(report: &PrecheckReport) {
    let flag = "--force";
    // `--force` sitting in the forwarded args was typed after the verb — clap
    // handed it to the package manager, not us.
    let misplaced = report
        .original_args
        .iter()
        .any(|a| a.as_str() == flag)
        .then_some(flag);

    let manager = report.manager.binary_name();
    if let Some(typed) = misplaced {
        eprintln!("  note: `{typed}` after the verb was passed to {manager}, not corgea.");
    }
    // Rebuild the command with `--force` in the slot Corgea reads — between
    // the manager and the verb — dropping a misplaced copy from the tail.
    let rest: Vec<&str> = report
        .original_args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != flag)
        .collect();
    let mut corrected = format!("corgea {manager} {flag} {}", report.subcommand);
    if !rest.is_empty() {
        corrected.push(' ');
        corrected.push_str(&rest.join(" "));
    }
    eprintln!("  bypass the gate with: {corrected}");
}

pub(super) fn warn_public_lookup_failures(report: &PrecheckReport, opts: &PrecheckOptions) {
    if super::verdict::public_verdict(opts).is_some() && report.unverifiable_count() > 0 {
        eprintln!("warning: CVE check unavailable; continuing because public mode is fail-open.");
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
            let mut parsed = Vec::with_capacity(many.len());
            for raw in many {
                match semver::Version::parse(&verify_deps::registry::normalize_for_semver(raw)) {
                    Ok(v) => parsed.push((v, *raw)),
                    Err(_) if all_must_parse => return None,
                    Err(_) => {}
                }
            }
            parsed
                .into_iter()
                .max_by(|(a, _), (b, _)| a.cmp(b))
                .map(|(_, raw)| raw.to_string())
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

/// Per-match advisory lines plus the safe-version steer, shared by the
/// named-target and transitive vulnerable render arms. Built for agent
/// self-correction: each advisory carries `fixed in <version>`, and the
/// steer names the exact spec to install instead.
fn print_vulnerable_matches(name: &str, matches: &[crate::vuln_api::VulnMatch]) {
    for m in matches {
        println!(
            "      {} ({}){}",
            m.advisory_id,
            m.severity_level,
            fix_note(m)
        );
    }
    if let Some(safe) = safe_version(matches) {
        println!("      → safe version: {name}@{safe}");
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

pub(super) fn print_text(report: &PrecheckReport) {
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

    println!("Pre-checking `{command}`");
    println!(
        "  {} ok, {}, {}, {} skipped, {} errors",
        report.ok_count(),
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
                        print_vulnerable_matches(&t.name, matches);
                        // A vulnerable dep the project already declares can be
                        // bumped directly — point at the fix as a command.
                        // When `safe_version` is `Some` it equals
                        // `advertised_fix` and clears every advisory; otherwise
                        // some advisory has no fix, so the "(advertised fix)"
                        // hedge marks the bump as partial.
                        if t.origin == TreeOrigin::PreExisting {
                            if let Some(fix) = advertised_fix(matches) {
                                let hedge = if safe_version(matches).is_some() {
                                    ""
                                } else {
                                    " (advertised fix)"
                                };
                                println!(
                                    "      fix with: corgea {} install {}@{}{}",
                                    report.manager.binary_name(),
                                    t.name,
                                    fix,
                                    hedge
                                );
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
                    print_vulnerable_matches(&resolved.name, matches);
                }
                VerdictStatus::Unverifiable(error) => {
                    if !is_collapsed(error) {
                        println!(
                            "  ⚠ {} → {}@{}  could not be verified: {}",
                            target.display, resolved.name, resolved.version, error,
                        );
                    }
                }
                // `age` is `None` when pip backtracked the named target to a
                // version we never resolved — its publish date is unknown, so
                // show the version without a (wrong) provenance line.
                VerdictStatus::Clean | VerdictStatus::NotChecked => match age {
                    Some(age) => println!(
                        "  ✓ {} → {}@{}  published {} ago at {}",
                        target.display,
                        resolved.name,
                        resolved.version,
                        verify_deps::format_duration(*age),
                        resolved.published_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    ),
                    None => println!(
                        "  ✓ {} → {}@{}  publish date unavailable",
                        target.display, resolved.name, resolved.version,
                    ),
                },
            },
            TargetOutcome::Skipped { target, reason } => {
                println!("  ? {}: {}", target.display, reason);
            }
            TargetOutcome::Error { target, error } => {
                // Be explicit that an unresolvable target was NOT vetted:
                // without this line a resolution failure followed by a
                // proceeding install reads like a pass.
                println!(
                    "  ✗ {}: {} (not verified — this target is ungated)",
                    target.display, error
                );
            }
        }
    }
}

impl TreeOrigin {
    fn json_name(self) -> &'static str {
        match self {
            TreeOrigin::Transitive => "transitive",
            TreeOrigin::Requested => "requested",
            TreeOrigin::PreExisting => "pre-existing",
            TreeOrigin::Locked => "locked",
        }
    }
}

/// JSON shape for a single verdict. Shared by named outcomes and tree
/// (transitive) outcomes so both render verdicts identically.
/// `remediation` carries the version that clears every advisory
/// (`safe_version`); `null` when any advisory has no known fix.
fn verdict_json(verdict: &VerdictStatus) -> serde_json::Value {
    use serde_json::json;
    match verdict {
        VerdictStatus::Clean => json!({ "status": "clean" }),
        VerdictStatus::Vulnerable(matches) => {
            json!({
                "status": "vulnerable",
                "matches": matches,
                "remediation": safe_version(matches),
            })
        }
        VerdictStatus::Unverifiable(error) => {
            json!({ "status": "unverifiable", "error": error })
        }
        VerdictStatus::NotChecked => {
            json!({ "status": "not_checked", "reason": NO_VERDICT_REASON })
        }
    }
}

/// Verdict tallies for one scope, keyed identically so each summary
/// sub-object reconciles against its own array (`named` ↔ `results`,
/// `tree` ↔ `tree.transitive`).
#[derive(Default)]
struct VerdictCounts {
    clean: usize,
    vulnerable: usize,
    unverifiable: usize,
    not_checked: usize,
}

fn verdict_counts<'a>(verdicts: impl Iterator<Item = &'a VerdictStatus>) -> VerdictCounts {
    let mut c = VerdictCounts::default();
    for v in verdicts {
        match v {
            VerdictStatus::Clean => c.clean += 1,
            VerdictStatus::Vulnerable(_) => c.vulnerable += 1,
            VerdictStatus::Unverifiable(_) => c.unverifiable += 1,
            VerdictStatus::NotChecked => c.not_checked += 1,
        }
    }
    c
}

pub(super) fn print_json(report: &PrecheckReport, opts: &PrecheckOptions) {
    use serde_json::json;
    let verdict_mode = match opts.verdict.as_ref().map(|cfg| &cfg.mode) {
        Some(super::VerdictMode::Public) => "public",
        Some(super::VerdictMode::Authenticated { .. }) => "authenticated",
        None => "none",
    };
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
                let verdict_json = verdict_json(verdict);
                // `null` when pip backtracked to a version we never resolved:
                // the publish date belonged to the CLI-resolved version, not
                // what installs, so we drop it rather than report a wrong one.
                let (published_at, age_seconds) = match age {
                    Some(age) => (
                        json!(resolved.published_at.to_rfc3339()),
                        json!(age.as_secs()),
                    ),
                    None => (serde_json::Value::Null, serde_json::Value::Null),
                };
                json!({
                    "status": "ok",
                    "spec": target.display,
                    "name": resolved.name,
                    "resolved_version": resolved.version,
                    "published_at": published_at,
                    "age_seconds": age_seconds,
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

    // Summary counts are split by scope so each sub-object reconciles
    // against its own array: `named` covers the targets this command
    // adds (the `results` array), `tree` covers the resolved would-install
    // set beyond them (`tree.transitive`). A flat summary mixed the two —
    // e.g. `npm ci` has no named outcomes, so a clean lockfile read as
    // all-zero despite a fully-checked tree.
    let named_counts = verdict_counts(report.named_verdicts());
    let tree_counts = verdict_counts(report.tree_verdicts());
    let tree_resolved = match &report.tree {
        Some(TreeReport::Full { resolved_count, .. }) => *resolved_count,
        Some(TreeReport::NamedOnly { .. }) | None => 0,
    };
    let body = json!({
        "schema_version": SCHEMA_VERSION,
        "manager": report.manager.binary_name(),
        "subcommand": report.subcommand,
        "args": report.original_args,
        "summary": {
            "named": {
                "ok": report.ok_count(),
                "vulnerable": named_counts.vulnerable,
                "unverifiable": named_counts.unverifiable,
                "clean": named_counts.clean,
                "not_checked": named_counts.not_checked,
                "skipped": report.skipped_count(),
                "errors": report.error_count(),
            },
            "tree": {
                "resolved_count": tree_resolved,
                "vulnerable": tree_counts.vulnerable,
                "unverifiable": tree_counts.unverifiable,
                "clean": tree_counts.clean,
                "not_checked": tree_counts.not_checked,
            },
        },
        "verdict_mode": verdict_mode,
        // `null` when the recency gate is off; consumers pair it with each
        // result's `age_seconds` to see which named targets tripped it.
        "recency_threshold_days": opts.recency.as_ref().map(|r| r.threshold_days),
        "results": outcomes,
        "tree": report.tree.as_ref().map(|t| match t {
            TreeReport::Full { resolved_count, transitive } => json!({
                "mode": "full",
                "reason": serde_json::Value::Null,
                "resolved_count": resolved_count,
                "transitive": transitive.iter().map(|o| json!({
                    "name": o.name,
                    "version": o.version,
                    "origin": o.origin.json_name(),
                    "verdict": verdict_json(&o.verdict),
                })).collect::<Vec<_>>(),
            }),
            TreeReport::NamedOnly { reason } => json!({
                "mode": "named-only",
                "reason": reason,
                "resolved_count": 0,
                "transitive": [],
            }),
        }),
    });

    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::TreeOutcome;
    use super::*;

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
            let mut o = resolved_outcome(name, "1.0.0");
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
}
