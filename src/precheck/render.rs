//! Report rendering: text output, refusal line, fix/steer helpers.

use crate::verify_deps;

use super::{parse, PrecheckOptions, PrecheckReport, TargetOutcome, VerdictStatus};

/// The refusal line on stderr. Messaging only; the block decision and the
/// choice of escape hatch live in `verdict::block_reason`.
pub(super) fn print_refusal(reason: super::verdict::BlockReason) {
    use super::verdict::BlockReason;
    match reason {
        BlockReason::Findings => {
            eprintln!("Refusing to run install. Pass --force to proceed despite findings.")
        }
        BlockReason::RecencyOnly => {
            eprintln!("Refusing to run install. Pass --no-fail to proceed anyway.")
        }
    }
}

/// Print the "requirements files are not recency-checked" note when the
/// install carried any `-r` files. No-op otherwise.
pub(super) fn requirements_note(parsed: &parse::ParsedInstall) {
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

pub(super) fn warn_public_lookup_failures(report: &PrecheckReport, opts: &PrecheckOptions) {
    if opts.verdict.is_some() && report.unverifiable_count() > 0 {
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
/// values compare by lenient semver. One unparsable candidate among several
/// poisons the answer (`None`) — certifying a "safe version" from a partial
/// ordering could steer to a still-vulnerable release.
fn highest_fix(mut fixes: Vec<&str>) -> Option<String> {
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
                    Err(_) => return None,
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
    highest_fix(fixes)
}

/// Per-match advisory lines plus the safe-version steer. Built for agent
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

pub(super) fn print_text(report: &PrecheckReport) {
    // Build the echoed command from non-empty parts: a gated install with
    // zero remaining args has nothing to append.
    let mut command = format!("{} {}", report.manager.binary_name(), report.subcommand);
    if !report.original_args.is_empty() {
        command.push(' ');
        command.push_str(&report.original_args.join(" "));
    }

    println!(
        "Pre-checking `{}` (threshold {})",
        command,
        verify_deps::format_duration(report.threshold)
    );
    println!(
        "  {} ok, {} recent, {} vulnerable, {} unverifiable, {} skipped, {} errors",
        report.ok_count(),
        report.recent_count(),
        report.vulnerable_count(),
        report.unverifiable_count(),
        report.skipped_count(),
        report.error_count(),
    );

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
                    println!(
                        "  ⚠ {} → {}@{}  could not be verified: {}",
                        target.display, resolved.name, resolved.version, error,
                    );
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

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
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
}
