//! Render a verification report to the terminal or as JSON.

use std::collections::HashMap;

use serde_json::json;

use crate::utils::terminal::{set_text_color, TerminalColor};

use super::{format_duration, CveFinding, Dependency, LookupOutcome, VerifyReport};

fn dep_key(dep: &Dependency) -> (String, String, String) {
    (
        dep.ecosystem.label().to_string(),
        dep.name.clone(),
        dep.version.clone(),
    )
}

/// Format a single CVE finding line for text output. Public for integration tests.
pub fn format_cve_finding(finding: &CveFinding) -> String {
    let dep = &finding.dep;
    let fixed_candidates: Vec<String> = finding
        .matches
        .iter()
        .filter_map(|m| m.fixed_version.clone())
        .collect();
    let best_fixed = super::pick_highest_fixed(dep.ecosystem, &fixed_candidates);
    let fix_seg = match &best_fixed {
        Some(v) => format!(", fix: upgrade to {}", v),
        None => String::new(),
    };
    finding
        .matches
        .iter()
        .zip(
            finding
                .advisory_details
                .iter()
                .chain(std::iter::repeat(&None)),
        )
        .map(|(m, detail)| {
            let color = if m.tier == 1 {
                TerminalColor::Red
            } else {
                TerminalColor::Yellow
            };
            let url_seg = match detail.as_ref().and_then(|d| d.url.as_deref()) {
                Some(u) => format!(", {}", set_text_color(u, TerminalColor::Blue)),
                None => String::new(),
            };
            set_text_color(
                &format!(
                    "✗ {} {}@{}: {} (severity: {}, tier: {}{}{})",
                    dep.ecosystem.label(),
                    dep.name,
                    dep.version,
                    m.advisory_id,
                    m.severity_level,
                    m.tier,
                    fix_seg,
                    url_seg,
                ),
                color,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the report for human consumption.
pub fn print_text(report: &VerifyReport) {
    println!(
        "Verifying dependencies against publish-time threshold of {}",
        format_duration(report.threshold)
    );
    if !report.sources.is_empty() {
        println!("Sources:");
        for s in &report.sources {
            println!("  - {}", s);
        }
    }

    let recent = report.recent();
    let errors = report.errors();
    let ok_count = report.ok_count();

    println!(
        "Checked {} dependencies — {} ok, {} recent, {} errors, {} unpinned",
        report.outcomes.len(),
        ok_count,
        recent.len(),
        errors.len(),
        report.unpinned_warnings.len(),
    );

    if !report.unpinned_warnings.is_empty() {
        println!();
        println!(
            "{}",
            set_text_color(
                "Unpinned dependencies (cannot be verified against the registry):",
                TerminalColor::Yellow,
            )
        );
        for w in &report.unpinned_warnings {
            println!(
                "  {} [{}] {}: {}",
                set_text_color("?", TerminalColor::Yellow),
                w.ecosystem.label(),
                w.manifest,
                w.reason,
            );
        }
    }

    if !recent.is_empty() {
        println!();
        println!(
            "{}",
            set_text_color(
                "Recently published dependencies (within threshold):",
                TerminalColor::Yellow,
            )
        );
        for f in &recent {
            println!(
                "  {} {}@{} ({})  published {} ago at {}",
                set_text_color("⚠", TerminalColor::Yellow),
                f.dep.ecosystem.label(),
                f.dep.name,
                f.dep.version,
                set_text_color(&format_duration(f.age), TerminalColor::Yellow,),
                f.published_at.format("%Y-%m-%d %H:%M:%S UTC"),
            );
        }
    }

    if report.check_cve {
        println!();
        println!(
            "{}",
            set_text_color("Known vulnerabilities:", TerminalColor::Yellow)
        );

        let cve_findings = report.cve_findings();
        let cve_errors = report.cve_errors();

        let checked = report.cve_outcomes.len();
        if cve_findings.is_empty() && cve_errors.is_empty() {
            if checked == 0 {
                println!(
                    "  {}",
                    set_text_color(
                        "⚠ no dependencies eligible for CVE check",
                        TerminalColor::Yellow,
                    )
                );
            } else {
                println!(
                    "  {}",
                    set_text_color(
                        &format!(
                            "✓ no known vulnerabilities ({} dependencies checked)",
                            checked
                        ),
                        TerminalColor::Green,
                    )
                );
            }
        } else {
            for finding in &cve_findings {
                for line in format_cve_finding(finding).lines() {
                    println!("  {}", line);
                }
            }
            if !cve_findings.is_empty() {
                println!(
                    "  {}",
                    set_text_color(
                        &format!("note: {} dependencies CVE-checked", checked),
                        TerminalColor::Yellow,
                    )
                );
            }
        }

        if !cve_errors.is_empty() {
            println!();
            println!(
                "{}",
                set_text_color("CVE lookup errors:", TerminalColor::Red)
            );
            for (dep, err) in &cve_errors {
                println!(
                    "  {} {}@{} ({}): {}",
                    set_text_color("✗", TerminalColor::Red),
                    dep.name,
                    dep.version,
                    dep.ecosystem.label(),
                    err,
                );
            }
        }

        if !report.unpinned_warnings.is_empty() {
            println!(
                "  {}",
                set_text_color(
                    &format!(
                        "note: {} unpinned dependency manifest(s) were not CVE-checked",
                        report.unpinned_warnings.len()
                    ),
                    TerminalColor::Yellow,
                )
            );
        }
    }

    if !errors.is_empty() {
        println!();
        println!(
            "{}",
            set_text_color(
                "Could not verify the following dependencies:",
                TerminalColor::Red,
            )
        );
        for (dep, err) in &errors {
            println!(
                "  {} {}@{} ({}): {}",
                set_text_color("✗", TerminalColor::Red),
                dep.name,
                dep.version,
                dep.ecosystem.label(),
                err,
            );
        }
    }

    if recent.is_empty() && errors.is_empty() && report.unpinned_warnings.is_empty() {
        println!(
            "{}",
            set_text_color(
                "All dependencies are older than the threshold.",
                TerminalColor::Green,
            )
        );
    }
}

/// Per-dep CVE status, kept distinct so downstream automation can
/// tell apart "checked clean", "checked and failed", "lookup errored",
/// and "never checked" (e.g. unpinned manifests).
enum CveStatus {
    Clean,
    Vulnerable(Vec<serde_json::Value>),
    Error(String),
    NotChecked,
}

impl CveStatus {
    fn label(&self) -> &'static str {
        match self {
            CveStatus::Clean => "clean",
            CveStatus::Vulnerable(_) => "vulnerable",
            CveStatus::Error(_) => "error",
            CveStatus::NotChecked => "not_checked",
        }
    }
}

/// Render the report as a single JSON object on stdout.
///
/// ## CVE fields (when `--check-cve` was passed)
///
/// Each entry in `results` includes a `cves` array (empty when clean) and a
/// `cve_status` label (`clean`, `vulnerable`, `error`, or `not_checked`).
/// Lookup failures add `cve_error` instead of `cves`. When `--check-cve` was
/// not passed, per-dep CVE fields are omitted entirely.
///
/// Each entry of `cves` carries `advisory_id`, `severity_level`, `tier`,
/// `vulnerable_version_range`, `fixed_version`, and `advisory_url`.
/// The last two may be `null` when the server did not return a fix
/// version or the advisory-detail lookup did not produce a URL
/// (e.g. 404 on `/v1/advisories/:id`).
///
/// Top-level `cve_summary` is present when `--check-cve` was passed:
/// `{ checked, vulnerable, clean, errors, unpinned_not_checked }`.
/// It is omitted when CVE checking was not requested.
pub fn print_json(report: &VerifyReport) {
    let mut cve_by_dep: HashMap<(String, String, String), CveStatus> = HashMap::new();
    if report.check_cve {
        for outcome in &report.cve_outcomes {
            match outcome {
                super::CveLookupOutcome::Vulnerable(f) => {
                    let entries: Vec<_> = f
                        .matches
                        .iter()
                        .zip(f.advisory_details.iter().chain(std::iter::repeat(&None)))
                        .map(|(m, detail)| {
                            let advisory_url = detail.as_ref().and_then(|d| d.url.clone());
                            json!({
                                "advisory_id": m.advisory_id,
                                "severity_level": m.severity_level,
                                "tier": m.tier,
                                "vulnerable_version_range": m.vulnerable_version_range,
                                "fixed_version": m.fixed_version,
                                "advisory_url": advisory_url,
                            })
                        })
                        .collect();
                    cve_by_dep.insert(dep_key(&f.dep), CveStatus::Vulnerable(entries));
                }
                super::CveLookupOutcome::Clean { dep } => {
                    cve_by_dep.entry(dep_key(dep)).or_insert(CveStatus::Clean);
                }
                super::CveLookupOutcome::Error { dep, error } => {
                    cve_by_dep.insert(dep_key(dep), CveStatus::Error(error.clone()));
                }
            }
        }
    }

    let outcomes: Vec<_> = report
        .outcomes
        .iter()
        .map(|o| {
            let obj = match o {
                LookupOutcome::Ok {
                    dep,
                    published_at,
                    age,
                } => json!({
                    "status": "ok",
                    "ecosystem": dep.ecosystem.label(),
                    "name": dep.name,
                    "version": dep.version,
                    "dev": dep.dev,
                    "source": dep.source,
                    "published_at": published_at.to_rfc3339(),
                    "age_seconds": age.as_secs(),
                }),
                LookupOutcome::Recent(f) => json!({
                    "status": "recent",
                    "ecosystem": f.dep.ecosystem.label(),
                    "name": f.dep.name,
                    "version": f.dep.version,
                    "dev": f.dep.dev,
                    "source": f.dep.source,
                    "published_at": f.published_at.to_rfc3339(),
                    "age_seconds": f.age.as_secs(),
                }),
                LookupOutcome::Error { dep, error } => json!({
                    "status": "error",
                    "ecosystem": dep.ecosystem.label(),
                    "name": dep.name,
                    "version": dep.version,
                    "dev": dep.dev,
                    "source": dep.source,
                    "error": error,
                }),
            };

            if !report.check_cve {
                return obj;
            }

            let dep = match o {
                LookupOutcome::Ok { dep, .. } => dep,
                LookupOutcome::Recent(f) => &f.dep,
                LookupOutcome::Error { dep, .. } => dep,
            };
            let status = cve_by_dep
                .remove(&dep_key(dep))
                .unwrap_or(CveStatus::NotChecked);
            let mut obj = obj;
            let map = obj
                .as_object_mut()
                .expect("LookupOutcome JSON serializes as an object");
            map.insert("cve_status".to_string(), json!(status.label()));
            match status {
                CveStatus::Vulnerable(cves) => {
                    map.insert("cves".to_string(), json!(cves));
                }
                CveStatus::Clean => {
                    map.insert("cves".to_string(), json!([]));
                }
                CveStatus::Error(err) => {
                    map.insert("cve_error".to_string(), json!(err));
                }
                CveStatus::NotChecked => {}
            }
            obj
        })
        .collect();

    let unpinned: Vec<_> = report
        .unpinned_warnings
        .iter()
        .map(|w| {
            json!({
                "ecosystem": w.ecosystem.label(),
                "manifest": w.manifest,
                "reason": w.reason,
            })
        })
        .collect();

    let mut body = json!({
        "scanned_at": report.scanned_at.to_rfc3339(),
        "threshold_seconds": report.threshold.as_secs(),
        "sources": report.sources,
        "summary": {
            "checked": report.outcomes.len(),
            "ok": report.ok_count(),
            "recent": report.recent().len(),
            "errors": report.errors().len(),
            "unpinned": report.unpinned_warnings.len(),
        },
        "results": outcomes,
        "unpinned": unpinned,
    });

    if report.check_cve {
        let vulnerable = report.cve_findings().len();
        let errors = report.cve_errors().len();
        let clean = report
            .cve_outcomes
            .iter()
            .filter(|o| matches!(o, super::CveLookupOutcome::Clean { .. }))
            .count();
        let summary = json!({
            "checked": report.cve_outcomes.len(),
            "vulnerable": vulnerable,
            "clean": clean,
            "errors": errors,
            "unpinned_not_checked": report.unpinned_warnings.len(),
        });
        body.as_object_mut()
            .expect("top-level JSON is an object")
            .insert("cve_summary".to_string(), summary);
    }

    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_deps::{CveFinding, Dependency, DependencyEcosystem};
    use crate::vuln_api::VulnMatch;

    #[test]
    fn format_cve_finding_includes_advisory_id() {
        let finding = CveFinding {
            dep: Dependency {
                name: "lodash".into(),
                version: "4.17.20".into(),
                ecosystem: DependencyEcosystem::Npm,
                source: "package-lock.json".into(),
                dev: false,
            },
            matches: vec![VulnMatch {
                advisory_id: "GHSA-test-advisory".into(),
                severity_level: "high".into(),
                tier: 1,
                vulnerable_version_range: None,
                fixed_version: None,
            }],
            advisory_details: vec![None],
        };
        let line = format_cve_finding(&finding);
        assert!(line.contains("GHSA-test-advisory"));
        assert!(line.contains("lodash@4.17.20"));
    }

    #[test]
    fn format_cve_finding_includes_fix_version() {
        let finding = CveFinding {
            dep: Dependency {
                name: "lodash".into(),
                version: "4.17.20".into(),
                ecosystem: DependencyEcosystem::Npm,
                source: "package-lock.json".into(),
                dev: false,
            },
            matches: vec![VulnMatch {
                advisory_id: "GHSA-test-advisory".into(),
                severity_level: "high".into(),
                tier: 1,
                vulnerable_version_range: None,
                fixed_version: Some("4.17.21".into()),
            }],
            advisory_details: vec![None],
        };
        let line = format_cve_finding(&finding);
        assert!(
            line.contains("fix: upgrade to 4.17.21"),
            "expected 'fix: upgrade to 4.17.21' in: {}",
            line
        );
    }

    #[test]
    fn format_cve_finding_picks_highest_fix_across_matches() {
        let dep = Dependency {
            name: "left-pad".into(),
            version: "1.0.0".into(),
            ecosystem: DependencyEcosystem::Npm,
            source: "package-lock.json".into(),
            dev: false,
        };
        let mk = |id: &str, fv: &str| VulnMatch {
            advisory_id: id.into(),
            severity_level: "low".into(),
            tier: 2,
            vulnerable_version_range: None,
            fixed_version: Some(fv.into()),
        };
        let finding = CveFinding {
            dep,
            matches: vec![
                mk("GHSA-a", "1.0.0"),
                mk("GHSA-b", "1.2.0"),
                mk("GHSA-c", "1.1.0"),
            ],
            advisory_details: vec![None, None, None],
        };
        let line = format_cve_finding(&finding);
        assert!(line.contains("fix: upgrade to 1.2.0"), "got: {}", line);
        assert!(!line.contains("fix: upgrade to 1.0.0"), "got: {}", line);
    }
}
