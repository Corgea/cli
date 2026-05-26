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
    finding
        .matches
        .iter()
        .map(|m| {
            let color = if m.tier == 1 {
                TerminalColor::Red
            } else {
                TerminalColor::Yellow
            };
            set_text_color(
                &format!(
                    "✗ {} {}@{}: {} (severity: {}, tier: {})",
                    dep.ecosystem.label(),
                    dep.name,
                    dep.version,
                    m.advisory_id,
                    m.severity_level,
                    m.tier,
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
        let cve_findings = report.cve_findings();
        let cve_errors = report.cve_errors();

        println!();
        println!(
            "{}",
            set_text_color("Known vulnerabilities:", TerminalColor::Yellow)
        );

        if cve_findings.is_empty() && cve_errors.is_empty() {
            println!(
                "  {}",
                set_text_color("✓ no known vulnerabilities", TerminalColor::Green)
            );
        } else {
            for finding in &cve_findings {
                for line in format_cve_finding(finding).lines() {
                    println!("  {}", line);
                }
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

/// Render the report as a single JSON object on stdout.
pub fn print_json(report: &VerifyReport) {
    let mut cve_by_dep: HashMap<(String, String, String), Vec<serde_json::Value>> = HashMap::new();
    if report.check_cve {
        for outcome in &report.cve_outcomes {
            match outcome {
                super::CveLookupOutcome::Vulnerable(f) => {
                    let key = dep_key(&f.dep);
                    let entries: Vec<_> = f
                        .matches
                        .iter()
                        .map(|m| {
                            json!({
                                "advisory_id": m.advisory_id,
                                "severity_level": m.severity_level,
                                "tier": m.tier,
                                "vulnerable_version_range": m.vulnerable_version_range,
                                "fixed_version": m.fixed_version,
                            })
                        })
                        .collect();
                    cve_by_dep.insert(key, entries);
                }
                super::CveLookupOutcome::Clean { dep } => {
                    cve_by_dep.entry(dep_key(dep)).or_default();
                }
                super::CveLookupOutcome::Error { .. } => {}
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

            if report.check_cve {
                let dep = match o {
                    LookupOutcome::Ok { dep, .. } => dep,
                    LookupOutcome::Recent(f) => &f.dep,
                    LookupOutcome::Error { dep, .. } => dep,
                };
                let mut obj = obj;
                let cves = cve_by_dep.get(&dep_key(dep)).cloned().unwrap_or_default();
                obj.as_object_mut()
                    .unwrap()
                    .insert("cves".to_string(), json!(cves));
                obj
            } else {
                obj
            }
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
        body.as_object_mut().unwrap().insert(
            "cve_summary".to_string(),
            json!({
                "checked": report.cve_outcomes.len(),
                "vulnerable": vulnerable,
                "clean": clean,
                "errors": errors,
            }),
        );
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
        };
        let line = format_cve_finding(&finding);
        assert!(line.contains("GHSA-test-advisory"));
        assert!(line.contains("lodash@4.17.20"));
    }
}
