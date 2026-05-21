//! Render a verification report to the terminal or as JSON.

use serde_json::json;

use crate::utils::terminal::{set_text_color, TerminalColor};

use super::{format_duration, LookupOutcome, VerifyReport};

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
        "Checked {} dependencies — {} ok, {} recent, {} errors",
        report.outcomes.len(),
        ok_count,
        recent.len(),
        errors.len(),
    );

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
                set_text_color(
                    &format_duration(f.age),
                    TerminalColor::Yellow,
                ),
                f.published_at.format("%Y-%m-%d %H:%M:%S UTC"),
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

    if recent.is_empty() && errors.is_empty() {
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
    let outcomes: Vec<_> = report
        .outcomes
        .iter()
        .map(|o| match o {
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
        })
        .collect();

    let body = json!({
        "scanned_at": report.scanned_at.to_rfc3339(),
        "threshold_seconds": report.threshold.as_secs(),
        "sources": report.sources,
        "summary": {
            "checked": report.outcomes.len(),
            "ok": report.ok_count(),
            "recent": report.recent().len(),
            "errors": report.errors().len(),
        },
        "results": outcomes,
    });

    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}
