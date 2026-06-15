pub mod evaluate;
pub mod maven;
pub mod npm;
pub mod pypi;

use crate::deps::ecosystems::evaluate::ScanContext;
use crate::deps::DepsError;

pub fn scan_all(ctx: &mut ScanContext<'_>) -> Result<(), DepsError> {
    evaluate::scan_all(ctx)
}

use crate::deps::model::{ConstraintKind, Ecosystem};

/// Classify a raw declared constraint string.
pub fn classify_constraint(ecosystem: Ecosystem, raw: &str) -> ConstraintKind {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ConstraintKind::Unbounded;
    }

    match ecosystem {
        Ecosystem::Npm => classify_npm(trimmed),
        Ecosystem::PyPI => classify_pypi(trimmed),
        Ecosystem::Maven => classify_maven(trimmed),
        _ => classify_generic(trimmed),
    }
}

fn classify_npm(raw: &str) -> ConstraintKind {
    if raw.starts_with("git+") || raw.starts_with("git:") || raw.starts_with("git@") {
        return git_ref_kind(raw);
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return ConstraintKind::Url { checksum: false };
    }
    if raw == "*" || raw.eq_ignore_ascii_case("latest") || raw.eq_ignore_ascii_case("x") {
        return ConstraintKind::Unbounded;
    }
    if raw.starts_with('^') || raw.starts_with('~') || raw.starts_with('=') {
        return ConstraintKind::BoundedRange;
    }
    if raw.starts_with('>') || raw.starts_with('<') {
        return ConstraintKind::Unbounded;
    }
    if looks_like_exact_version(raw) {
        return ConstraintKind::Exact;
    }
    ConstraintKind::Unbounded
}

fn classify_pypi(raw: &str) -> ConstraintKind {
    if raw.contains("git+") || raw.contains("@git") {
        return git_ref_kind(raw);
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return ConstraintKind::Url { checksum: false };
    }
    if raw.starts_with("==") {
        return ConstraintKind::Exact;
    }
    if let Some((_name, ver)) = raw.split_once("==") {
        let ver = ver.trim();
        if looks_like_exact_version(ver) {
            return ConstraintKind::Exact;
        }
    }
    if raw.starts_with("~=") {
        return ConstraintKind::BoundedRange;
    }
    if raw.starts_with('^') || raw.starts_with('~') {
        return ConstraintKind::BoundedRange;
    }
    if raw.starts_with(">=") || raw.starts_with('>') || raw.starts_with('<') {
        return ConstraintKind::Unbounded;
    }
    if looks_like_exact_version(raw) {
        return ConstraintKind::Exact;
    }
    // Bare package name
    ConstraintKind::Unbounded
}

fn classify_maven(raw: &str) -> ConstraintKind {
    if raw.ends_with("-SNAPSHOT") {
        return ConstraintKind::Mutable;
    }
    if raw.eq_ignore_ascii_case("LATEST")
        || raw.eq_ignore_ascii_case("RELEASE")
        || raw.eq_ignore_ascii_case("latest.release")
    {
        return ConstraintKind::Unbounded;
    }
    if raw.ends_with(".+") || raw.contains('+') && raw.ends_with('.') {
        return ConstraintKind::BoundedRange;
    }
    if raw.starts_with('[') || raw.starts_with('(') {
        return ConstraintKind::BoundedRange;
    }
    if looks_like_exact_version(raw) || raw.contains('-') || raw.contains('.') {
        return ConstraintKind::Exact;
    }
    ConstraintKind::Unbounded
}

fn classify_generic(raw: &str) -> ConstraintKind {
    if raw.starts_with("git+") {
        return git_ref_kind(raw);
    }
    if raw == "*" || raw.eq_ignore_ascii_case("latest") {
        return ConstraintKind::Unbounded;
    }
    if looks_like_exact_version(raw) {
        return ConstraintKind::Exact;
    }
    ConstraintKind::BoundedRange
}

fn git_ref_kind(raw: &str) -> ConstraintKind {
    let ref_part = raw
        .rsplit_once('#')
        .or_else(|| raw.rsplit_once('@'))
        .map(|(_, r)| r)
        .unwrap_or("");
    if ref_part.len() == 40 && ref_part.chars().all(|c| c.is_ascii_hexdigit()) {
        ConstraintKind::GitRef { mutable: false }
    } else {
        ConstraintKind::GitRef { mutable: true }
    }
}

fn looks_like_exact_version(raw: &str) -> bool {
    let s = raw.trim_start_matches('=');
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    first.is_ascii_digit() || first == 'v'
}
