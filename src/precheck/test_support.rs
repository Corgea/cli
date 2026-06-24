//! Shared builders for precheck unit tests (mod.rs, render.rs, verdict.rs).
//! Test-only: declared `#[cfg(test)]` from mod.rs.

use std::time::Duration;

use chrono::Utc;

use super::{
    InstallTarget, PackageManager, PrecheckOptions, PrecheckReport, TargetKind, TargetOutcome,
    VerdictConfig, VerdictMode, VerdictStatus,
};

/// Baseline options: pypi registry at a dead address (a port that
/// refuses connections - these tests never dial it), no verdict config.
/// Override fields per test via struct update.
pub(crate) fn stub_opts() -> PrecheckOptions {
    PrecheckOptions {
        force: false,
        json: false,
        verdict: None,
        npm_registry: None,
        pypi_registry: Some("http://127.0.0.1:9".to_string()),
    }
}

/// `stub_opts()` plus an authenticated verdict config pointing at `base_url`.
pub(crate) fn verdict_opts(base_url: &str) -> PrecheckOptions {
    PrecheckOptions {
        verdict: Some(VerdictConfig {
            base_url: base_url.to_string(),
            mode: VerdictMode::Authenticated {
                token: "test-token".to_string(),
            },
            public_login_hint: false,
        }),
        ..stub_opts()
    }
}

pub(crate) fn public_opts(force: bool) -> PrecheckOptions {
    PrecheckOptions {
        force,
        verdict: Some(VerdictConfig {
            base_url: "http://127.0.0.1:9".to_string(),
            mode: VerdictMode::Public,
            public_login_hint: true,
        }),
        ..stub_opts()
    }
}

pub(crate) fn authenticated_opts(force: bool) -> PrecheckOptions {
    PrecheckOptions {
        force,
        ..verdict_opts("http://127.0.0.1:9")
    }
}

pub(crate) fn resolved_outcome(name: &str, version: &str) -> TargetOutcome {
    // Age only drives the published-date display now; fix it for determinism.
    let age = Duration::from_secs(3600);
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
        age: Some(age),
        verdict: VerdictStatus::NotChecked,
    }
}

pub(crate) fn report_with(outcomes: Vec<TargetOutcome>) -> PrecheckReport {
    PrecheckReport {
        manager: PackageManager::Pip,
        subcommand: "install".to_string(),
        original_args: vec![],
        outcomes,
        tree: None,
        // Most tests model an install that named something; bare-install
        // cases set this explicitly.
        bare_install: false,
    }
}

pub(crate) fn set_verdict(outcome: &mut TargetOutcome, v: VerdictStatus) {
    if let TargetOutcome::Resolved { verdict, .. } = outcome {
        *verdict = v;
    }
}

pub(crate) fn vm(advisory: &str, fixed: Option<&str>) -> crate::vuln_api::VulnMatch {
    crate::vuln_api::VulnMatch {
        advisory_id: advisory.to_string(),
        severity_level: "high".to_string(),
        tier: Some(1),
        vulnerable_version_range: None,
        fixed_version: fixed.map(str::to_string),
    }
}
