//! Verdict pass: bounded vuln-api worker pool, registry resolution, and the
//! single block predicate (`block_reason`).

use std::time::Duration;

use super::{
    InstallTarget, PackageManager, PrecheckOptions, PrecheckReport, TargetKind, TargetOutcome,
    VerdictStatus,
};

/// Max parallel vuln-api / registry requests.
const VERDICT_CONCURRENCY: usize = 8;

/// Vuln-api verdict pass over resolved targets, run through the bounded
/// worker pool. No-op without a `VerdictConfig` (recency-only callers).
/// Any client/call failure becomes `Unverifiable`, which warns but never
/// blocks: public lookups fail open.
pub(super) fn run_verdict_pass(
    manager: PackageManager,
    outcomes: &mut [TargetOutcome],
    opts: &PrecheckOptions,
) {
    let Some(cfg) = &opts.verdict else { return };

    let jobs: Vec<(usize, String, String)> = outcomes
        .iter()
        .enumerate()
        .filter_map(|(i, o)| match o {
            TargetOutcome::Resolved { resolved, .. } => {
                Some((i, resolved.name.clone(), resolved.version.clone()))
            }
            _ => None,
        })
        .collect();
    if jobs.is_empty() {
        return;
    }

    let client = crate::vuln_api::http_client();
    let ecosystem = manager.ecosystem();
    let verdicts = pooled_map(&jobs, VERDICT_CONCURRENCY, |(_, name, version)| {
        let client = match &client {
            Ok(c) => c,
            Err(e) => return VerdictStatus::Unverifiable(e.clone()),
        };
        match crate::vuln_api::check_package_version(
            client,
            &cfg.base_url,
            ecosystem,
            name,
            version,
        ) {
            Ok(resp) if resp.is_vulnerable => VerdictStatus::Vulnerable(resp.matches),
            Ok(_) => VerdictStatus::Clean,
            Err(e) => VerdictStatus::Unverifiable(e.to_string()),
        }
    });

    for ((i, _, _), v) in jobs.into_iter().zip(verdicts) {
        if let TargetOutcome::Resolved { verdict, .. } = &mut outcomes[i] {
            *verdict = v;
        }
    }
}

/// Order-preserving bounded worker pool: `results[i]` is `f(&items[i])`.
/// Each call is an independent blocking HTTP request on the gate's critical
/// path, so they must not run serially. Plain work-stealing over an index,
/// no new crates; single-item lists skip the thread machinery.
fn pooled_map<T: Sync, R: Send>(
    items: &[T],
    concurrency: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    if items.len() <= 1 {
        return items.iter().map(&f).collect();
    }
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new(items.iter().map(|_| None).collect());
    let workers = concurrency.clamp(1, items.len());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                let result = f(item);
                results.lock().unwrap()[i] = Some(result);
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|r| r.expect("pooled_map worker filled every slot"))
        .collect()
}

/// Why the gate refuses to run the install. The single owner of both the
/// block decision and the escape hatch the refusal advertises —
/// `render::print_refusal` only maps variants to text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockReason {
    /// Vulnerable findings. `--force` is the escape.
    Findings,
    /// Only the recency threshold fired. `--no-fail` is the escape.
    RecencyOnly,
}

pub(super) fn block_reason(report: &PrecheckReport, opts: &PrecheckOptions) -> Option<BlockReason> {
    if opts.force {
        return None;
    }
    if report.verdicts().any(|v| v.blocks()) {
        return Some(BlockReason::Findings);
    }
    if !opts.no_fail && report.recent_count() > 0 {
        return Some(BlockReason::RecencyOnly);
    }
    None
}

/// Resolve every named target against its registry through the bounded
/// worker pool. Order is preserved: outcome `i` belongs to `targets[i]`.
pub(super) fn verify_all(
    targets: &[InstallTarget],
    opts: &PrecheckOptions,
    now: &chrono::DateTime<chrono::Utc>,
    allow_prerelease: bool,
) -> Vec<TargetOutcome> {
    pooled_map(targets, VERDICT_CONCURRENCY, |t| {
        verify_one(t, opts, now, allow_prerelease)
    })
}

fn verify_one(
    target: &InstallTarget,
    opts: &PrecheckOptions,
    now: &chrono::DateTime<chrono::Utc>,
    allow_prerelease: bool,
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
        TargetKind::Pypi(spec) => registry::pypi_resolve(
            &target.name,
            spec,
            opts.pypi_registry.as_deref(),
            allow_prerelease,
        ),
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
    use super::super::test_support::*;
    use super::super::{InstallTarget, PackageManager, TargetKind, TargetOutcome, VerdictStatus};
    use super::*;

    fn should_block_install(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
        block_reason(report, opts).is_some()
    }

    /// Predicate matrix: force ⇒ never block; vulnerable always blocks
    /// (`--no-fail` must not waive it); unverifiable findings and resolution
    /// errors never block (public mode fails open); recency blocks unless
    /// `--no-fail` demotes it.
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
            !should_block_install(&resolution_error, &public_opts(false, false)),
            "public mode must fail open when no verdict can be obtained"
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
        }
    }

    /// Verdict pass against an in-process stub: vulnerable body → Vulnerable
    /// with matches; 503 override → Unverifiable; no VerdictConfig → outcomes
    /// keep NotChecked.
    #[test]
    fn verdict_pass_maps_stub_responses() {
        use std::collections::HashMap;

        let key = |name: &str| crate::vuln_api_stub::key("pypi", name, "1.0.0");
        let mut checks = HashMap::new();
        checks.insert(
            key("evil"),
            crate::vuln_api_stub::vulnerable_body("pypi", "evil", "1.0.0", "MAL-2024-0001", None),
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

    /// `pooled_map` maps every item and preserves order at any concurrency
    /// (1 = serial, 8 > item count = all workers spawn but some drain empty).
    #[test]
    fn pooled_map_preserves_order_at_any_concurrency() {
        let items: Vec<usize> = (0..6).collect();
        for concurrency in [1usize, 8] {
            assert_eq!(
                pooled_map(&items, concurrency, |i| i * 2),
                vec![0, 2, 4, 6, 8, 10],
                "concurrency {concurrency}"
            );
        }
    }
}
