//! Verdict pass: bounded vuln-api worker pool, result matching, and the
//! single block predicate (`should_block_install`).

use std::time::Duration;

use super::{
    tree, InstallTarget, PackageManager, PrecheckOptions, PrecheckReport, TargetKind,
    TargetOutcome, TreeOrigin, TreeOutcome, VerdictConfig, VerdictStatus,
};

/// Above this many verdict jobs, print a stderr progress line so a big tree
/// pass doesn't look hung.
const VERDICT_PROGRESS_THRESHOLD: usize = 8;

/// Max parallel vuln-api verdict requests.
pub(super) const VERDICT_CONCURRENCY: usize = 8;

/// Bounded worker pool over the verdict jobs. On client/request failure every
/// job comes back `Unverifiable`; `should_block_install` decides whether that
/// fails closed for the selected mode.
/// Plain work queue, no new crates; `reqwest::blocking::Client` is
/// `Send + Sync`. Result order is not preserved; callers match results back
/// by `(name, version)`.
pub(super) fn verdict_pool(
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
pub(super) fn apply_verdicts(
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

pub(super) fn authenticated_verdict(opts: &PrecheckOptions) -> bool {
    opts.verdict
        .as_ref()
        .is_some_and(|cfg| cfg.mode.is_authenticated())
}

pub(super) fn public_verdict(opts: &PrecheckOptions) -> bool {
    opts.verdict
        .as_ref()
        .is_some_and(|cfg| cfg.mode.is_public())
}

pub(super) fn should_block_install(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
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

pub(super) fn verify_one(
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
    use super::super::test_support::*;
    use super::super::{
        run_verdict_pass, tree, InstallTarget, PackageManager, PrecheckOptions, TargetKind,
        TargetOutcome, TreeOrigin, TreeOutcome, VerdictConfig, VerdictMode, VerdictStatus,
    };
    use super::*;

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
        report.tree = Some(super::super::TreeReport::Full {
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
