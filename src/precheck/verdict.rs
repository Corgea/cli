//! Verdict pass: bounded vuln-api worker pool, result matching, and the
//! single block predicate (`block_reason`).

use std::time::Duration;

use super::{
    tree, InstallTarget, PackageManager, PrecheckOptions, PrecheckReport, TargetKind,
    TargetOutcome, TreeOrigin, TreeOutcome, TreeReport, VerdictConfig, VerdictStatus,
};

/// Above this many verdict jobs, print a stderr progress line so a big tree
/// pass doesn't look hung.
const VERDICT_PROGRESS_THRESHOLD: usize = 8;

/// Max parallel vuln-api / registry requests.
const VERDICT_CONCURRENCY: usize = 8;

/// Bounded worker pool over the verdict jobs. On client/request failure every
/// job comes back `Unverifiable`, which warns but never blocks: public
/// lookups fail open. Order is preserved: result `i` belongs to job `i`.
pub(super) fn verdict_pool(
    jobs: Vec<tree::TreePackage>,
    cfg: &VerdictConfig,
    manager: PackageManager,
) -> Vec<(tree::TreePackage, VerdictStatus)> {
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
    let verdicts =
        pooled_map(
            &jobs,
            VERDICT_CONCURRENCY,
            |job| match crate::vuln_api::check_package_version(
                &client,
                &cfg.base_url,
                ecosystem,
                &job.name,
                &job.version,
            ) {
                Ok(resp) if resp.is_vulnerable => VerdictStatus::Vulnerable(resp.matches),
                Ok(_) => VerdictStatus::Clean,
                Err(e) => VerdictStatus::Unverifiable(e.to_string()),
            },
        );
    jobs.into_iter().zip(verdicts).collect()
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

/// Why the gate refuses to run the install. The single owner of both the
/// block decision and the escape hatch the refusal advertises —
/// `render::print_refusal` only maps variants to text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockReason {
    /// Every blocking finding predates this command (existing tree only).
    /// `--force` is the escape.
    ExistingTree,
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
        return Some(if blames_existing_tree(report) {
            BlockReason::ExistingTree
        } else {
            BlockReason::Findings
        });
    }
    if !opts.no_fail && report.recent_count() > 0 {
        return Some(BlockReason::RecencyOnly);
    }
    None
}

/// True when the block is entirely the existing tree's doing: vulnerable
/// findings exist, no named target blocks, and every *blocking* tree
/// finding (`VerdictStatus::blocks`, same predicate `block_reason` refuses
/// on) genuinely predates this command. A `Requested` finding (pip `-r`)
/// is added by this command and renders as `(from requirements)`; a
/// `Transitive` finding on any install that names targets or requirements
/// files is being pulled in by them right now. Only a truly bare install
/// (`report.bare_install`) or manifest-declared `PreExisting` findings may
/// blame the existing tree.
fn blames_existing_tree(report: &PrecheckReport) -> bool {
    let named_blocks = report.named_verdicts().any(|v| v.blocks());
    if report.vulnerable_count() == 0 || named_blocks {
        return false;
    }
    let Some(TreeReport::Full { transitive, .. }) = &report.tree else {
        return false;
    };
    transitive
        .iter()
        .filter(|t| t.verdict.blocks())
        .all(|t| match t.origin {
            // A locked pin predates the `npm ci` that installs it.
            TreeOrigin::PreExisting | TreeOrigin::Locked => true,
            TreeOrigin::Requested => false,
            TreeOrigin::Transitive => report.bare_install,
        })
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
    use super::super::{
        run_verdict_pass, InstallTarget, PackageManager, TargetKind, TargetOutcome, TreeOrigin,
        TreeOutcome, TreeReport, VerdictStatus,
    };
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

    /// A clean named outcome plus a vulnerable transitive tree finding must
    /// roll into the block counts: `vulnerable_count() == 1`,
    /// `should_block_install` true without `--force`, false with it.
    #[test]
    fn tree_findings_extend_block_counts() {
        let mut named = resolved_outcome("pkg", "1.0.0", false);
        set_verdict(&mut named, VerdictStatus::Clean);
        let mut report = report_with(vec![named]);
        report.tree = Some(TreeReport::Full {
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

    /// The existing-tree refusal fires only when every vulnerable finding
    /// predates the command: a `Requested` finding (pip `-r`) is added by
    /// this command, and a `Transitive` finding is being pulled in right
    /// now unless the install is truly bare. `bare_install` is the explicit
    /// discriminator — a requirements-only install also has no named
    /// outcomes, but its resolved set is the command's doing.
    #[test]
    fn refusal_blame_respects_finding_origin() {
        let tree_vulnerable = |origin| TreeOutcome {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            verdict: VerdictStatus::Vulnerable(vec![vm("A-1", None)]),
            origin,
        };
        // (origin, named outcomes present, bare_install, expected).
        // (origin, named=false, bare=false) is the requirements-only shape.
        let cases = [
            (TreeOrigin::PreExisting, false, true, true),
            (TreeOrigin::PreExisting, false, false, true),
            (TreeOrigin::PreExisting, true, false, true),
            (TreeOrigin::Locked, false, true, true),
            (TreeOrigin::Transitive, false, true, true),
            (TreeOrigin::Transitive, false, false, false),
            (TreeOrigin::Transitive, true, false, false),
            (TreeOrigin::Requested, false, true, false),
            (TreeOrigin::Requested, false, false, false),
            (TreeOrigin::Requested, true, false, false),
        ];
        for (origin, with_named, bare_install, blames_tree) in cases {
            let outcomes = if with_named {
                vec![resolved_outcome("cleanpkg", "1.0.0", false)]
            } else {
                vec![]
            };
            let mut report = report_with(outcomes);
            report.bare_install = bare_install;
            report.tree = Some(TreeReport::Full {
                resolved_count: 1,
                transitive: vec![tree_vulnerable(origin)],
            });
            assert_eq!(
                blames_existing_tree(&report),
                blames_tree,
                "origin {origin:?}, with_named {with_named}, bare {bare_install}"
            );
        }
    }

    /// A vulnerable NAMED target must never blame the existing tree, even
    /// when a pre-existing tree finding is also vulnerable.
    #[test]
    fn refusal_blame_requires_clean_named_targets() {
        let mut named = resolved_outcome("badpkg", "1.0.0", false);
        set_verdict(&mut named, VerdictStatus::Vulnerable(vec![vm("A-1", None)]));
        let mut report = report_with(vec![named]);
        report.tree = Some(TreeReport::Full {
            resolved_count: 2,
            transitive: vec![TreeOutcome {
                name: "stickydep".to_string(),
                version: "1.0.0".to_string(),
                verdict: VerdictStatus::Vulnerable(vec![vm("A-2", None)]),
                origin: TreeOrigin::PreExisting,
            }],
        });
        assert!(!blames_existing_tree(&report));
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

    /// The pool must verdict every job exactly once and return the flagged
    /// job `Vulnerable` with the rest `Clean`.
    #[test]
    fn verdict_pool_returns_all_results() {
        use std::collections::HashMap;

        let mut checks = HashMap::new();
        checks.insert(
            crate::vuln_api_stub::key("pypi", "evil", "1.0.0"),
            crate::vuln_api_stub::vulnerable_body("pypi", "evil", "1.0.0", "MAL-2024-0001", None),
        );
        let stub = crate::vuln_api_stub::spawn_with_statuses(checks, HashMap::new());

        let cfg = VerdictConfig {
            base_url: stub.base_url.clone(),
        };

        let jobs: Vec<tree::TreePackage> = ["a", "b", "evil", "c", "d", "e"]
            .iter()
            .map(|n| tree::TreePackage {
                name: n.to_string(),
                version: "1.0.0".to_string(),
                requested: false,
            })
            .collect();

        let results = verdict_pool(jobs, &cfg, PackageManager::Pip);
        assert_eq!(results.len(), 6, "all jobs verdicted");
        let flagged = results
            .iter()
            .filter(|(_, v)| matches!(v, VerdictStatus::Vulnerable(_)))
            .count();
        let clean = results
            .iter()
            .filter(|(_, v)| matches!(v, VerdictStatus::Clean))
            .count();
        assert_eq!(flagged, 1, "only evil flagged");
        assert_eq!(clean, 5, "rest clean");
        let evil = results
            .iter()
            .find(|(p, _)| p.name == "evil")
            .expect("evil present");
        assert!(
            matches!(&evil.1, VerdictStatus::Vulnerable(m) if m[0].advisory_id == "MAL-2024-0001")
        );
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
