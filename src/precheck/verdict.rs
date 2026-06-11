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
/// job comes back `Unverifiable`; `block_reason` decides whether that
/// fails closed for the selected mode.
/// Plain work queue, no new crates; `reqwest::blocking::Client` is
/// `Send + Sync`. Result order is not preserved; callers match results back
/// by `(name, version)`.
pub(super) fn verdict_pool(
    jobs: Vec<tree::TreePackage>,
    cfg: &VerdictConfig,
    manager: PackageManager,
) -> Vec<(tree::TreePackage, VerdictStatus)> {
    verdict_pool_with(jobs, cfg, manager, VERDICT_CONCURRENCY)
}

fn verdict_pool_with(
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

/// Why the gate refuses to run the install. The single owner of both the
/// block decision and the escape hatch the refusal advertises —
/// `render::print_refusal` only maps variants to text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockReason {
    /// Every blocking finding predates this command (existing tree only).
    /// `--force` is the escape.
    ExistingTree,
    /// Vulnerable findings, or unverifiable/error findings in fail-closed
    /// (authenticated) mode. `--force` is the escape.
    Findings,
    /// Only the recency threshold fired. `--no-fail` is the escape.
    RecencyOnly,
}

pub(super) fn block_reason(report: &PrecheckReport, opts: &PrecheckOptions) -> Option<BlockReason> {
    if opts.force {
        return None;
    }
    // A resolution error means no verdict was obtained for that target, so
    // in authenticated mode it fails closed like `Unverifiable` — otherwise a
    // registry outage silently bypasses the gate.
    let fail_closed = authenticated_verdict(opts);
    if report.vulnerable_count() > 0
        || (fail_closed && report.unverifiable_count() > 0)
        || (fail_closed && report.error_count() > 0)
    {
        return Some(if blames_existing_tree(report, opts) {
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
/// findings exist, none sit on a named target (or block as unverifiable
/// there), and every *blocking* tree finding — vulnerable or unverifiable,
/// since `block_reason` refuses on both — genuinely predates this
/// command. A `Requested` finding (pip `-r`) is added by this command and
/// renders as `(from requirements)`; a `Transitive` finding on any install
/// that names targets or requirements files is being pulled in by them
/// right now. Only a truly bare install (`report.bare_install`) or
/// manifest-declared `PreExisting` findings may blame the existing tree.
fn blames_existing_tree(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
    let fail_closed = authenticated_verdict(opts);
    let named_findings = report.named_vulnerable_count()
        + if fail_closed {
            report.named_unverifiable_count()
        } else {
            0
        };
    if report.vulnerable_count() == 0 || named_findings > 0 {
        return false;
    }
    let Some(TreeReport::Full { transitive, .. }) = &report.tree else {
        return false;
    };
    transitive
        .iter()
        .filter(|t| {
            matches!(t.verdict, VerdictStatus::Vulnerable(_))
                || (fail_closed && matches!(t.verdict, VerdictStatus::Unverifiable(_)))
        })
        .all(|t| match t.origin {
            // A locked pin predates the sync command that installs it.
            TreeOrigin::PreExisting | TreeOrigin::Locked => true,
            TreeOrigin::Requested => false,
            TreeOrigin::Transitive => report.bare_install,
        })
}

/// Resolve every named target against its registry through a bounded worker
/// pool — each lookup is an independent blocking HTTP GET on the gate's
/// critical path, so they must not run serially. Order is preserved:
/// outcome `i` belongs to `targets[i]`.
pub(super) fn verify_all(
    targets: &[InstallTarget],
    opts: &PrecheckOptions,
    now: &chrono::DateTime<chrono::Utc>,
) -> Vec<TargetOutcome> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    if targets.len() <= 1 {
        return targets.iter().map(|t| verify_one(t, opts, now)).collect();
    }
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<TargetOutcome>>> =
        Mutex::new(targets.iter().map(|_| None).collect());
    let workers = VERDICT_CONCURRENCY.min(targets.len());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(target) = targets.get(i) else { break };
                let outcome = verify_one(target, opts, now);
                results.lock().unwrap()[i] = Some(outcome);
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|o| o.expect("verify_all worker filled every slot"))
        .collect()
}

fn verify_one(
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
        TargetOutcome, TreeOrigin, TreeOutcome, TreeReport, VerdictConfig, VerdictMode,
        VerdictStatus,
    };
    use super::*;

    fn should_block_install(report: &PrecheckReport, opts: &PrecheckOptions) -> bool {
        block_reason(report, opts).is_some()
    }

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
                blames_existing_tree(&report, &authenticated_opts(false, false)),
                blames_tree,
                "origin {origin:?}, with_named {with_named}, bare {bare_install}"
            );
        }
    }

    /// Unverifiable tree findings block too (`block_reason`), so they must
    /// pass the same origin test before the refusal may blame the existing
    /// tree: a command-added unverifiable transitive alongside a
    /// pre-existing vulnerable dep keeps the generic refusal on a named
    /// install, while on a bare install everything still predates the
    /// command.
    #[test]
    fn refusal_blame_considers_unverifiable_tree_findings() {
        let tree_finding = |name: &str, verdict, origin| TreeOutcome {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            verdict,
            origin,
        };
        let mixed_tree = || {
            Some(TreeReport::Full {
                resolved_count: 2,
                transitive: vec![
                    tree_finding(
                        "stickydep",
                        VerdictStatus::Vulnerable(vec![vm("A-1", None)]),
                        TreeOrigin::PreExisting,
                    ),
                    tree_finding(
                        "newdep",
                        VerdictStatus::Unverifiable("vuln-api unavailable".to_string()),
                        TreeOrigin::Transitive,
                    ),
                ],
            })
        };

        // Named install: the unverifiable transitive is being added by this
        // command, so "none were added by this command" would lie.
        let mut report = report_with(vec![resolved_outcome("cleanpkg", "1.0.0", false)]);
        report.tree = mixed_tree();
        assert!(!blames_existing_tree(
            &report,
            &authenticated_opts(false, false)
        ));
        assert!(blames_existing_tree(&report, &public_opts(false, false)));

        // Bare install: nothing named, everything resolved predates the
        // command — the mixed findings still blame the existing tree.
        let mut report = report_with(vec![]);
        report.bare_install = true;
        report.tree = mixed_tree();
        assert!(blames_existing_tree(
            &report,
            &authenticated_opts(false, false)
        ));
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
            let results = verdict_pool_with(jobs.clone(), &cfg, PackageManager::Pip, concurrency);
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
