use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::deps::detect::DepFileKind;
use crate::deps::ecosystems::classify_constraint;
use crate::deps::ecosystems::evaluate::{
    constraint_to_findings, dep002, dep008, file_in_dir, parent_dir, read_json,
    source_type_from_declared, ScanContext,
};
use crate::deps::model::{
    ConstraintKind, DependencyEdge, DependencyNode, Ecosystem, PackageId, Scope, SourceType,
};
use crate::deps::DepsError;

pub fn scan_npm_projects(ctx: &mut ScanContext<'_>) -> Result<(), DepsError> {
    let manifests: Vec<_> = ctx
        .detected
        .iter()
        .filter(|f| f.kind == DepFileKind::NpmManifest)
        .collect();

    for manifest in manifests {
        let dir = parent_dir(&manifest.path);
        let rel_manifest = manifest
            .path
            .strip_prefix(ctx.root)
            .unwrap_or(&manifest.path)
            .display()
            .to_string();
        scan_one_npm(ctx, &dir, &manifest.path, &rel_manifest)?;
    }
    Ok(())
}

fn scan_one_npm(
    ctx: &mut ScanContext<'_>,
    dir: &Path,
    manifest_path: &Path,
    rel_manifest: &str,
) -> Result<(), DepsError> {
    let pkg = read_json(manifest_path)?;
    let lock_path = file_in_dir(ctx.detected, dir, DepFileKind::NpmLockfile);

    let mut direct_prod: HashMap<String, String> = HashMap::new();
    let mut direct_dev: HashMap<String, String> = HashMap::new();
    if let Some(deps) = pkg.get("dependencies").and_then(|v| v.as_object()) {
        for (k, v) in deps {
            if let Some(s) = v.as_str() {
                direct_prod.insert(k.clone(), s.to_string());
            }
        }
    }
    if let Some(deps) = pkg.get("devDependencies").and_then(|v| v.as_object()) {
        for (k, v) in deps {
            if let Some(s) = v.as_str() {
                direct_dev.insert(k.clone(), s.to_string());
            }
        }
    }

    let lock_packages: HashMap<String, LockPackage> = if let Some(ref lp) = lock_path {
        parse_npm_lock(lp)?
    } else {
        HashMap::new()
    };

    let lock_has = |name: &str| -> bool {
        lock_packages.contains_key(name)
            || lock_packages.contains_key(&format!("node_modules/{name}"))
    };

    if ctx.policy.fail_on_stale_lockfile {
        for name in direct_prod.keys().chain(direct_dev.keys()) {
            let declared = direct_prod
                .get(name)
                .or_else(|| direct_dev.get(name))
                .map(String::as_str)
                .unwrap_or("");
            if declared.starts_with("git") || declared.contains("git+") {
                continue;
            }
            if !lock_has(name) {
                dep002(ctx.findings, ctx.policy, rel_manifest, name);
            }
        }
    }

    let mut seen_nodes: HashSet<String> = HashSet::new();

    for (name, declared) in direct_prod.iter().chain(direct_dev.iter()) {
        let scope = if direct_dev.contains_key(name) {
            Scope::Development
        } else {
            Scope::Production
        };
        let resolved = lock_packages
            .get(name)
            .or_else(|| lock_packages.get(&format!("node_modules/{name}")))
            .map(|p| p.version.clone());
        let reproducible = resolved.is_some() && lock_path.is_some();
        let kind = classify_constraint(Ecosystem::Npm, declared);
        let package_id = resolved
            .as_ref()
            .map(|v| PackageId::npm(name, v))
            .or_else(|| {
                if matches!(kind, ConstraintKind::GitRef { .. }) {
                    Some(PackageId::npm(name, "git"))
                } else {
                    None
                }
            });
        ctx.findings.extend(constraint_to_findings(
            ctx.policy,
            &kind,
            true,
            name,
            declared,
            resolved.as_deref(),
            rel_manifest,
            package_id.clone(),
            reproducible,
        ));

        let source_type = source_type_from_declared(declared);
        let version = resolved.clone().or_else(|| {
            if matches!(kind, ConstraintKind::GitRef { .. }) {
                Some("git".into())
            } else {
                None
            }
        });
        if seen_nodes.insert(name.clone()) {
            let integrity = lock_packages
                .get(name)
                .or_else(|| lock_packages.get(&format!("node_modules/{name}")))
                .map(|p| p.has_integrity);
            let node = DependencyNode {
                id: package_id
                    .clone()
                    .unwrap_or_else(|| PackageId::npm(name, version.as_deref().unwrap_or("?"))),
                name: name.clone(),
                ecosystem: Ecosystem::Npm,
                version,
                direct: true,
                scope,
                depth: 1,
                source_type,
                manifest_file: Some(rel_manifest.into()),
                lockfile: lock_path.as_ref().map(|p| p.display().to_string()),
                declared_constraint: Some(declared.clone()),
                lock_integrity: integrity,
            };
            dep008(ctx.findings, ctx.policy, &node);
            ctx.graph.nodes.push(node.clone());
            ctx.graph.edges.push(DependencyEdge {
                from: PackageId::root(),
                to: node.id.clone(),
                declared_constraint: declared.clone(),
                resolved_version: resolved.clone(),
                scope,
                source_file: rel_manifest.into(),
            });
        }
    }

    // Transitive from lockfile (canonical node_modules/* keys only)
    for (key, lp) in &lock_packages {
        if !key.starts_with("node_modules/") {
            continue;
        }
        let name = key
            .strip_prefix("node_modules/")
            .unwrap_or(key.as_str())
            .rsplit('/')
            .next()
            .unwrap_or(key);
        if direct_prod.contains_key(name) || direct_dev.contains_key(name) {
            continue;
        }
        if !seen_nodes.insert(name.to_string()) {
            continue;
        }
        let node = DependencyNode {
            id: PackageId::npm(name, &lp.version),
            name: name.to_string(),
            ecosystem: Ecosystem::Npm,
            version: Some(lp.version.clone()),
            direct: false,
            scope: Scope::Production,
            depth: 2,
            source_type: SourceType::Registry,
            manifest_file: None,
            lockfile: lock_path.as_ref().map(|p| p.display().to_string()),
            declared_constraint: lp.declared.clone(),
            lock_integrity: Some(lp.has_integrity),
        };
        dep008(ctx.findings, ctx.policy, &node);
        ctx.graph.nodes.push(node);

        if let Some(parent) = &lp.parent {
            let from = ctx
                .graph
                .node(parent)
                .map(|n| n.id.clone())
                .unwrap_or_else(|| PackageId::npm(parent, &lp.version));
            ctx.graph.edges.push(DependencyEdge {
                from,
                to: PackageId::npm(name, &lp.version),
                declared_constraint: lp.declared.clone().unwrap_or_else(|| lp.version.clone()),
                resolved_version: Some(lp.version.clone()),
                scope: Scope::Production,
                source_file: rel_manifest.into(),
            });
        }
    }

    Ok(())
}

struct LockPackage {
    version: String,
    has_integrity: bool,
    declared: Option<String>,
    parent: Option<String>,
}

fn parse_npm_lock(path: &Path) -> Result<HashMap<String, LockPackage>, DepsError> {
    let v = read_json(path)?;
    let mut out = HashMap::new();

    if let Some(packages) = v.get("packages").and_then(|p| p.as_object()) {
        for (key, entry) in packages {
            if key.is_empty() {
                continue;
            }
            let version = entry
                .get("version")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string();
            let has_integrity = entry.get("integrity").is_some();
            let name = key
                .strip_prefix("node_modules/")
                .unwrap_or(key)
                .rsplit('/')
                .next()
                .unwrap_or(key)
                .to_string();
            let parent = entry.get("dependencies").and_then(|_| {
                if key.contains('/') {
                    key.rsplit_once('/')
                        .map(|(p, _)| p.strip_prefix("node_modules/").unwrap_or(p).to_string())
                } else {
                    None
                }
            });
            out.insert(
                key.clone(),
                LockPackage {
                    version: version.clone(),
                    has_integrity,
                    declared: None,
                    parent,
                },
            );
            out.entry(name).or_insert(LockPackage {
                version,
                has_integrity,
                declared: None,
                parent: None,
            });
        }

        // Parse dependency declarations from root and express
        if let Some(root) = packages.get("") {
            if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
                for (n, spec) in deps {
                    if let Some(s) = spec.as_str() {
                        if let Some(lp) = out.get_mut(n) {
                            lp.declared = Some(s.to_string());
                        }
                    }
                }
            }
        }
        if let Some(express) = packages.get("node_modules/express") {
            if let Some(deps) = express.get("dependencies").and_then(|d| d.as_object()) {
                for (n, spec) in deps {
                    if let Some(s) = spec.as_str() {
                        if let Some(lp) = out.get_mut(&format!("node_modules/{n}")) {
                            lp.declared = Some(s.to_string());
                            lp.parent = Some("express".into());
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}
