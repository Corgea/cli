use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::deps::detect::DepFileKind;
use crate::deps::ecosystems::classify_constraint;
use crate::deps::ecosystems::evaluate::{
    constraint_to_findings, dep002, dep008, dep019_unsupported_lockfile, file_in_dir, parent_dir,
    read_json, source_type_from_declared, ScanContext,
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
    let unsupported_lock_path = file_in_dir(ctx.detected, dir, DepFileKind::YarnLockfile)
        .or_else(|| file_in_dir(ctx.detected, dir, DepFileKind::PnpmLockfile));

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
    if lock_path.is_none() {
        if let Some(lock) = unsupported_lock_path.as_ref() {
            let rel_lock = lock
                .strip_prefix(ctx.root)
                .unwrap_or(lock)
                .display()
                .to_string();
            dep019_unsupported_lockfile(ctx.findings, &rel_lock, "npm");
        }
    }

    let lock_has = |name: &str| -> bool {
        lock_packages.contains_key(name)
            || lock_packages.contains_key(&format!("node_modules/{name}"))
    };

    if ctx.policy.fail_on_stale_lockfile && unsupported_lock_path.is_none() {
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
            let lock_package = lock_packages
                .get(name)
                .or_else(|| lock_packages.get(&format!("node_modules/{name}")))
                .cloned();
            let has_integrity = lock_package.as_ref().map(|p| p.has_integrity);
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
                lock_integrity: has_integrity,
                lock_resolved: lock_package.as_ref().and_then(|p| p.resolved.clone()),
                lock_integrity_hash: lock_package.as_ref().and_then(|p| p.integrity.clone()),
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

    // Transitive nodes from lockfile (canonical node_modules/* keys only).
    for (key, lp) in &lock_packages {
        if !key.starts_with("node_modules/") {
            continue;
        }
        let name = package_name_from_lock_key(key);
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
            lock_resolved: lp.resolved.clone(),
            lock_integrity_hash: lp.integrity.clone(),
        };
        dep008(ctx.findings, ctx.policy, &node);
        ctx.graph.nodes.push(node);
    }

    for (key, lp) in &lock_packages {
        if !key.starts_with("node_modules/") {
            continue;
        }
        if let Some(parent) = &lp.parent {
            let name = package_name_from_lock_key(key);
            let Some(child) = ctx.graph.node(name) else {
                continue;
            };
            let Some(parent_node) = ctx.graph.node(parent) else {
                continue;
            };
            ctx.graph.edges.push(DependencyEdge {
                from: parent_node.id().clone(),
                to: child.id().clone(),
                declared_constraint: lp.declared.clone().unwrap_or_else(|| lp.version.clone()),
                resolved_version: Some(lp.version.clone()),
                scope: Scope::Production,
                source_file: rel_manifest.into(),
            });
        }
    }

    Ok(())
}

#[derive(Clone)]
struct LockPackage {
    version: String,
    has_integrity: bool,
    resolved: Option<String>,
    integrity: Option<String>,
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
            let resolved = entry
                .get("resolved")
                .and_then(|x| x.as_str())
                .map(str::to_string);
            let integrity = entry
                .get("integrity")
                .and_then(|x| x.as_str())
                .map(str::to_string);
            let name = package_name_from_lock_key(key).to_string();
            out.insert(
                key.clone(),
                LockPackage {
                    version: version.clone(),
                    has_integrity,
                    resolved: resolved.clone(),
                    integrity: integrity.clone(),
                    declared: None,
                    parent: None,
                },
            );
            out.entry(name).or_insert(LockPackage {
                version,
                has_integrity,
                resolved,
                integrity,
                declared: None,
                parent: None,
            });
        }

        for (parent_key, entry) in packages {
            let Some(deps) = entry.get("dependencies").and_then(|d| d.as_object()) else {
                continue;
            };
            let parent = if parent_key.is_empty() {
                None
            } else {
                Some(package_name_from_lock_key(parent_key).to_string())
            };
            for (child_name, spec) in deps {
                let Some(spec) = spec.as_str() else {
                    continue;
                };
                if let Some(child_key) = child_lock_key(parent_key, child_name, packages) {
                    if let Some(lp) = out.get_mut(&child_key) {
                        lp.declared = Some(spec.to_string());
                        lp.parent = parent.clone();
                    }
                    if parent.is_none() {
                        if let Some(lp) = out.get_mut(child_name) {
                            lp.declared = Some(spec.to_string());
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

fn package_name_from_lock_key(key: &str) -> &str {
    let package_path = key
        .rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .unwrap_or(key);
    let mut parts = package_path.split('/');
    let first = parts.next().unwrap_or(package_path);
    if first.starts_with('@') {
        if let Some(second) = parts.next() {
            let scoped_len = first.len() + 1 + second.len();
            return &package_path[..scoped_len];
        }
    }
    first
}

fn child_lock_key(
    parent_key: &str,
    child_name: &str,
    packages: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let nested = if parent_key.is_empty() {
        format!("node_modules/{child_name}")
    } else {
        format!("{parent_key}/node_modules/{child_name}")
    };
    if packages.contains_key(&nested) {
        return Some(nested);
    }
    let hoisted = format!("node_modules/{child_name}");
    packages.contains_key(&hoisted).then_some(hoisted)
}
