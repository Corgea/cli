use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::deps::detect::DepFileKind;
use crate::deps::ecosystems::classify_constraint;
use crate::deps::ecosystems::evaluate::{
    constraint_to_findings, dep001, file_in_dir, parent_dir, ScanContext,
};
use crate::deps::model::{DependencyEdge, DependencyNode, Ecosystem, PackageId, Scope, SourceType};
use crate::deps::DepsError;

pub fn scan_pypi_projects(ctx: &mut ScanContext<'_>) -> Result<(), DepsError> {
    let mut handled_dirs: HashSet<_> = HashSet::new();

    for f in ctx.detected {
        if f.kind == DepFileKind::PyProject {
            let dir = parent_dir(&f.path);
            if file_in_dir(ctx.detected, &dir, DepFileKind::PoetryLock).is_some() {
                if !handled_dirs.insert(dir.clone()) {
                    continue;
                }
                scan_poetry(ctx, &dir)?;
            }
        }
    }

    for f in ctx.detected {
        if f.kind == DepFileKind::PipRequirements {
            let dir = parent_dir(&f.path);
            let has_lock = ctx
                .detected
                .iter()
                .any(|x| parent_dir(&x.path) == dir && matches!(x.kind, DepFileKind::PoetryLock));
            if !has_lock && !handled_dirs.contains(&dir) {
                scan_requirements(ctx, &dir, &f.path)?;
            }
        }
    }
    Ok(())
}

fn scan_poetry(ctx: &mut ScanContext<'_>, dir: &Path) -> Result<(), DepsError> {
    let pyproject = file_in_dir(ctx.detected, dir, DepFileKind::PyProject).unwrap();
    let poetry_lock = file_in_dir(ctx.detected, dir, DepFileKind::PoetryLock).unwrap();
    let rel_py = pyproject
        .strip_prefix(ctx.root)
        .unwrap_or(&pyproject)
        .display()
        .to_string();

    let content = std::fs::read_to_string(&pyproject)
        .map_err(|e| DepsError(format!("read pyproject: {e}")))?;
    let toml: toml::Value =
        toml::from_str(&content).map_err(|e| DepsError(format!("parse pyproject: {e}")))?;

    let mut direct: HashMap<String, (String, Scope)> = HashMap::new();
    if let Some(deps) = toml
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (k, v) in deps {
            if k == "python" {
                continue;
            }
            let spec = v.as_str().unwrap_or(&v.to_string()).to_string();
            direct.insert(k.clone(), (spec, Scope::Production));
        }
    }
    if let Some(deps) = toml
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("group"))
        .and_then(|g| g.get("dev"))
        .and_then(|d| d.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (k, v) in deps {
            let spec = v.as_str().unwrap_or(&v.to_string()).to_string();
            direct.insert(k.clone(), (spec, Scope::Development));
        }
    }

    let locked = parse_poetry_lock(&poetry_lock)?;
    let mut seen = HashSet::new();

    for (name, (declared, scope)) in &direct {
        let resolved = locked.get(name).map(|p| p.version.as_str());
        let reproducible = resolved.is_some();
        let kind = classify_constraint(Ecosystem::PyPI, declared);
        ctx.findings.extend(constraint_to_findings(
            ctx.policy,
            &kind,
            true,
            name,
            declared,
            resolved,
            &rel_py,
            resolved.map(|v| PackageId::pypi(name, v)),
            reproducible,
        ));
        if seen.insert(name.clone()) {
            let node = DependencyNode {
                id: resolved
                    .map(|v| PackageId::pypi(name, v))
                    .unwrap_or_else(|| PackageId::pypi(name, "?")),
                name: name.clone(),
                ecosystem: Ecosystem::PyPI,
                version: resolved.map(str::to_string),
                direct: true,
                scope: *scope,
                depth: 1,
                source_type: SourceType::Registry,
                manifest_file: Some(rel_py.clone()),
                lockfile: Some(poetry_lock.display().to_string()),
                declared_constraint: Some(declared.clone()),
                lock_integrity: None,
            };
            ctx.graph.edges.push(DependencyEdge {
                from: PackageId::root(),
                to: node.id().clone(),
                declared_constraint: declared.clone(),
                resolved_version: resolved.map(str::to_string),
                scope: *scope,
                source_file: rel_py.clone(),
            });
            ctx.graph.nodes.push(node);
        }
    }

    for (name, package) in &locked {
        if direct.contains_key(name) {
            continue;
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        ctx.graph.nodes.push(DependencyNode {
            id: PackageId::pypi(name, &package.version),
            name: name.clone(),
            ecosystem: Ecosystem::PyPI,
            version: Some(package.version.clone()),
            direct: false,
            scope: Scope::Production,
            depth: 2,
            source_type: SourceType::Registry,
            manifest_file: None,
            lockfile: Some(poetry_lock.display().to_string()),
            declared_constraint: first_parent_constraint(&locked, name),
            lock_integrity: None,
        });
    }

    for (parent_name, parent_package) in &locked {
        for (child_name, declared) in &parent_package.dependencies {
            let Some(child_package) = locked.get(child_name) else {
                continue;
            };
            ctx.graph.edges.push(DependencyEdge {
                from: PackageId::pypi(parent_name, &parent_package.version),
                to: PackageId::pypi(child_name, &child_package.version),
                declared_constraint: declared.clone(),
                resolved_version: Some(child_package.version.clone()),
                scope: Scope::Production,
                source_file: rel_py.clone(),
            });
        }
    }

    Ok(())
}

fn scan_requirements(
    ctx: &mut ScanContext<'_>,
    dir: &Path,
    req_path: &Path,
) -> Result<(), DepsError> {
    let rel = req_path
        .strip_prefix(ctx.root)
        .unwrap_or(req_path)
        .display()
        .to_string();
    dep001(ctx.findings, ctx.policy, &rel, "Python");

    let content = std::fs::read_to_string(req_path)
        .map_err(|e| DepsError(format!("read requirements: {e}")))?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, declared) = parse_requirement_line(line);
        let kind = classify_constraint(Ecosystem::PyPI, &declared);
        let is_exact = matches!(kind, crate::deps::model::ConstraintKind::Exact);
        ctx.findings.extend(constraint_to_findings(
            ctx.policy,
            &kind,
            true,
            &name,
            &declared,
            if is_exact {
                declared.strip_prefix("==").map(str::trim)
            } else {
                None
            },
            &rel,
            is_exact
                .then(|| {
                    PackageId::pypi(
                        &name,
                        declared.strip_prefix("==").unwrap_or(&declared).trim(),
                    )
                })
                .or_else(|| {
                    if declared.contains("git+") {
                        Some(PackageId::pypi(&name, "git"))
                    } else {
                        Some(PackageId::pypi(&name, "?"))
                    }
                }),
            false,
        ));
        if is_exact {
            let ver = declared.strip_prefix("==").unwrap_or(&declared);
            ctx.graph.nodes.push(DependencyNode {
                id: PackageId::pypi(&name, ver),
                name: name.clone(),
                ecosystem: Ecosystem::PyPI,
                version: Some(ver.to_string()),
                direct: true,
                scope: Scope::Production,
                depth: 1,
                source_type: if declared.contains("git+") {
                    SourceType::GitBranch
                } else {
                    SourceType::Registry
                },
                manifest_file: Some(rel.clone()),
                lockfile: None,
                declared_constraint: Some(declared.to_string()),
                lock_integrity: None,
            });
        } else if declared.contains("git+") {
            ctx.graph.nodes.push(DependencyNode {
                id: PackageId::pypi(&name, "git"),
                name: name.clone(),
                ecosystem: Ecosystem::PyPI,
                version: Some("git".into()),
                direct: true,
                scope: Scope::Production,
                depth: 1,
                source_type: SourceType::GitBranch,
                manifest_file: Some(rel.clone()),
                lockfile: None,
                declared_constraint: Some(declared.to_string()),
                lock_integrity: None,
            });
        }
    }
    let _ = dir;
    Ok(())
}

fn parse_requirement_line(line: &str) -> (String, String) {
    let line = line.trim();
    if let Some((name, _rest)) = line.split_once('@') {
        return (name.trim().to_string(), line.to_string());
    }
    if line.contains("==") {
        let name = line.split("==").next().unwrap_or(line).trim();
        return (name.to_string(), line.to_string());
    }
    if let Some(idx) = line.find(">=") {
        let name = line[..idx].trim();
        return (name.to_string(), line.to_string());
    }
    (line.to_string(), line.to_string())
}

#[derive(Debug, Clone)]
struct PoetryLockPackage {
    version: String,
    dependencies: HashMap<String, String>,
}

fn parse_poetry_lock(path: &Path) -> Result<HashMap<String, PoetryLockPackage>, DepsError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| DepsError(format!("read poetry.lock: {e}")))?;
    if content.trim().is_empty() || !content.contains("[[package]]") {
        return Err(DepsError(format!(
            "parse poetry.lock {}: truncated or invalid",
            path.display()
        )));
    }
    let mut out = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_dependencies: HashMap<String, String> = HashMap::new();
    let mut in_dependencies = false;
    for line in content.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            insert_poetry_package(
                &mut out,
                current_name.take(),
                current_version.take(),
                std::mem::take(&mut current_dependencies),
            );
            in_dependencies = false;
            continue;
        }
        if line.starts_with('[') {
            in_dependencies = line == "[package.dependencies]";
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        }
        if let Some(rest) = line.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
        }
        if in_dependencies {
            if let Some((name, spec)) = line.split_once('=') {
                current_dependencies.insert(
                    name.trim().trim_matches('"').to_string(),
                    spec.trim().trim_matches('"').to_string(),
                );
            }
        }
    }
    insert_poetry_package(
        &mut out,
        current_name,
        current_version,
        current_dependencies,
    );
    Ok(out)
}

fn insert_poetry_package(
    packages: &mut HashMap<String, PoetryLockPackage>,
    name: Option<String>,
    version: Option<String>,
    dependencies: HashMap<String, String>,
) {
    if let (Some(name), Some(version)) = (name, version) {
        packages.insert(
            name,
            PoetryLockPackage {
                version,
                dependencies,
            },
        );
    }
}

fn first_parent_constraint(
    packages: &HashMap<String, PoetryLockPackage>,
    child_name: &str,
) -> Option<String> {
    packages
        .values()
        .find_map(|package| package.dependencies.get(child_name).cloned())
}
