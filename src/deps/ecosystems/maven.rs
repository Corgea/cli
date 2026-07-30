use std::path::Path;

use crate::deps::detect::DepFileKind;
use crate::deps::ecosystems::classify_constraint;
use crate::deps::ecosystems::evaluate::{
    constraint_to_findings, dep001, file_in_dir, parent_dir, ScanContext,
};
use crate::deps::model::{DependencyEdge, DependencyNode, Ecosystem, PackageId, Scope, SourceType};
use crate::deps::DepsError;

pub fn scan_maven_projects(ctx: &mut ScanContext<'_>) -> Result<(), DepsError> {
    for f in ctx.detected {
        match f.kind {
            DepFileKind::MavenPom => {
                let dir = parent_dir(&f.path);
                scan_maven_pom(ctx, &dir, &f.path)?;
            }
            DepFileKind::GradleBuild => {
                let dir = parent_dir(&f.path);
                scan_gradle(ctx, &dir, &f.path)?;
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone)]
struct MavenDep {
    group: String,
    artifact: String,
    version: String,
    scope: Scope,
}

fn scan_maven_pom(ctx: &mut ScanContext<'_>, dir: &Path, pom_path: &Path) -> Result<(), DepsError> {
    let rel = pom_path
        .strip_prefix(ctx.root)
        .unwrap_or(pom_path)
        .display()
        .to_string();

    let content =
        std::fs::read_to_string(pom_path).map_err(|e| DepsError(format!("read pom: {e}")))?;
    if !content.trim_start().starts_with('<') {
        return Err(DepsError(format!(
            "parse XML {}: not valid XML",
            pom_path.display()
        )));
    }

    dep001(ctx.findings, ctx.policy, &rel, "Maven");

    let deps = parse_pom_dependencies(&content)?;
    for dep in deps {
        let name = dep.artifact.clone();
        let declared = dep.version.clone();
        let kind = classify_constraint(Ecosystem::Maven, &declared);
        let package_id = PackageId::maven(&dep.group, &dep.artifact, &dep.version);
        ctx.findings.extend(constraint_to_findings(
            ctx.policy,
            &kind,
            true,
            &name,
            &declared,
            Some(&dep.version),
            &rel,
            Some(package_id.clone()),
            false,
        ));
        ctx.graph.edges.push(DependencyEdge {
            from: PackageId::root(),
            to: package_id.clone(),
            declared_constraint: declared.clone(),
            resolved_version: Some(dep.version.clone()),
            scope: dep.scope,
            source_file: rel.clone(),
        });
        ctx.graph.nodes.push(DependencyNode {
            id: package_id,
            name,
            ecosystem: Ecosystem::Maven,
            version: Some(dep.version),
            direct: true,
            scope: dep.scope,
            depth: 1,
            source_type: SourceType::Registry,
            manifest_file: Some(rel.clone()),
            lockfile: None,
            declared_constraint: Some(declared),
            lock_integrity: None,
            lock_resolved: None,
            lock_integrity_hash: None,
        });
    }
    let _ = dir;
    Ok(())
}

fn parse_pom_dependencies(content: &str) -> Result<Vec<MavenDep>, DepsError> {
    let props = parse_pom_properties(content);
    let (rest, management) = split_dependency_management(content);
    let managed: std::collections::HashMap<(String, String), String> = parse_pom_regex(management)
        .into_iter()
        .filter(|d| !d.version.is_empty())
        .map(|d| ((d.group, d.artifact), d.version))
        .collect();
    let mut deps = parse_pom_regex(&rest);
    for dep in &mut deps {
        if dep.version.is_empty() {
            if let Some(v) = managed.get(&(dep.group.clone(), dep.artifact.clone())) {
                dep.version = v.clone();
            }
        }
        dep.version = resolve_placeholders(&dep.version, &props);
    }
    Ok(deps)
}

/// Split out the `<dependencyManagement>` section: its entries pin versions
/// for the project's dependencies but are not dependencies themselves.
/// Returns (pom without the section, the section's inner content).
fn split_dependency_management(content: &str) -> (String, &str) {
    const OPEN: &str = "<dependencyManagement>";
    const CLOSE: &str = "</dependencyManagement>";
    if let (Some(s), Some(e)) = (content.find(OPEN), content.find(CLOSE)) {
        if s < e {
            let management = &content[s + OPEN.len()..e];
            let rest = format!("{}{}", &content[..s], &content[e + CLOSE.len()..]);
            return (rest, management);
        }
    }
    (content.to_string(), "")
}

/// Collect `<properties>` entries plus the built-in `project.version`.
fn parse_pom_properties(content: &str) -> std::collections::HashMap<String, String> {
    let mut props = std::collections::HashMap::new();
    if let Some(start) = content.find("<properties>") {
        let rest = &content[start + "<properties>".len()..];
        if let Some(end) = rest.find("</properties>") {
            let mut block = &rest[..end];
            while let Some(open_start) = block.find('<') {
                let after = &block[open_start + 1..];
                let Some(open_end) = after.find('>') else {
                    break;
                };
                let tag = after[..open_end].trim();
                let body = &after[open_end + 1..];
                if tag.starts_with('/') || tag.starts_with('!') || tag.ends_with('/') {
                    block = body;
                    continue;
                }
                let close = format!("</{tag}>");
                match body.find(&close) {
                    Some(close_pos) => {
                        props.insert(tag.to_string(), body[..close_pos].trim().to_string());
                        block = &body[close_pos + close.len()..];
                    }
                    None => block = body,
                }
            }
        }
    }
    // Property values may reference other properties; resolve the map to a
    // fixed point, bounded to guard against definition cycles.
    for _ in 0..5 {
        let resolved: std::collections::HashMap<String, String> = props
            .iter()
            .map(|(k, v)| (k.clone(), resolve_placeholders(v, &props)))
            .collect();
        if resolved == props {
            break;
        }
        props = resolved;
    }
    let project_version = resolve_placeholders(&pom_project_version(content), &props);
    if !project_version.is_empty() && !project_version.contains("${") {
        props.insert("project.version".to_string(), project_version);
    }
    props
}

/// The pom's own `<version>`: first `<version>` before `<dependencies>`,
/// excluding the `<parent>` block. A child that inherits its version has
/// none of its own, so fall back to the parent's (Maven's inheritance rule).
fn pom_project_version(content: &str) -> String {
    let head = content.split("<dependencies>").next().unwrap_or(content);
    if let (Some(ps), Some(pe)) = (head.find("<parent>"), head.find("</parent>")) {
        if ps < pe {
            let cleaned = format!("{}{}", &head[..ps], &head[pe + "</parent>".len()..]);
            let own = extract_xml_tag(&cleaned, "version");
            if !own.is_empty() {
                return own;
            }
            return extract_xml_tag(&head[ps..pe], "version");
        }
    }
    extract_xml_tag(head, "version")
}

/// Substitute `${name}` placeholders; unresolved ones pass through unchanged.
fn resolve_placeholders(raw: &str, props: &std::collections::HashMap<String, String>) -> String {
    if !raw.contains("${") {
        return raw.to_string();
    }
    let mut out = String::new();
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let key = &after[..end];
        match props.get(key) {
            Some(v) => out.push_str(v),
            None => out.push_str(&rest[start..start + 2 + end + 1]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn parse_pom_regex(content: &str) -> Vec<MavenDep> {
    let mut deps = Vec::new();
    let dep_blocks: Vec<&str> = content.split("<dependency>").skip(1).collect();
    for block in dep_blocks {
        let group = extract_xml_tag(block, "groupId");
        let artifact = extract_xml_tag(block, "artifactId");
        let version = extract_xml_tag(block, "version");
        let scope = extract_xml_tag(block, "scope");
        if artifact.is_empty() {
            continue;
        }
        deps.push(MavenDep {
            group,
            artifact: artifact.clone(),
            version: version.clone(),
            scope: if scope == "test" {
                Scope::Development
            } else {
                Scope::Production
            },
        });
    }
    deps
}

fn extract_xml_tag(block: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(start) = block.find(&open) {
        let rest = &block[start + open.len()..];
        if let Some(end) = rest.find(&close) {
            return rest[..end].trim().to_string();
        }
    }
    String::new()
}

fn scan_gradle(ctx: &mut ScanContext<'_>, dir: &Path, gradle_path: &Path) -> Result<(), DepsError> {
    let rel = gradle_path
        .strip_prefix(ctx.root)
        .unwrap_or(gradle_path)
        .display()
        .to_string();
    let content =
        std::fs::read_to_string(gradle_path).map_err(|e| DepsError(format!("read gradle: {e}")))?;

    let lock_path = file_in_dir(ctx.detected, dir, DepFileKind::GradleLockfile);
    let locked = lock_path
        .as_ref()
        .map(|p| parse_gradle_lockfile(p))
        .transpose()?
        .unwrap_or_default();

    if lock_path.is_none() {
        dep001(ctx.findings, ctx.policy, &rel, "Gradle");
    }

    let deps = parse_gradle_deps(&content);
    for (coords, declared, scope) in deps {
        let parts: Vec<&str> = coords.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        let group = parts[0];
        let artifact = parts[1];
        let name = artifact.to_string();
        let resolved = locked
            .get(&format!("{group}:{artifact}"))
            .cloned()
            .or_else(|| {
                if !declared.contains('+') && !declared.eq_ignore_ascii_case("latest.release") {
                    Some(declared.clone())
                } else {
                    locked.get(&format!("{group}:{artifact}")).cloned()
                }
            });
        let version = resolved.clone().unwrap_or_else(|| declared.clone());
        let kind = classify_constraint(Ecosystem::Maven, &declared);
        let reproducible = lock_path.is_some() && resolved.is_some();
        let package_id = PackageId::maven(group, artifact, &version);
        ctx.findings.extend(constraint_to_findings(
            ctx.policy,
            &kind,
            true,
            &name,
            &declared,
            resolved.as_deref(),
            &rel,
            Some(package_id.clone()),
            reproducible,
        ));
        ctx.graph.nodes.push(DependencyNode {
            id: package_id,
            name,
            ecosystem: Ecosystem::Maven,
            version: Some(version),
            direct: true,
            scope,
            depth: 1,
            source_type: SourceType::Registry,
            manifest_file: Some(rel.clone()),
            lockfile: lock_path.as_ref().map(|p| p.display().to_string()),
            declared_constraint: Some(declared),
            lock_integrity: None,
            lock_resolved: None,
            lock_integrity_hash: None,
        });
    }
    Ok(())
}

fn parse_gradle_deps(content: &str) -> Vec<(String, String, Scope)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("implementation ") || line.starts_with("testImplementation ") {
            let scope = if line.starts_with("test") {
                Scope::Development
            } else {
                Scope::Production
            };
            if let Some(spec) = line.split('\'').nth(1) {
                let parts: Vec<&str> = spec.split(':').collect();
                if parts.len() >= 3 {
                    let coord = format!("{}:{}", parts[0], parts[1]);
                    out.push((coord, parts[2].to_string(), scope));
                }
            }
        }
    }
    out
}

fn parse_gradle_lockfile(
    path: &Path,
) -> Result<std::collections::HashMap<String, String>, DepsError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| DepsError(format!("read gradle.lockfile: {e}")))?;
    let mut out = std::collections::HashMap::new();
    for line in content.lines() {
        if line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        if let Some((coord, _)) = line.split_once('=') {
            let parts: Vec<&str> = coord.split(':').collect();
            if parts.len() >= 3 {
                out.insert(format!("{}:{}", parts[0], parts[1]), parts[2].to_string());
            }
        }
    }
    Ok(out)
}
