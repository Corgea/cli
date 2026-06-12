use std::path::Path;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::deps::detect::DepFileKind;
use crate::deps::ecosystems::classify_constraint;
use crate::deps::ecosystems::evaluate::{
    constraint_to_findings, dep001, file_in_dir, parent_dir, ScanContext,
};
use crate::deps::model::{DependencyNode, Ecosystem, PackageId, Scope, SourceType};
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

#[derive(Default)]
struct PartialMavenDep {
    group: String,
    artifact: String,
    version: String,
    scope: String,
}

#[derive(Clone, Copy)]
enum MavenField {
    Group,
    Artifact,
    Version,
    Scope,
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
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut deps = Vec::new();
    let mut current: Option<PartialMavenDep> = None;
    let mut dep_depth = 0usize;
    let mut field: Option<MavenField> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                let tag = local_xml_name(name.as_ref());
                if current.is_none() && tag == b"dependency" {
                    current = Some(PartialMavenDep::default());
                    dep_depth = 1;
                    field = None;
                } else if current.is_some() {
                    if dep_depth == 1 {
                        field = maven_field_from_tag(tag);
                    }
                    dep_depth += 1;
                }
            }
            Ok(Event::Text(text)) => {
                if dep_depth == 2 {
                    if let (Some(dep), Some(active_field)) = (current.as_mut(), field) {
                        let value = text
                            .unescape()
                            .map(|value| value.trim().to_string())
                            .unwrap_or_else(|_| {
                                String::from_utf8_lossy(text.as_ref()).trim().to_string()
                            });
                        if !value.is_empty() {
                            set_maven_field(dep, active_field, value);
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                if current.is_some() {
                    let name = e.name();
                    let tag = local_xml_name(name.as_ref());
                    if dep_depth == 2 {
                        field = None;
                    }
                    if tag == b"dependency" && dep_depth == 1 {
                        let dep = current.take().expect("dependency started");
                        if !dep.artifact.is_empty() {
                            deps.push(MavenDep {
                                group: dep.group,
                                artifact: dep.artifact,
                                version: dep.version,
                                scope: if dep.scope == "test" {
                                    Scope::Development
                                } else {
                                    Scope::Production
                                },
                            });
                        }
                        field = None;
                    } else {
                        dep_depth = dep_depth.saturating_sub(1);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(DepsError(format!("parse XML: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    Ok(deps)
}

fn local_xml_name(name: &[u8]) -> &[u8] {
    name.rsplit(|b| *b == b':').next().unwrap_or(name)
}

fn maven_field_from_tag(tag: &[u8]) -> Option<MavenField> {
    match tag {
        b"groupId" => Some(MavenField::Group),
        b"artifactId" => Some(MavenField::Artifact),
        b"version" => Some(MavenField::Version),
        b"scope" => Some(MavenField::Scope),
        _ => None,
    }
}

fn set_maven_field(dep: &mut PartialMavenDep, field: MavenField, value: String) {
    match field {
        MavenField::Group => dep.group = value,
        MavenField::Artifact => dep.artifact = value,
        MavenField::Version => dep.version = value,
        MavenField::Scope => dep.scope = value,
    }
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
