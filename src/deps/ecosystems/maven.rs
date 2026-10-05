use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::deps::detect::{DepFileKind, DetectedFile};
use crate::deps::ecosystems::classify_constraint;
use crate::deps::ecosystems::evaluate::{
    constraint_to_findings, dep001, file_in_dir, parent_dir, ScanContext,
};
use crate::deps::model::{DependencyEdge, DependencyNode, Ecosystem, PackageId, Scope, SourceType};
use crate::deps::DepsError;

pub fn scan_maven_projects(ctx: &mut ScanContext<'_>) -> Result<(), DepsError> {
    let poms = PomIndex::build(ctx.detected);
    for f in ctx.detected {
        match f.kind {
            DepFileKind::MavenPom => {
                let dir = parent_dir(&f.path);
                scan_maven_pom(ctx, &poms, &dir, &f.path)?;
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

/// A `<parent>` reference: the coordinates a child inherits from.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ParentRef {
    group: String,
    artifact: String,
    version: String,
    /// `None` when absent (Maven defaults to `../pom.xml`); `Some("")` for
    /// an explicit empty `<relativePath/>`, which disables the path lookup.
    relative_path: Option<String>,
}

/// One pom.xml in the scanned tree, reduced to what parent resolution needs.
struct PomInfo {
    /// Pom content with `NON_DEPENDENCY_SECTIONS` stripped.
    content: String,
    group: String,
    artifact: String,
    /// The project version, resolved against the pom's own properties.
    version: String,
    parent: Option<ParentRef>,
}

/// Every pom.xml found in the scan, so a child can inherit properties and
/// `<dependencyManagement>` from a parent that lives elsewhere in the repo
/// rather than only at `../pom.xml`.
struct PomIndex {
    by_path: HashMap<PathBuf, PomInfo>,
    by_coords: HashMap<(String, String, String), PathBuf>,
}

/// Parent chains longer than this are treated as broken.
const MAX_PARENT_DEPTH: usize = 64;

impl PomIndex {
    fn build(detected: &[DetectedFile]) -> Self {
        let mut by_path = HashMap::new();
        let mut by_coords = HashMap::new();
        for f in detected.iter().filter(|f| f.kind == DepFileKind::MavenPom) {
            // Unreadable or malformed poms are reported when scanned on
            // their own; here they just can't serve as parents.
            let Ok(raw) = std::fs::read_to_string(&f.path) else {
                continue;
            };
            if !raw.trim_start().starts_with('<') {
                continue;
            }
            let content = strip_sections(&raw, NON_DEPENDENCY_SECTIONS);
            let info = pom_info(content);
            let key = normalize_path(&f.path);
            if !info.group.is_empty() && !info.artifact.is_empty() && !info.version.is_empty() {
                by_coords
                    .entry((
                        info.group.clone(),
                        info.artifact.clone(),
                        info.version.clone(),
                    ))
                    .or_insert_with(|| key.clone());
            }
            by_path.insert(key, info);
        }
        Self { by_path, by_coords }
    }

    /// Stripped contents of the pom's in-repo ancestors, nearest parent
    /// first. The chain stops at the first parent not present in the scan
    /// (typically one published to a registry).
    fn ancestors(&self, pom_path: &Path) -> Vec<&str> {
        let mut out = Vec::new();
        let mut current_path = normalize_path(pom_path);
        let mut visited = HashSet::from([current_path.clone()]);
        while out.len() < MAX_PARENT_DEPTH {
            let Some(parent) = self
                .by_path
                .get(&current_path)
                .and_then(|info| info.parent.as_ref())
            else {
                break;
            };
            let Some(parent_path) = self.find_parent(&current_path, parent) else {
                break;
            };
            if !visited.insert(parent_path.clone()) {
                break;
            }
            out.push(self.by_path[&parent_path].content.as_str());
            current_path = parent_path;
        }
        out
    }

    /// Maven's lookup order: `<relativePath>` (default `../pom.xml`) when
    /// the pom there has the referenced coordinates, then any pom in the
    /// scan with exactly those coordinates.
    fn find_parent(&self, child_path: &Path, parent: &ParentRef) -> Option<PathBuf> {
        let relative = parent.relative_path.as_deref().unwrap_or("../pom.xml");
        if !relative.is_empty() {
            let candidate = normalize_path(&parent_dir(child_path).join(relative));
            for path in [candidate.join("pom.xml"), candidate] {
                if self
                    .by_path
                    .get(&path)
                    .is_some_and(|info| parent_matches(info, parent))
                {
                    return Some(path);
                }
            }
        }
        if parent.version.contains("${") {
            return None;
        }
        self.by_coords
            .get(&(
                parent.group.clone(),
                parent.artifact.clone(),
                parent.version.clone(),
            ))
            .cloned()
    }
}

/// A placeholder parent version (CI-friendly `${revision}`) can only be
/// checked on groupId/artifactId; the relativePath already pins the file.
fn parent_matches(info: &PomInfo, parent: &ParentRef) -> bool {
    info.group == parent.group
        && info.artifact == parent.artifact
        && (info.version == parent.version || parent.version.contains("${"))
}

/// Lexically collapse `.` and `..` so `a/b/../pom.xml` and `./a/pom.xml`
/// key the same entry as `a/pom.xml`.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn pom_info(content: String) -> PomInfo {
    let head = project_head(&content);
    let (own, parent) = match split_section(head, "parent") {
        Some((own, parent_block)) => (
            own,
            Some(ParentRef {
                group: extract_xml_tag(parent_block, "groupId"),
                artifact: extract_xml_tag(parent_block, "artifactId"),
                version: extract_xml_tag(parent_block, "version"),
                relative_path: extract_optional_xml_tag(parent_block, "relativePath"),
            }),
        ),
        None => (head.to_string(), None),
    };
    let mut group = extract_xml_tag(&own, "groupId");
    if group.is_empty() {
        group = parent.as_ref().map(|p| p.group.clone()).unwrap_or_default();
    }
    let artifact = extract_xml_tag(&own, "artifactId");
    let version = resolve_properties(raw_properties(&content), &content)
        .remove("project.version")
        .unwrap_or_else(|| pom_project_version(&content));
    PomInfo {
        content,
        group,
        artifact,
        version,
        parent,
    }
}

fn scan_maven_pom(
    ctx: &mut ScanContext<'_>,
    poms: &PomIndex,
    dir: &Path,
    pom_path: &Path,
) -> Result<(), DepsError> {
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

    let deps = parse_pom_dependencies(&content, &poms.ancestors(pom_path))?;
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

/// Sections whose contents are not the project's own coordinates or
/// dependencies; stripped before any dependency or property extraction.
const NON_DEPENDENCY_SECTIONS: &[&str] = &["profiles", "build", "reporting"];

/// `ancestors` are the stripped contents of the pom's in-repo parents,
/// nearest first. Their `<properties>` and `<dependencyManagement>` are
/// inherited, with nearer poms (and the pom itself) taking precedence.
fn parse_pom_dependencies(content: &str, ancestors: &[&str]) -> Result<Vec<MavenDep>, DepsError> {
    let stripped = strip_sections(content, NON_DEPENDENCY_SECTIONS);
    let mut raw_props = HashMap::new();
    let mut managed = HashMap::new();
    for pom in ancestors
        .iter()
        .rev()
        .copied()
        .chain(std::iter::once(stripped.as_str()))
    {
        raw_props.extend(raw_properties(pom));
        managed.extend(managed_versions(pom));
    }
    let props = resolve_properties(raw_props, &stripped);
    let (rest, _) = split_dependency_management(&stripped);
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

/// Remove every `<tag>...</tag>` section. Their dependency blocks are not
/// application dependencies, and a profile's `<properties>` or
/// `<dependencyManagement>` must not affect the base dependency graph, so
/// stripping runs before property and management extraction.
fn strip_sections(content: &str, tags: &[&str]) -> String {
    let mut content = content.to_string();
    for tag in tags {
        while let Some((rest, _)) = split_section(&content, tag) {
            content = rest;
        }
    }
    content
}

/// Split out the `<dependencyManagement>` section: its entries pin versions
/// for the project's dependencies but are not dependencies themselves.
/// Returns (pom without the section, the section's inner content).
fn split_dependency_management(content: &str) -> (String, &str) {
    split_section(content, "dependencyManagement").unwrap_or_else(|| (content.to_string(), ""))
}

/// Locate a `<tag>...</tag>` section and split content into (content with
/// the section removed, the section's inner content). `None` if the tag
/// isn't present or is malformed (close before open).
fn split_section<'a>(content: &'a str, tag: &str) -> Option<(String, &'a str)> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = content.find(&open)?;
    let e = content.find(&close)?;
    if s >= e {
        return None;
    }
    let inner = &content[s + open.len()..e];
    let rest = format!("{}{}", &content[..s], &content[e + close.len()..]);
    Some((rest, inner))
}

/// Versions pinned by the pom's own `<dependencyManagement>`, keyed by
/// (groupId, artifactId), placeholders left unresolved.
fn managed_versions(content: &str) -> HashMap<(String, String), String> {
    let (_, management) = split_dependency_management(content);
    parse_pom_regex(management)
        .into_iter()
        .filter(|d| !d.version.is_empty())
        .map(|d| ((d.group, d.artifact), d.version))
        .collect()
}

/// The pom's own `<properties>` entries, placeholders left unresolved.
fn raw_properties(content: &str) -> HashMap<String, String> {
    let mut props = HashMap::new();
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
    props
}

/// Resolve raw properties for the pom `content`, adding the built-in
/// `project.version`. Inherited properties resolve in the child's context,
/// so a parent's `${project.version}` means the child's version, as in Maven.
fn resolve_properties(
    mut props: HashMap<String, String>,
    content: &str,
) -> HashMap<String, String> {
    // Property values may reference other properties; resolve the map to a
    // fixed point, bounded to guard against definition cycles.
    resolve_props_fixed_point(&mut props);
    let project_version = resolve_placeholders(&pom_project_version(content), &props);
    if !project_version.is_empty() && !project_version.contains("${") {
        props.insert("project.version".to_string(), project_version);
    }
    // Properties aliasing ${project.version} (e.g. `<shared.version>`) only
    // resolve now that project.version itself is in the map.
    resolve_props_fixed_point(&mut props);
    props
}

/// Resolve `${...}` references among property values to a fixed point. A
/// resolution chain can't be longer than the number of properties without
/// a cycle, so bound the iteration count by the map size.
fn resolve_props_fixed_point(props: &mut std::collections::HashMap<String, String>) {
    for _ in 0..=props.len() {
        let resolved: std::collections::HashMap<String, String> = props
            .iter()
            .map(|(k, v)| (k.clone(), resolve_placeholders(v, props)))
            .collect();
        if resolved == *props {
            break;
        }
        *props = resolved;
    }
}

/// The part of the pom holding its own coordinates and `<parent>`: before
/// `<dependencies>` and any nested section that may carry unrelated
/// `<groupId>`/`<version>` tags of its own (plugin versions in `<build>`,
/// managed versions in `<dependencyManagement>`, etc).
fn project_head(content: &str) -> &str {
    let head = content.split("<dependencies>").next().unwrap_or(content);
    let nested_start = NON_DEPENDENCY_SECTIONS
        .iter()
        .copied()
        .chain(["dependencyManagement"])
        .filter_map(|tag| head.find(&format!("<{tag}>")))
        .min();
    match nested_start {
        Some(pos) => &head[..pos],
        None => head,
    }
}

/// The pom's own `<version>`, excluding the `<parent>` block. A child that
/// inherits its version has none of its own, so fall back to the parent's
/// (Maven's inheritance rule).
fn pom_project_version(content: &str) -> String {
    let head = project_head(content);
    if let Some((cleaned, parent)) = split_section(head, "parent") {
        let own = extract_xml_tag(&cleaned, "version");
        if !own.is_empty() {
            return own;
        }
        return extract_xml_tag(parent, "version");
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
    extract_optional_xml_tag(block, tag).unwrap_or_default()
}

/// Like `extract_xml_tag`, but tells an absent tag (`None`) apart from an
/// empty one (`<tag/>` or `<tag></tag>`, `Some("")`).
fn extract_optional_xml_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(start) = block.find(&open) {
        let rest = &block[start + open.len()..];
        if let Some(end) = rest.find(&close) {
            return Some(rest[..end].trim().to_string());
        }
    }
    let self_closing = [format!("<{tag}/>"), format!("<{tag} />")];
    if self_closing.iter().any(|t| block.contains(t.as_str())) {
        return Some(String::new());
    }
    None
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
