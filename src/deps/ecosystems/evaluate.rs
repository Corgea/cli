use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::deps::catalog::emitted_definition;
use crate::deps::detect::{DepFileKind, DetectedFile};
use crate::deps::ecosystems::classify_constraint;
use crate::deps::findings::Finding;
use crate::deps::model::{
    ConstraintKind, DependencyGraph, DependencyNode, Ecosystem, PackageId, Severity, SourceType,
};
use crate::deps::policy::Policy;
use crate::deps::DepsError;

pub struct ScanContext<'a> {
    pub root: &'a Path,
    pub policy: &'a Policy,
    pub detected: &'a [DetectedFile],
    pub graph: &'a mut DependencyGraph,
    pub findings: &'a mut Vec<Finding>,
}

pub fn scan_all(ctx: &mut ScanContext<'_>) -> Result<(), DepsError> {
    super::npm::scan_npm_projects(ctx)?;
    super::pypi::scan_pypi_projects(ctx)?;
    super::maven::scan_maven_projects(ctx)?;
    ctx.graph.sort_nodes();
    crate::deps::findings::sort_findings(ctx.findings);
    Ok(())
}

#[deprecated(note = "finding metadata is catalog-backed; use the dependency scan APIs")]
#[allow(clippy::too_many_arguments)]
pub fn add_pinning_finding(
    findings: &mut Vec<Finding>,
    code: &str,
    severity: Severity,
    title: &str,
    package: Option<PackageId>,
    source_file: &str,
    declared: Option<&str>,
    resolved: Option<&str>,
    reproducible: bool,
    recommendation: &str,
) {
    findings.push(Finding {
        id: code.into(),
        severity,
        title: title.into(),
        package,
        source_file: source_file.into(),
        declared_constraint: declared.map(str::to_string),
        resolved_version: resolved.map(str::to_string),
        recommendation: recommendation.into(),
        reproducible,
        paths: vec![vec![PackageId::root()]],
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_catalog_pinning_finding(
    findings: &mut Vec<Finding>,
    code: &str,
    package: Option<PackageId>,
    source_file: &str,
    declared: Option<&str>,
    resolved: Option<&str>,
    reproducible: bool,
    recommendation: &str,
) {
    let Some(definition) = emitted_definition(code) else {
        panic!("dependency finding code must be registered and emitted: {code}");
    };

    findings.push(Finding {
        id: definition.id.into(),
        severity: definition.severity,
        title: definition.title.into(),
        package,
        source_file: source_file.into(),
        declared_constraint: declared.map(str::to_string),
        resolved_version: resolved.map(str::to_string),
        recommendation: recommendation.into(),
        reproducible,
        paths: vec![vec![PackageId::root()]],
    });
}

#[allow(clippy::too_many_arguments)]
pub fn constraint_to_findings(
    policy: &Policy,
    kind: &ConstraintKind,
    is_direct: bool,
    _name: &str,
    declared: &str,
    resolved: Option<&str>,
    source_file: &str,
    package_id: Option<PackageId>,
    reproducible: bool,
) -> Vec<Finding> {
    if !is_direct && reproducible {
        return vec![];
    }

    let mut out = Vec::new();
    match kind {
        ConstraintKind::Exact => {}
        ConstraintKind::BoundedRange if is_direct && policy.warn_on_semver_range => {
            add_catalog_pinning_finding(
                &mut out,
                "DEP003",
                package_id,
                source_file,
                Some(declared),
                resolved,
                reproducible,
                if reproducible && resolved.is_some() {
                    "Pin to the resolved version or allow by policy because the lockfile resolves it."
                } else {
                    "Pin an exact version or explicitly allow the range by policy."
                },
            );
        }
        ConstraintKind::BoundedRange => {}
        ConstraintKind::Unbounded
            if is_direct && (policy.fail_on_wildcard || policy.fail_on_latest) =>
        {
            add_catalog_pinning_finding(
                &mut out,
                "DEP004",
                package_id,
                source_file,
                Some(declared),
                resolved,
                reproducible,
                "Pin to an exact version instead of using wildcard, latest, or unbounded ranges.",
            );
        }
        ConstraintKind::Mutable if is_direct && policy.fail_on_mutable_sources => {
            add_catalog_pinning_finding(
                &mut out,
                "DEP021",
                package_id,
                source_file,
                Some(declared),
                resolved,
                false,
                "Avoid SNAPSHOT or other mutable artifact versions; pin to an immutable release.",
            );
        }
        ConstraintKind::GitRef { mutable: true } if is_direct && policy.fail_on_mutable_sources => {
            add_catalog_pinning_finding(
                &mut out,
                "DEP005",
                package_id,
                source_file,
                Some(declared),
                resolved,
                false,
                "Pin to a commit SHA or immutable release tag instead of a branch ref.",
            );
        }
        ConstraintKind::GitRef { .. } => {}
        ConstraintKind::Url { checksum: false } if is_direct => {
            add_catalog_pinning_finding(
                &mut out,
                "DEP006",
                package_id,
                source_file,
                Some(declared),
                resolved,
                false,
                "Add an integrity checksum or pin to a registry package.",
            );
        }
        ConstraintKind::Url { .. } => {}
        _ => {}
    }
    out
}

pub fn dep001(
    findings: &mut Vec<Finding>,
    policy: &Policy,
    source_file: &str,
    ecosystem_label: &str,
) {
    if policy.fail_on_missing_lockfile {
        add_catalog_pinning_finding(
            findings,
            "DEP001",
            None,
            source_file,
            None,
            None,
            false,
            &format!(
                "Generate a {ecosystem_label} lockfile and commit it for reproducible installs."
            ),
        );
    }
}

pub fn dep002(findings: &mut Vec<Finding>, policy: &Policy, manifest_file: &str, missing: &str) {
    if policy.fail_on_stale_lockfile {
        add_catalog_pinning_finding(
            findings,
            "DEP002",
            None,
            manifest_file,
            Some(missing),
            None,
            false,
            &format!(
                "Regenerate the lockfile — `{missing}` is declared in the manifest but missing from the lockfile."
            ),
        );
    }
}

pub fn dep019_unsupported_lockfile(
    findings: &mut Vec<Finding>,
    source_file: &str,
    ecosystem_label: &str,
) {
    add_catalog_pinning_finding(
        findings,
        "DEP019",
        None,
        source_file,
        None,
        None,
        false,
        &format!(
            "{ecosystem_label} lockfile support is not implemented yet; use a supported lockfile or wait for parser support."
        ),
    );
}

pub fn dep008(findings: &mut Vec<Finding>, policy: &Policy, node: &DependencyNode) {
    if !policy.require_integrity_hashes {
        return;
    }
    if node.lock_integrity == Some(false) {
        add_catalog_pinning_finding(
            findings,
            "DEP008",
            Some(node.id.clone()),
            node.lockfile.as_deref().unwrap_or("lockfile"),
            node.declared_constraint.as_deref(),
            node.version.as_deref(),
            true,
            "Add an integrity hash to the lockfile entry for this package.",
        );
    }
}

pub fn read_json(path: &Path) -> Result<Value, DepsError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| DepsError(format!("read {}: {e}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|e| DepsError(format!("parse JSON {}: {e}", path.display())))
}

pub fn parent_dir(path: &Path) -> PathBuf {
    path.parent().unwrap_or(path).to_path_buf()
}

pub fn has_kind_in_dir(detected: &[DetectedFile], dir: &Path, kind: DepFileKind) -> bool {
    detected
        .iter()
        .any(|f| f.kind == kind && parent_dir(&f.path) == dir)
}

pub fn file_in_dir(detected: &[DetectedFile], dir: &Path, kind: DepFileKind) -> Option<PathBuf> {
    detected
        .iter()
        .find(|f| f.kind == kind && parent_dir(&f.path) == dir)
        .map(|f| f.path.clone())
}

pub fn source_type_from_declared(declared: &str) -> SourceType {
    match classify_constraint(Ecosystem::Npm, declared) {
        ConstraintKind::GitRef { mutable: true } => SourceType::GitBranch,
        ConstraintKind::GitRef { mutable: false } => SourceType::GitCommit,
        ConstraintKind::Url { .. } => SourceType::Url,
        _ => SourceType::Registry,
    }
}

pub fn dep014(findings: &mut Vec<Finding>, graph: &DependencyGraph) {
    let mut versions: HashMap<String, HashSet<String>> = HashMap::new();
    for n in &graph.nodes {
        if let Some(v) = &n.version {
            versions
                .entry(n.name.clone())
                .or_default()
                .insert(v.clone());
        }
    }
    for (name, vers) in versions {
        if vers.len() > 1 {
            add_catalog_pinning_finding(
                findings,
                "DEP014",
                Some(PackageId::npm(&name, vers.iter().next().unwrap())),
                "lockfile",
                None,
                None,
                true,
                &format!(
                    "Multiple versions of {name} present: {}",
                    vers.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            );
        }
    }
}
