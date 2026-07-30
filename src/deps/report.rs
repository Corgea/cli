use serde_json::{json, Value};
use std::fmt::Write as _;

use crate::deps::detect::DetectedFile;
use crate::deps::model::{DependencyGraph, Ecosystem};
use crate::deps::Inventory;

/// Load the policy at `root`, scan the tree, and emit a CycloneDX SBOM.
pub fn sbom(root: &std::path::Path) -> Result<Value, crate::deps::DepsError> {
    let policy = crate::deps::run::load_policy(root)?;
    let inv = crate::deps::scan(root, &policy)?;
    warn_unsupported_ecosystems(&inv.detected_files);
    Ok(to_cyclonedx(&inv))
}

/// Print one deduplicated stderr warning per detected ecosystem that
/// `to_cyclonedx` does not emit components for (currently Go and Cargo),
/// so `deps sbom` / `scan --sbom` don't silently produce an empty-looking
/// SBOM for those trees.
pub fn warn_unsupported_ecosystems(detected: &[DetectedFile]) {
    let mut by_ecosystem: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();

    for f in detected {
        let Some(label) = unsupported_ecosystem_label(f.ecosystem) else {
            continue;
        };
        let file_name = f
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        by_ecosystem.entry(label).or_default().insert(file_name);
    }

    for (label, files) in by_ecosystem {
        let files: Vec<String> = files.into_iter().collect();
        eprintln!(
            "Warning: detected {} but {} is not yet included in SBOMs",
            files.join(", "),
            label
        );
    }
}

fn unsupported_ecosystem_label(ecosystem: Ecosystem) -> Option<&'static str> {
    if crate::deps::ecosystems::is_graphed(ecosystem) {
        return None;
    }
    Some(match ecosystem {
        Ecosystem::Go => "Go",
        Ecosystem::Cargo => "Cargo",
        _ => "this ecosystem",
    })
}

pub fn to_json(inv: &Inventory) -> Value {
    inventory_to_json(inv)
}

pub fn to_sarif(inv: &Inventory) -> Value {
    let rules: Vec<Value> = inv
        .findings
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "name": f.title,
                "shortDescription": { "text": f.title },
            })
        })
        .collect();

    let results: Vec<Value> = inv
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.id,
                "level": severity_to_sarif(f.severity),
                "message": { "text": f.recommendation },
            })
        })
        .collect();

    json!({
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "corgea-deps",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

fn severity_to_sarif(sev: crate::deps::model::Severity) -> &'static str {
    use crate::deps::model::Severity;
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// A version is resolved when it names a concrete release — not empty, not
/// the `?` placeholder for lockfile-less manifests, not an unsubstituted
/// `${...}` Maven property. Unresolved versions (and the purls fabricated
/// from them) must be omitted, or the document fails CycloneDX 1.7 validation.
fn is_resolved_version(version: &str) -> bool {
    !version.is_empty() && version != "?" && !version.contains("${")
}

pub fn to_cyclonedx(inv: &Inventory) -> Value {
    let graph = &inv.graph;
    // Deduplicate by bom-ref: multi-module trees list the same package once
    // per manifest, but the schema sets uniqueItems on components.
    let mut components: std::collections::BTreeMap<&str, Value> = std::collections::BTreeMap::new();
    for n in graph.nodes.iter().filter(|n| n.name() != "root") {
        let mut c = json!({
            "type": "library",
            "bom-ref": n.id().0,
            "name": n.name(),
        });
        if let Some(v) = n.version().filter(|v| is_resolved_version(v)) {
            c["version"] = json!(v);
            c["purl"] = json!(n.id().0);
        }
        components.entry(&n.id().0).or_insert(c);
    }
    let components: Vec<Value> = components.into_values().collect();

    let mut depends_on: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
        std::collections::BTreeMap::new();
    for e in &graph.edges {
        depends_on.entry(&e.from.0).or_default().insert(&e.to.0);
    }
    let deps: Vec<Value> = depends_on
        .iter()
        .map(|(from, tos)| {
            json!({
                "ref": from,
                "dependsOn": tos,
            })
        })
        .collect();

    let root_name = std::fs::canonicalize(&inv.root)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "project".to_string());

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "corgea",
                    "version": env!("CARGO_PKG_VERSION"),
                }]
            },
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": root_name,
            },
        },
        "components": components,
        "dependencies": deps,
    })
}

pub fn graph_nodes_json(graph: &DependencyGraph) -> Vec<Value> {
    graph
        .nodes
        .iter()
        .map(|n| {
            json!({
                "id": n.id().0,
                "name": n.name(),
                "version": n.version(),
                "direct": n.is_direct(),
                "scope": format!("{:?}", n.scope()),
                "depth": n.depth(),
            })
        })
        .collect()
}

pub fn inventory_to_json(inv: &Inventory) -> Value {
    let nodes = graph_nodes_json(&inv.graph);

    let findings: Vec<Value> = inv
        .findings
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "severity": format!("{:?}", f.severity),
                "title": f.title,
                "package": f.package.as_ref().map(|p| p.0.clone()),
                "reproducible": f.reproducible,
                "recommendation": f.recommendation,
            })
        })
        .collect();

    json!({
        "root": inv.root,
        "nodes": nodes,
        "findings": findings,
    })
}

pub fn table_output(inv: &Inventory) -> String {
    let mut out = String::new();
    writeln!(&mut out, "Corgea dependency inventory\n").unwrap();
    writeln!(
        &mut out,
        "Detected {} dependency file(s)",
        inv.detected_files.len()
    )
    .unwrap();
    writeln!(
        &mut out,
        "Inventory: {} packages, {} findings\n",
        inv.graph.nodes.len(),
        inv.findings.len()
    )
    .unwrap();

    let mut by_sev: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in &inv.findings {
        *by_sev.entry(format!("{:?}", f.severity)).or_default() += 1;
    }
    for (sev, count) in by_sev {
        writeln!(&mut out, "  {sev}: {count}").unwrap();
    }

    for f in &inv.findings {
        let pkg = f.package.as_ref().map(|p| p.name()).unwrap_or("project");
        writeln!(&mut out, "\n  {}  {:?}  {}", f.id, f.severity, f.title).unwrap();
        writeln!(&mut out, "    package: {pkg}").unwrap();
        writeln!(&mut out, "    {}", f.recommendation).unwrap();
    }
    out
}

pub fn print_table(inv: &Inventory) {
    print!("{}", table_output(inv));
}
