use serde_json::{json, Value};
use std::fmt::Write as _;

use crate::deps::model::DependencyGraph;
use crate::deps::Inventory;

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

pub fn to_cyclonedx(graph: &DependencyGraph) -> Value {
    let components: Vec<Value> = graph
        .nodes
        .iter()
        .filter(|n| n.name() != "root")
        .map(|n| {
            json!({
                "type": "library",
                "name": n.name(),
                "version": n.version(),
                "purl": n.id().0,
            })
        })
        .collect();

    let deps: Vec<Value> = graph
        .edges
        .iter()
        .map(|e| {
            json!({
                "ref": e.from.0,
                "dependsOn": [e.to.0],
            })
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": components,
        "dependencies": deps,
    })
}

pub fn inventory_to_json(inv: &Inventory) -> Value {
    let nodes: Vec<Value> = inv
        .graph
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
        .collect();

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
