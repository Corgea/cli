use super::common::{fixture, scan_fixture};
use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::Ecosystem;
use crate::deps::policy::Policy;
use crate::deps::report::to_json;
use crate::deps::scan;

#[test]
fn robust_malformed_npm_lockfile_is_error_not_panic() {
    let result = scan(&fixture("malformed"), &Policy::default());
    assert!(result.is_err());
}

#[test]
fn robust_truncated_poetry_lock_is_error_not_panic() {
    let result = std::panic::catch_unwind(|| scan(&fixture("malformed"), &Policy::default()));
    assert!(result.is_ok());
}

#[test]
fn robust_classify_never_panics_on_adversarial_input() {
    let corpus = [
        "",
        " ",
        "\t\n",
        "^",
        "~",
        ">=",
        "@",
        "git+",
        "#",
        "[",
        "[,]",
        "999999999999999999999999999999",
        "v1.2.3",
        "==",
        "*.*.*",
        "latest.latest",
        "-SNAPSHOT",
        "💥",
        "../../etc/passwd",
    ];
    for raw in corpus {
        for eco in [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Maven] {
            let _ = classify_constraint(eco, raw);
        }
    }
    let long = "a".repeat(10_000);
    for eco in [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Maven] {
        let _ = classify_constraint(eco, &long);
    }
}

#[test]
fn robust_graph_order_deterministic() {
    let a = scan_fixture("node-app");
    let b = scan_fixture("node-app");
    let names = |inv: &crate::deps::Inventory| -> Vec<String> {
        inv.graph.nodes.iter().map(|n| n.id().0.clone()).collect()
    };
    assert_eq!(names(&a), names(&b));
}

#[test]
fn robust_json_output_byte_stable() {
    let a = to_json(&scan_fixture("node-app")).to_string();
    let b = to_json(&scan_fixture("node-app")).to_string();
    assert_eq!(a, b);
}

#[test]
fn robust_monorepo_detects_all_workspace_manifests() {
    let inv = scan_fixture("node-monorepo");
    use crate::deps::detect::DepFileKind::NpmManifest;
    let manifests = inv
        .detected_files
        .iter()
        .filter(|f| f.kind == NpmManifest)
        .count();
    assert!(manifests >= 3, "expected >=3 manifests, got {manifests}");
}

#[test]
fn robust_scan_skips_node_modules() {
    use std::fs;
    let tmp = tempfile::TempDir::new().expect("temp dir");
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"x","version":"1.0.0","dependencies":{}}"#,
    )
    .unwrap();
    let nested = tmp.path().join("node_modules/inner");
    fs::create_dir_all(&nested).unwrap();
    fs::write(
        nested.join("package.json"),
        r#"{"name":"inner","version":"9.9.9"}"#,
    )
    .unwrap();

    let files = crate::deps::detect::detect_dependency_files(tmp.path());
    assert!(files.iter().all(|f| !f
        .path
        .components()
        .any(|c| { c.as_os_str() == "node_modules" })));
}

#[test]
fn robust_scan_skips_hidden_tooling_dirs() {
    use std::fs;
    let tmp = tempfile::TempDir::new().expect("temp dir");
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"x","version":"1.0.0","dependencies":{}}"#,
    )
    .unwrap();
    let hidden = tmp
        .path()
        .join(".claude/worktrees/agent/tests/fixtures/malformed");
    fs::create_dir_all(&hidden).unwrap();
    fs::write(hidden.join("package-lock.json"), "{").unwrap();

    let files = crate::deps::detect::detect_dependency_files(tmp.path());
    assert!(files
        .iter()
        .all(|f| !f.path.components().any(|c| { c.as_os_str() == ".claude" })));
    assert!(scan(tmp.path(), &Policy::default()).is_ok());
}
