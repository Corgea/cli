use super::common::fixture;
use crate::deps::detect::{detect_dependency_files, DepFileKind};
use crate::deps::model::Ecosystem;

fn kinds(root: &str) -> Vec<DepFileKind> {
    let mut k: Vec<_> = detect_dependency_files(&fixture(root))
        .into_iter()
        .map(|f| f.kind)
        .collect();
    k.sort_by_key(|x| format!("{x:?}"));
    k
}

#[test]
fn detect_finds_npm_files() {
    let k = kinds("node-app");
    assert!(k.contains(&DepFileKind::NpmManifest));
    assert!(k.contains(&DepFileKind::NpmLockfile));
}

#[test]
fn detect_finds_python_poetry_files() {
    let k = kinds("python-poetry");
    assert!(k.contains(&DepFileKind::PyProject));
    assert!(k.contains(&DepFileKind::PoetryLock));
}

#[test]
fn detect_finds_pip_requirements() {
    let files = detect_dependency_files(&fixture("python-pip-nolock"));
    assert!(files.iter().any(|f| f.kind == DepFileKind::PipRequirements));
    assert!(files.iter().all(|f| f.ecosystem == Ecosystem::PyPI));
}

#[test]
fn detect_finds_maven_pom() {
    assert!(kinds("java-maven").contains(&DepFileKind::MavenPom));
}

#[test]
fn detect_finds_gradle_files() {
    let k = kinds("java-gradle");
    assert!(k.contains(&DepFileKind::GradleBuild));
    assert!(k.contains(&DepFileKind::GradleLockfile));
}

#[test]
fn detect_ignores_unsupported_go_files() {
    assert!(kinds("go-mod-smoke").is_empty());
}
