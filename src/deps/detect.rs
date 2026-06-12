use std::path::{Path, PathBuf};

use crate::deps::model::Ecosystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepFileKind {
    NpmManifest,
    NpmLockfile,
    YarnLockfile,
    PnpmLockfile,
    PipRequirements,
    PipConstraints,
    PyProject,
    PoetryLock,
    UvLock,
    MavenPom,
    GradleBuild,
    GradleLockfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedFile {
    pub path: PathBuf,
    pub kind: DepFileKind,
    pub ecosystem: Ecosystem,
}

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "vendor",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
];

/// Recursively detect supported dependency files; skip vendored/VCS dirs.
pub fn detect_dependency_files(root: &Path) -> Vec<DetectedFile> {
    let mut out = Vec::new();
    detect_recursive(root, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn detect_recursive(dir: &Path, out: &mut Vec<DetectedFile>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if path.is_dir() {
            if should_skip_dir(&name) {
                continue;
            }
            detect_recursive(&path, out);
            continue;
        }

        if let Some(detected) = classify_file(&path) {
            out.push(detected);
        }
    }
}

fn classify_file(path: &Path) -> Option<DetectedFile> {
    let name = path.file_name()?.to_string_lossy();
    let kind_eco = match name.as_ref() {
        "package.json" => (DepFileKind::NpmManifest, Ecosystem::Npm),
        "package-lock.json" | "npm-shrinkwrap.json" => (DepFileKind::NpmLockfile, Ecosystem::Npm),
        "yarn.lock" => (DepFileKind::YarnLockfile, Ecosystem::Npm),
        "pnpm-lock.yaml" => (DepFileKind::PnpmLockfile, Ecosystem::Npm),
        "requirements.txt" => (DepFileKind::PipRequirements, Ecosystem::PyPI),
        "constraints.txt" => (DepFileKind::PipConstraints, Ecosystem::PyPI),
        "pyproject.toml" => (DepFileKind::PyProject, Ecosystem::PyPI),
        "poetry.lock" => (DepFileKind::PoetryLock, Ecosystem::PyPI),
        "uv.lock" => (DepFileKind::UvLock, Ecosystem::PyPI),
        "pom.xml" => (DepFileKind::MavenPom, Ecosystem::Maven),
        "build.gradle" | "build.gradle.kts" => (DepFileKind::GradleBuild, Ecosystem::Maven),
        "gradle.lockfile" => (DepFileKind::GradleLockfile, Ecosystem::Maven),
        _ => return None,
    };
    Some(DetectedFile {
        path: path.to_path_buf(),
        kind: kind_eco.0,
        ecosystem: kind_eco.1,
    })
}

fn should_skip_dir(name: &str) -> bool {
    name.starts_with('.') || SKIP_DIRS.contains(&name)
}
