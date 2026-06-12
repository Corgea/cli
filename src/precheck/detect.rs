//! Package-manager/project detection: wrong-manager guidance messages.

use std::path::Path;

use super::{parse, PackageManager};

pub(super) fn wrong_package_manager_message(
    manager: PackageManager,
    rest: &[String],
    parsed: &parse::ParsedInstall,
) -> Option<String> {
    let cwd = &std::env::current_dir().ok()?;
    let expected = match manager {
        PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm => {
            let expected = detect_node_manager_from(cwd)?;
            (expected != manager).then_some(expected)?
        }
        PackageManager::Pip if detect_uv_project_from(cwd) => PackageManager::Uv,
        PackageManager::Uv if detect_pip_project_from(cwd) => PackageManager::Pip,
        _ => return None,
    };

    let suggestion = suggested_install_command(expected, rest, parsed);
    Some(format!(
        "error: this project appears to use {}, but you ran {}.\nDid you mean `{suggestion}`?",
        expected.binary_name(),
        manager.binary_name()
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectManagerDetection {
    None,
    Ambiguous,
    Found(PackageManager),
}

fn detect_node_manager_from(start: &Path) -> Option<PackageManager> {
    for dir in start.ancestors() {
        match detect_node_manager_in_dir(dir) {
            ProjectManagerDetection::Found(manager) => return Some(manager),
            ProjectManagerDetection::Ambiguous => return None,
            ProjectManagerDetection::None => {}
        }
        // A `package.json` marks the project root (npm/yarn/pnpm scope
        // their own discovery the same way). A project with no manager
        // indicators of its own must not inherit a stray ancestor lockfile
        // — that would hard-refuse installs in every fresh project under it.
        //
        // EXCEPT a workspace member: its package manager is controlled by the
        // workspace ROOT (root `workspaces` field or `pnpm-workspace.yaml`),
        // so keep walking up to find it instead of stopping at the leaf.
        if dir.join("package.json").is_file() && !is_inside_npm_workspace(dir) {
            return None;
        }
    }
    None
}

/// Whether `dir` is a member of an npm/yarn/pnpm workspace rooted at some
/// ancestor — i.e. a strict ancestor carries a `pnpm-workspace.yaml` or a
/// `package.json` with a `workspaces` field. Used to keep the wrong-manager
/// walk going past a leaf member up to the workspace root.
fn is_inside_npm_workspace(dir: &Path) -> bool {
    dir.ancestors().skip(1).any(|ancestor| {
        if ancestor.join("pnpm-workspace.yaml").is_file() {
            return true;
        }
        std::fs::read_to_string(ancestor.join("package.json"))
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .is_some_and(|j| j.get("workspaces").is_some())
    })
}

fn detect_node_manager_in_dir(dir: &Path) -> ProjectManagerDetection {
    match package_json_manager(dir) {
        ProjectManagerDetection::None => {}
        found => return found,
    }

    let mut found = Vec::new();
    if dir.join("pnpm-lock.yaml").is_file() {
        found.push(PackageManager::Pnpm);
    }
    if dir.join("yarn.lock").is_file() {
        found.push(PackageManager::Yarn);
    }
    if dir.join("package-lock.json").is_file() || dir.join("npm-shrinkwrap.json").is_file() {
        found.push(PackageManager::Npm);
    }

    match found.as_slice() {
        [] => ProjectManagerDetection::None,
        [manager] => ProjectManagerDetection::Found(*manager),
        _ => ProjectManagerDetection::Ambiguous,
    }
}

/// `packageManager`-field detection. Missing/unparsable `package.json` and a
/// missing field both fall through to lockfile detection (`None`).
fn package_json_manager(dir: &Path) -> ProjectManagerDetection {
    let json: Option<serde_json::Value> = std::fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok());
    let Some(package_manager) = json
        .as_ref()
        .and_then(|j| j.get("packageManager"))
        .and_then(|v| v.as_str())
    else {
        return ProjectManagerDetection::None;
    };
    parse_node_package_manager(package_manager)
        .map(ProjectManagerDetection::Found)
        .unwrap_or(ProjectManagerDetection::Ambiguous)
}

fn parse_node_package_manager(raw: &str) -> Option<PackageManager> {
    let name = raw.trim().split('@').next().unwrap_or("").trim();
    match name {
        "npm" => Some(PackageManager::Npm),
        "yarn" => Some(PackageManager::Yarn),
        "pnpm" => Some(PackageManager::Pnpm),
        _ => None,
    }
}

/// Walk up looking for `uv.lock`, but stop at the nearest Python project
/// boundary (a `pyproject.toml` or requirements file without a `uv.lock`
/// beside it) — symmetric with [`detect_pip_project_from`], so a stray
/// `~/uv.lock` can't condemn every pip project beneath it.
fn detect_uv_project_from(start: &Path) -> bool {
    for dir in start.ancestors() {
        if dir.join("uv.lock").is_file() {
            return true;
        }
        if dir.join("pyproject.toml").is_file() || has_requirements_file(dir) {
            return false;
        }
    }
    false
}

fn detect_pip_project_from(start: &Path) -> bool {
    start
        .ancestors()
        .take_while(|dir| !dir.join("pyproject.toml").is_file() && !dir.join("uv.lock").is_file())
        .any(has_requirements_file)
}

fn has_requirements_file(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        entry.path().is_file()
            && ((name.starts_with("requirements")
                && (name.ends_with(".txt") || name.ends_with(".in")))
                || name.ends_with("-requirements.txt"))
    })
}

fn suggested_install_command(
    expected: PackageManager,
    rest: &[String],
    parsed: &parse::ParsedInstall,
) -> String {
    let mut parts = vec!["corgea".to_string(), expected.binary_name().to_string()];
    match expected {
        PackageManager::Npm => parts.push("install".to_string()),
        PackageManager::Yarn | PackageManager::Pnpm => {
            if parsed.targets.is_empty() && parsed.requirements_files.is_empty() {
                parts.push("install".to_string());
            } else {
                parts.push("add".to_string());
            }
        }
        PackageManager::Uv => {
            if is_plain_pip_target_install(rest, parsed) {
                parts.push("add".to_string());
                parts.extend(parsed.targets.iter().map(|target| target.display.clone()));
                return parts.join(" ");
            }
            parts.push("pip".to_string());
            parts.push("install".to_string());
        }
        PackageManager::Pip => parts.push("install".to_string()),
    }
    parts.extend(rest.iter().cloned());
    parts.join(" ")
}

fn is_plain_pip_target_install(rest: &[String], parsed: &parse::ParsedInstall) -> bool {
    !parsed.targets.is_empty()
        && parsed.requirements_files.is_empty()
        && rest.len() == parsed.targets.len()
        && rest
            .iter()
            .zip(&parsed.targets)
            .all(|(arg, target)| arg == &target.display)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::write(path, "").expect("write marker file");
    }

    #[test]
    fn node_walk_stops_at_the_project_boundary() {
        // A stray ancestor lockfile must not condemn a fresh project that
        // has its own package.json but no manager indicators yet.
        let root = tempfile::tempdir().expect("tempdir");
        touch(&root.path().join("package-lock.json"));
        let project = root.path().join("newapp");
        std::fs::create_dir(&project).expect("mkdir");
        std::fs::write(project.join("package.json"), "{}").expect("write manifest");

        assert_eq!(detect_node_manager_from(&project), None);

        // Without its own package.json the walk still reaches the ancestor.
        let bare = root.path().join("scratch");
        std::fs::create_dir(&bare).expect("mkdir");
        assert_eq!(detect_node_manager_from(&bare), Some(PackageManager::Npm));
    }

    #[test]
    fn node_walk_reaches_workspace_root_from_a_member() {
        // A workspace member's own package.json has no manager indicators,
        // but the workspace ROOT controls the manager. The walk must reach
        // the root (here: pnpm via pnpm-lock.yaml + `workspaces`) instead of
        // hard-stopping at the leaf.
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"monorepo","workspaces":["packages/*"]}"#,
        )
        .expect("write root manifest");
        touch(&root.path().join("pnpm-lock.yaml"));
        let member = root.path().join("packages").join("a");
        std::fs::create_dir_all(&member).expect("mkdir");
        std::fs::write(member.join("package.json"), r#"{"name":"a"}"#).expect("write member");

        assert_eq!(
            detect_node_manager_from(&member),
            Some(PackageManager::Pnpm),
            "a workspace member must resolve to the root's manager"
        );

        // A standalone project (no workspace ancestor) still stops at its leaf.
        let standalone = tempfile::tempdir().expect("tempdir");
        touch(&standalone.path().join("yarn.lock"));
        let fresh = standalone.path().join("fresh");
        std::fs::create_dir(&fresh).expect("mkdir");
        std::fs::write(fresh.join("package.json"), "{}").expect("write manifest");
        assert_eq!(detect_node_manager_from(&fresh), None);
    }

    #[test]
    fn uv_walk_stops_at_a_nearer_python_project() {
        // A pip project (requirements/pyproject, no uv.lock) must not be
        // blamed for a stray uv.lock further up.
        let root = tempfile::tempdir().expect("tempdir");
        touch(&root.path().join("uv.lock"));
        let pip_project = root.path().join("legacy");
        std::fs::create_dir(&pip_project).expect("mkdir");
        touch(&pip_project.join("requirements.txt"));

        assert!(!detect_uv_project_from(&pip_project));

        // The uv root itself (uv.lock beside pyproject.toml) still detects.
        touch(&root.path().join("pyproject.toml"));
        assert!(detect_uv_project_from(root.path()));

        // And a plain subdirectory of the uv project still walks up to it.
        let sub = root.path().join("src");
        std::fs::create_dir(&sub).expect("mkdir");
        assert!(detect_uv_project_from(&sub));
    }
}
