//! Package-manager/project detection: wrong-manager and
//! externally-managed-pip (PEP 668) guidance messages.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use super::{corgea_cmd, parse, PackageManager};

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
    }
    None
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

fn detect_uv_project_from(start: &Path) -> bool {
    start.ancestors().any(|dir| dir.join("uv.lock").is_file())
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

pub(super) fn externally_managed_pip_message(
    manager: PackageManager,
    rest: &[String],
    _parsed: &parse::ParsedInstall,
) -> Option<String> {
    if manager != PackageManager::Pip
        || pip_install_overrides_external_management(rest)
        || !pip_environment_is_externally_managed()
    {
        return None;
    }

    Some(format!(
        "error: this Python environment is externally managed (PEP 668).\nCreate and activate a virtualenv, then retry `{}`.",
        corgea_cmd(&["pip", "install"], rest)
    ))
}

fn pip_install_overrides_external_management(args: &[String]) -> bool {
    const VALUE_FLAGS: [&str; 4] = ["-t", "--target", "--prefix", "--root"];
    args.iter().any(|arg| {
        arg == "--break-system-packages"
            || VALUE_FLAGS
                .iter()
                .any(|flag| arg == flag || arg.starts_with(&format!("{flag}=")))
    })
}

fn pip_environment_is_externally_managed() -> bool {
    let Ok(pip) = super::exec::resolve_binary("pip") else {
        return false;
    };
    // PEP 668 markers live in a system interpreter's stdlib; pip inside an
    // active virtualenv can't be externally managed - skip the spawn.
    if let Some(venv) = std::env::var_os("VIRTUAL_ENV") {
        if pip.starts_with(&venv) {
            return false;
        }
    }
    let Some(interpreter) = python_interpreter_from_shebang(&pip) else {
        return false;
    };

    let mut command = Command::new(&interpreter[0]);
    command.args(&interpreter[1..]);
    let Ok(output) = command.arg("-c").arg(EXTERNALLY_MANAGED_PYTHON).output() else {
        return false;
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "1"
}

const EXTERNALLY_MANAGED_PYTHON: &str = r#"
import pathlib
import sysconfig

paths = []
for key in ("stdlib", "platstdlib"):
    path = sysconfig.get_path(key)
    if path and path not in paths:
        paths.append(path)

print("1" if any((pathlib.Path(path) / "EXTERNALLY-MANAGED").is_file() for path in paths) else "0")
"#;

fn python_interpreter_from_shebang(path: &Path) -> Option<Vec<OsString>> {
    let content = std::fs::read_to_string(path).ok()?;
    let first = content.lines().next()?.strip_prefix("#!")?.trim();
    let mut parts: Vec<&str> = first.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    if parts[0].ends_with("/env") || parts[0] == "env" {
        parts.remove(0);
        if parts.first() == Some(&"-S") {
            parts.remove(0);
        }
    }
    let executable = parts.first()?;
    if !executable.contains("python") {
        return None;
    }
    Some(parts.iter().map(OsString::from).collect())
}
