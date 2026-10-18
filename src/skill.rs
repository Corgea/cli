use crate::config::Config;
use crate::utils;
use crate::utils::terminal::{set_text_color, TerminalColor};
use std::path::{Path, PathBuf};

/// Supported agents and where their skills are installed.
///
/// Tuple layout: `(agent_id, project_relative_dir, user_relative_dir)`.
/// `project_relative_dir` is resolved against the current working directory;
/// `user_relative_dir` is resolved against the user's home directory.
pub const SUPPORTED_AGENTS: &[(&str, &str, &str)] = &[
    ("cursor", ".cursor/skills", ".cursor/skills"),
    ("claude-code", ".claude/skills", ".claude/skills"),
    ("codex", ".codex/skills", ".codex/skills"),
    (
        "github-copilot",
        ".github/skills",
        ".config/github-copilot/skills",
    ),
    ("gemini-cli", ".gemini/skills", ".gemini/skills"),
    ("windsurf", ".windsurf/skills", ".codeium/windsurf/skills"),
    ("opencode", ".opencode/skills", ".config/opencode/skills"),
    ("universal", ".ai/skills", ".ai/skills"),
];

fn supported_agent_ids() -> String {
    SUPPORTED_AGENTS
        .iter()
        .map(|(id, _, _)| *id)
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_supported_agent(agent: &str) -> bool {
    SUPPORTED_AGENTS.iter().any(|(id, _, _)| *id == agent)
}

/// Parse a `name[@version]` argument into `(name, Option<version>)`.
pub fn parse_skill_arg(arg: &str) -> (String, Option<String>) {
    match arg.split_once('@') {
        Some((name, version)) if !version.is_empty() => {
            (name.to_string(), Some(version.to_string()))
        }
        _ => (arg.to_string(), None),
    }
}

/// Resolve the directory that will contain the skill's `SKILL.md`.
///
/// When `dir` is provided it overrides `agent`/`scope` and is used as the base
/// skills directory. Otherwise the agent's directory for the given scope is
/// used. The skill is always placed in a `<skill_name>` subfolder.
pub fn resolve_skill_dir(
    skill_name: &str,
    agent: Option<&str>,
    scope: &str,
    dir: Option<&str>,
    cwd: &Path,
    home: &Path,
) -> Result<PathBuf, String> {
    let base = if let Some(custom) = dir {
        PathBuf::from(custom)
    } else {
        let agent = agent.ok_or_else(|| {
            format!(
                "No agent specified. Pass --agent <name>, set a default with \
                 'corgea skill set-default-agent <name>', or use --dir. \
                 Supported agents: {}",
                supported_agent_ids()
            )
        })?;
        let entry = SUPPORTED_AGENTS
            .iter()
            .find(|(id, _, _)| *id == agent)
            .ok_or_else(|| {
                format!(
                    "Unsupported agent '{}'. Supported agents: {}",
                    agent,
                    supported_agent_ids()
                )
            })?;
        match scope {
            "project" => cwd.join(entry.1),
            "user" => home.join(entry.2),
            other => {
                return Err(format!(
                    "Invalid scope '{}'. Expected 'project' or 'user'.",
                    other
                ))
            }
        }
    };

    Ok(base.join(skill_name))
}

/// `corgea skill set-default-agent <agent>`
pub fn run_set_default_agent(config: &mut Config, agent: &str) {
    if !is_supported_agent(agent) {
        eprintln!(
            "Unsupported agent '{}'. Supported agents: {}",
            agent,
            supported_agent_ids()
        );
        std::process::exit(1);
    }
    match config.set_default_agent(agent.to_string()) {
        Ok(()) => println!(
            "{}",
            set_text_color(
                &format!("Default agent set to '{}'.", agent),
                TerminalColor::Green
            )
        ),
        Err(e) => {
            eprintln!("Failed to save default agent: {}", e);
            std::process::exit(1);
        }
    }
}

/// `corgea skill install <name[@version]>`
pub fn run_install(
    config: &mut Config,
    name_arg: &str,
    agent: Option<String>,
    scope: &str,
    dir: Option<String>,
    set_default: bool,
) {
    let (skill_name, version) = parse_skill_arg(name_arg);

    if !["project", "user"].contains(&scope) {
        eprintln!("Invalid scope '{}'. Expected 'project' or 'user'.", scope);
        std::process::exit(1);
    }

    // Resolve the agent (flag > configured default) unless a custom dir is set.
    let resolved_agent = agent.clone().or_else(|| config.get_default_agent());
    if dir.is_none() && resolved_agent.is_none() {
        eprintln!(
            "No agent specified. Pass --agent <name>, set a default with \
             'corgea skill set-default-agent <name>', or use --dir.\nSupported agents: {}",
            supported_agent_ids()
        );
        std::process::exit(1);
    }
    if dir.is_none() {
        if let Some(ref a) = resolved_agent {
            if !is_supported_agent(a) {
                eprintln!(
                    "Unsupported agent '{}'. Supported agents: {}",
                    a,
                    supported_agent_ids()
                );
                std::process::exit(1);
            }
        }
    }

    let result = utils::api::get_skill(config.get_url().as_str(), &skill_name, version.as_deref());

    let response = match result {
        Ok(Some(resp)) => resp,
        Ok(None) => {
            eprintln!(
                "{}",
                set_text_color(
                    &format!("No skill named '{}' was found.", skill_name),
                    TerminalColor::Red
                )
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let version_info = match response.version {
        Some(v) => v,
        None => {
            eprintln!(
                "{}",
                set_text_color(
                    &format!("Skill '{}' has no versions to install.", skill_name),
                    TerminalColor::Yellow
                )
            );
            std::process::exit(1);
        }
    };

    if !version_info.is_installable || version_info.content.is_none() {
        match version_info.status.as_str() {
            "pending_review" => {
                println!(
                    "{}",
                    set_text_color(
                        &format!(
                            "Skill '{}' (v{}) is pending security review and is not yet installable.",
                            skill_name, version_info.version
                        ),
                        TerminalColor::Yellow
                    )
                );
            }
            "rejected" => {
                println!(
                    "{}",
                    set_text_color(
                        &format!(
                            "Skill '{}' (v{}) was rejected during security review and cannot be installed.",
                            skill_name, version_info.version
                        ),
                        TerminalColor::Red
                    )
                );
                if !version_info.security_concerns.is_empty() {
                    println!("Reason: {}", version_info.security_concerns);
                }
            }
            other => {
                println!(
                    "Skill '{}' (v{}) is not installable (status: {}).",
                    skill_name, version_info.version, other
                );
            }
        }
        std::process::exit(1);
    }

    let content = version_info.content.unwrap_or_default();

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to determine current directory: {}", e);
            std::process::exit(1);
        }
    };
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

    let skill_dir = match resolve_skill_dir(
        &skill_name,
        resolved_agent.as_deref(),
        scope,
        dir.as_deref(),
        &cwd,
        &home,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = utils::generic::create_path_if_not_exists(&skill_dir) {
        eprintln!("Failed to create skill directory {:?}: {}", skill_dir, e);
        std::process::exit(1);
    }

    let skill_file = skill_dir.join("SKILL.md");
    if let Err(e) = std::fs::write(&skill_file, content) {
        eprintln!("Failed to write skill file {:?}: {}", skill_file, e);
        std::process::exit(1);
    }

    println!(
        "{}",
        set_text_color(
            &format!(
                "Installed skill '{}' (v{}) to {}",
                skill_name,
                version_info.version,
                skill_file.display()
            ),
            TerminalColor::Green
        )
    );

    if set_default {
        if let Some(a) = resolved_agent {
            if let Err(e) = config.set_default_agent(a.clone()) {
                eprintln!("Warning: failed to save default agent: {}", e);
            } else {
                println!("Default agent set to '{}'.", a);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_skill_arg_with_version() {
        let (name, version) = parse_skill_arg("my-skill@1.2.3");
        assert_eq!(name, "my-skill");
        assert_eq!(version, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_parse_skill_arg_without_version() {
        let (name, version) = parse_skill_arg("my-skill");
        assert_eq!(name, "my-skill");
        assert_eq!(version, None);
    }

    #[test]
    fn test_parse_skill_arg_trailing_at() {
        let (name, version) = parse_skill_arg("my-skill@");
        assert_eq!(name, "my-skill@");
        assert_eq!(version, None);
    }

    #[test]
    fn test_resolve_project_scope() {
        let cwd = PathBuf::from("/work/project");
        let home = PathBuf::from("/home/user");
        let dir = resolve_skill_dir("foo", Some("cursor"), "project", None, &cwd, &home).unwrap();
        assert_eq!(dir, PathBuf::from("/work/project/.cursor/skills/foo"));
    }

    #[test]
    fn test_resolve_user_scope() {
        let cwd = PathBuf::from("/work/project");
        let home = PathBuf::from("/home/user");
        let dir = resolve_skill_dir("foo", Some("claude-code"), "user", None, &cwd, &home).unwrap();
        assert_eq!(dir, PathBuf::from("/home/user/.claude/skills/foo"));
    }

    #[test]
    fn test_resolve_custom_dir_overrides_agent() {
        let cwd = PathBuf::from("/work/project");
        let home = PathBuf::from("/home/user");
        let dir = resolve_skill_dir(
            "foo",
            Some("cursor"),
            "project",
            Some("/custom/place"),
            &cwd,
            &home,
        )
        .unwrap();
        assert_eq!(dir, PathBuf::from("/custom/place/foo"));
    }

    #[test]
    fn test_resolve_unsupported_agent_errors() {
        let cwd = PathBuf::from("/work/project");
        let home = PathBuf::from("/home/user");
        let result = resolve_skill_dir("foo", Some("notreal"), "project", None, &cwd, &home);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_missing_agent_errors() {
        let cwd = PathBuf::from("/work/project");
        let home = PathBuf::from("/home/user");
        let result = resolve_skill_dir("foo", None, "project", None, &cwd, &home);
        assert!(result.is_err());
    }
}
