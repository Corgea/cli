use crate::config::Config;
use crate::utils;
use crate::utils::terminal::{set_text_color, TerminalColor};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Well-known name written into every agent config we manage.
pub const SERVER_NAME: &str = "corgea";

/// Agent IDs accepted by `corgea mcp install --agent`.
///
/// `id` is the canonical flag value; `aliases` are also accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Cursor,
    ClaudeDesktop,
    ClaudeCode,
    Windsurf,
    Vscode,
    GeminiCli,
    Continue,
    OpenCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    Project,
}

/// Filesystem context the installer resolves paths against.
pub struct PathContext<'a> {
    pub home: &'a Path,
    pub cwd: &'a Path,
    pub config_dir: &'a Path,
}

const AGENTS: &[(&str, &[&str], Agent)] = &[
    ("cursor", &[], Agent::Cursor),
    ("claude", &["claude-desktop"], Agent::ClaudeDesktop),
    ("claude-code", &[], Agent::ClaudeCode),
    ("windsurf", &[], Agent::Windsurf),
    (
        "vscode",
        &["vs-code", "github-copilot", "copilot"],
        Agent::Vscode,
    ),
    ("gemini-cli", &["gemini"], Agent::GeminiCli),
    ("continue", &[], Agent::Continue),
    ("opencode", &["open-code"], Agent::OpenCode),
];

impl Agent {
    pub fn id(self) -> &'static str {
        AGENTS
            .iter()
            .find(|(_, _, agent)| *agent == self)
            .map(|(id, _, _)| *id)
            .expect("every Agent variant is listed in AGENTS")
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Agent::Cursor => "Cursor",
            Agent::ClaudeDesktop => "Claude Desktop",
            Agent::ClaudeCode => "Claude Code",
            Agent::Windsurf => "Windsurf",
            Agent::Vscode => "VS Code",
            Agent::GeminiCli => "Gemini CLI",
            Agent::Continue => "Continue",
            Agent::OpenCode => "OpenCode",
        }
    }
}

pub fn supported_agent_ids() -> String {
    AGENTS
        .iter()
        .map(|(id, _, _)| *id)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn parse_agent(id: &str) -> Result<Agent, String> {
    let normalized = id.trim().to_ascii_lowercase().replace('_', "-");
    for (canonical, aliases, agent) in AGENTS {
        if normalized == *canonical || aliases.contains(&normalized.as_str()) {
            return Ok(*agent);
        }
    }
    Err(format!(
        "Unsupported agent '{}'. Supported agents: {}",
        id.trim(),
        supported_agent_ids()
    ))
}

pub fn parse_scope(scope: &str) -> Result<Scope, String> {
    match scope.trim().to_ascii_lowercase().as_str() {
        "user" => Ok(Scope::User),
        "project" => Ok(Scope::Project),
        other => Err(format!(
            "Invalid scope '{}'. Expected 'project' or 'user'.",
            other
        )),
    }
}

/// `{base}/mcp`, matching https://docs.corgea.app/modelcontextprotocol
pub fn mcp_endpoint(base_url: &str) -> String {
    format!("{}/mcp", base_url.trim().trim_end_matches('/'))
}

pub fn resolve_config_path(
    agent: Agent,
    scope: Scope,
    dir: Option<&str>,
    ctx: &PathContext<'_>,
) -> Result<PathBuf, String> {
    if let Some(custom) = dir {
        return Ok(PathBuf::from(custom));
    }
    match (agent, scope) {
        (Agent::Cursor, Scope::User) => Ok(cursor_user_path(ctx)),
        (Agent::Cursor, Scope::Project) => Ok(ctx.cwd.join(".cursor/mcp.json")),
        (Agent::ClaudeDesktop, Scope::User) => Ok(ctx
            .config_dir
            .join("Claude")
            .join("claude_desktop_config.json")),
        (Agent::ClaudeDesktop, Scope::Project) => {
            Err("Claude Desktop has no project-level MCP config. Use --scope user.".to_string())
        }
        (Agent::ClaudeCode, Scope::User) => Ok(ctx.home.join(".claude.json")),
        (Agent::ClaudeCode, Scope::Project) => Ok(ctx.cwd.join(".mcp.json")),
        (Agent::Windsurf, Scope::User) => Ok(ctx
            .home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json")),
        (Agent::Windsurf, Scope::Project) => Ok(ctx.cwd.join(".windsurf/mcp.json")),
        (Agent::Vscode, Scope::User) => {
            Ok(ctx.config_dir.join("Code").join("User").join("mcp.json"))
        }
        (Agent::Vscode, Scope::Project) => Ok(ctx.cwd.join(".vscode/mcp.json")),
        (Agent::GeminiCli, Scope::User) => Ok(ctx.home.join(".gemini/settings.json")),
        (Agent::GeminiCli, Scope::Project) => Ok(ctx.cwd.join(".gemini/settings.json")),
        (Agent::Continue, Scope::User) => Ok(ctx.home.join(".continue/config.json")),
        (Agent::Continue, Scope::Project) => Ok(ctx.cwd.join(".continue/config.json")),
        (Agent::OpenCode, Scope::User) => Ok(ctx.config_dir.join("opencode/opencode.json")),
        (Agent::OpenCode, Scope::Project) => Ok(ctx.cwd.join("opencode.json")),
    }
}

fn cursor_user_path(ctx: &PathContext<'_>) -> PathBuf {
    let home_path = ctx.home.join(".cursor/mcp.json");
    let appdata_path = ctx.config_dir.join("Cursor").join("User").join("mcp.json");
    if home_path.exists() || !appdata_path.exists() {
        home_path
    } else {
        appdata_path
    }
}

pub fn looks_like_corgea_mcp_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("corgea.") && lower.contains("/mcp")
}

fn entry_points_at_corgea(entry: &Value) -> bool {
    for key in ["url", "httpUrl", "serverUrl"] {
        if entry
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(looks_like_corgea_mcp_url)
        {
            return true;
        }
    }
    if let Some(args) = entry.get("args").and_then(|a| a.as_array()) {
        if args
            .iter()
            .any(|arg| arg.as_str().is_some_and(looks_like_corgea_mcp_url))
        {
            return true;
        }
    }
    if let Some(params) = entry.get("params") {
        return entry_points_at_corgea(params);
    }
    false
}

fn is_corgea_server(name: &str, entry: &Value) -> bool {
    name.eq_ignore_ascii_case(SERVER_NAME) || entry_points_at_corgea(entry)
}

fn token_header(token: &str) -> Value {
    json!({ "CORGEA-TOKEN": token })
}

fn mcp_remote_entry(url: &str, token: &str, http_only: bool, use_env_block: bool) -> Value {
    let mut args = vec!["-y".to_string(), "mcp-remote".to_string(), url.to_string()];
    if http_only {
        args.push("--transport".to_string());
        args.push("http-only".to_string());
    }
    args.push("--header".to_string());
    if use_env_block {
        // Claude Desktop does not interpolate ${CORGEA_TOKEN}; mcp-remote reads
        // it from the env block. Leave no space after CORGEA-TOKEN: — Windows
        // Claude Desktop does not escape spaces inside args.
        args.push("CORGEA-TOKEN:${CORGEA_TOKEN}".to_string());
        json!({
            "command": "npx",
            "args": args,
            "env": { "CORGEA_TOKEN": token }
        })
    } else {
        // Cursor interpolates ${env:NAME} from its own process environment,
        // which a Dock/Start-menu launch usually lacks. Write the token.
        args.push(format!("CORGEA-TOKEN:{token}"));
        json!({
            "command": "npx",
            "args": args
        })
    }
}

/// The per-server object (or Continue provider object) we write for `agent`.
pub fn corgea_server_entry(agent: Agent, url: &str, token: &str) -> Value {
    match agent {
        Agent::Cursor | Agent::Windsurf => mcp_remote_entry(url, token, true, false),
        Agent::ClaudeDesktop => mcp_remote_entry(url, token, false, true),
        Agent::ClaudeCode => json!({
            "type": "http",
            "url": url,
            "headers": token_header(token)
        }),
        Agent::Vscode => json!({
            "type": "http",
            "url": url,
            "headers": token_header(token)
        }),
        Agent::GeminiCli => json!({
            "httpUrl": url,
            "headers": token_header(token)
        }),
        Agent::Continue => json!({
            "name": SERVER_NAME,
            "params": {
                "serverUrl": url,
                "headers": token_header(token)
            }
        }),
        Agent::OpenCode => json!({
            "type": "remote",
            "url": url,
            "headers": token_header(token)
        }),
    }
}

fn as_object_root(value: Value) -> Result<Map<String, Value>, String> {
    match value {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Map::new()),
        other => Err(format!(
            "MCP config must be a JSON object, found {}",
            value_kind(&other)
        )),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn object_field<'a>(
    root: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    let entry = root.entry(key.to_string()).or_insert_with(|| json!({}));
    match entry {
        Value::Object(map) => Ok(map),
        other => Err(format!(
            "'{key}' must be a JSON object, found {}",
            value_kind(other)
        )),
    }
}

fn remove_corgea_from_map(servers: &mut Map<String, Value>) -> bool {
    let keys: Vec<String> = servers
        .iter()
        .filter(|(name, entry)| is_corgea_server(name, entry))
        .map(|(name, _)| name.clone())
        .collect();
    let removed = !keys.is_empty();
    for key in keys {
        servers.remove(&key);
    }
    removed
}

fn upsert_named_server(
    root: &mut Map<String, Value>,
    container_key: &str,
    entry: Value,
) -> Result<bool, String> {
    let servers = object_field(root, container_key)?;
    let replaced = remove_corgea_from_map(servers);
    servers.insert(SERVER_NAME.to_string(), entry);
    Ok(replaced)
}

fn upsert_continue(root: &mut Map<String, Value>, entry: Value) -> Result<bool, String> {
    let providers = root
        .entry("contextProviders".to_string())
        .or_insert_with(|| json!([]));
    let arr = match providers {
        Value::Array(arr) => arr,
        other => {
            return Err(format!(
                "'contextProviders' must be a JSON array, found {}",
                value_kind(other)
            ))
        }
    };
    let before = arr.len();
    arr.retain(|provider| {
        let named_corgea = provider
            .get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(SERVER_NAME));
        !named_corgea && !entry_points_at_corgea(provider)
    });
    let replaced = arr.len() != before;
    arr.push(entry);
    Ok(replaced)
}

/// Merge a Corgea server into an existing agent config document.
///
/// Any previous Corgea entry is removed first so a reinstall refreshes the
/// URL and token. Other servers and unrelated keys are left in place.
pub fn upsert_corgea(
    agent: Agent,
    existing: &str,
    url: &str,
    token: &str,
) -> Result<(String, bool), String> {
    let parsed = if existing.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(existing).map_err(|e| format!("invalid JSON: {e}"))?
    };
    let mut root = as_object_root(parsed)?;
    let entry = corgea_server_entry(agent, url, token);
    let replaced = match agent {
        Agent::Continue => upsert_continue(&mut root, entry)?,
        Agent::Vscode => upsert_named_server(&mut root, "servers", entry)?,
        Agent::OpenCode => upsert_named_server(&mut root, "mcp", entry)?,
        Agent::Cursor
        | Agent::ClaudeDesktop
        | Agent::ClaudeCode
        | Agent::Windsurf
        | Agent::GeminiCli => upsert_named_server(&mut root, "mcpServers", entry)?,
    };
    let mut rendered = serde_json::to_string_pretty(&Value::Object(root))
        .map_err(|e| format!("failed to serialize MCP config: {e}"))?;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok((rendered, replaced))
}

pub fn install_to_path(path: &Path, agent: Agent, url: &str, token: &str) -> Result<bool, String> {
    let existing = if path.exists() {
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?
    } else {
        String::new()
    };
    let (rendered, replaced) = upsert_corgea(agent, &existing, url, token).map_err(|e| {
        if path.exists() {
            format!(
                "Failed to parse {}: {e}\nFix the file or remove it, then run this command again.",
                path.display()
            )
        } else {
            e
        }
    })?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            utils::generic::create_path_if_not_exists(parent)
                .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
        }
    }
    fs::write(path, rendered).map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    Ok(replaced)
}

/// `corgea mcp install --agent <name>`
pub fn run_install(
    config: &mut Config,
    agent: Option<String>,
    scope: &str,
    dir: Option<String>,
    set_default: bool,
) {
    let scope = match parse_scope(scope) {
        Ok(scope) => scope,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let resolved_agent = agent.clone().or_else(|| config.get_default_agent());
    let Some(agent_id) = resolved_agent else {
        eprintln!(
            "No agent specified. Pass --agent <name> or set a default with \
             'corgea skill set-default-agent <name>'.\nSupported agents: {}",
            supported_agent_ids()
        );
        std::process::exit(1);
    };

    let agent = match parse_agent(&agent_id) {
        Ok(agent) => agent,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to determine current directory: {e}");
            std::process::exit(1);
        }
    };
    let home = match dirs::home_dir() {
        Some(p) => p,
        None => {
            eprintln!("Unable to determine home directory.");
            std::process::exit(1);
        }
    };
    let config_dir = dirs::config_dir().unwrap_or_else(|| home.join(".config"));
    let ctx = PathContext {
        home: &home,
        cwd: &cwd,
        config_dir: &config_dir,
    };

    let path = match resolve_config_path(agent, scope, dir.as_deref(), &ctx) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let url = mcp_endpoint(&config.get_url());
    let token = config.get_token();

    let replaced = match install_to_path(&path, agent, &url, &token) {
        Ok(replaced) => replaced,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let action = if replaced { "Updated" } else { "Installed" };
    println!(
        "{}",
        set_text_color(
            &format!(
                "{action} Corgea MCP for {} in {}",
                agent.display_name(),
                path.display()
            ),
            TerminalColor::Green
        )
    );
    println!(
        "Restart {} so it picks up the new server. Docs: https://docs.corgea.app/modelcontextprotocol",
        agent.display_name()
    );
    if scope == Scope::Project {
        println!(
            "{}",
            set_text_color(
                "Warning: this file now contains your Corgea token. Do not commit it.",
                TerminalColor::Yellow
            )
        );
    }

    if set_default {
        if let Err(e) = config.set_default_agent(agent.id().to_string()) {
            eprintln!("Warning: failed to save default agent: {e}");
        } else {
            println!("Default agent set to '{}'.", agent.id());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ctx<'a>(home: &'a Path, cwd: &'a Path, config_dir: &'a Path) -> PathContext<'a> {
        PathContext {
            home,
            cwd,
            config_dir,
        }
    }

    #[test]
    fn parse_agent_accepts_canonical_ids_and_aliases() {
        assert_eq!(parse_agent("cursor").unwrap(), Agent::Cursor);
        assert_eq!(parse_agent("Claude").unwrap(), Agent::ClaudeDesktop);
        assert_eq!(parse_agent("claude-desktop").unwrap(), Agent::ClaudeDesktop);
        assert_eq!(parse_agent("claude_code").unwrap(), Agent::ClaudeCode);
        assert_eq!(parse_agent("github-copilot").unwrap(), Agent::Vscode);
        assert_eq!(parse_agent("gemini").unwrap(), Agent::GeminiCli);
        assert_eq!(parse_agent("open-code").unwrap(), Agent::OpenCode);
        assert!(parse_agent("not-an-agent").is_err());
        assert!(parse_agent("universal").is_err());
    }

    #[test]
    fn parse_scope_accepts_user_and_project() {
        assert_eq!(parse_scope("user").unwrap(), Scope::User);
        assert_eq!(parse_scope("PROJECT").unwrap(), Scope::Project);
        assert!(parse_scope("org").is_err());
    }

    #[test]
    fn mcp_endpoint_strips_trailing_slash() {
        assert_eq!(
            mcp_endpoint("https://www.corgea.app/"),
            "https://www.corgea.app/mcp"
        );
        assert_eq!(
            mcp_endpoint("https://acme.corgea.app"),
            "https://acme.corgea.app/mcp"
        );
    }

    #[test]
    fn resolve_cursor_prefers_home_dotfile_when_neither_exists() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let cwd = home.join("proj");
        let config_dir = home.join("AppData/Roaming");
        let path = resolve_config_path(
            Agent::Cursor,
            Scope::User,
            None,
            &ctx(home, &cwd, &config_dir),
        )
        .unwrap();
        assert_eq!(path, home.join(".cursor/mcp.json"));
    }

    #[test]
    fn resolve_cursor_uses_existing_appdata_file_on_windows() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let cwd = home.join("proj");
        let config_dir = home.join("AppData/Roaming");
        let appdata = config_dir.join("Cursor/User/mcp.json");
        fs::create_dir_all(appdata.parent().unwrap()).unwrap();
        fs::write(&appdata, "{}\n").unwrap();
        let path = resolve_config_path(
            Agent::Cursor,
            Scope::User,
            None,
            &ctx(home, &cwd, &config_dir),
        )
        .unwrap();
        assert_eq!(path, appdata);
    }

    #[test]
    fn resolve_known_user_and_project_paths() {
        let home = PathBuf::from("/home/ada");
        let cwd = PathBuf::from("/work/repo");
        let config_dir = PathBuf::from("/home/ada/.config");
        let ctx = ctx(&home, &cwd, &config_dir);

        assert_eq!(
            resolve_config_path(Agent::ClaudeCode, Scope::User, None, &ctx).unwrap(),
            PathBuf::from("/home/ada/.claude.json")
        );
        assert_eq!(
            resolve_config_path(Agent::ClaudeCode, Scope::Project, None, &ctx).unwrap(),
            PathBuf::from("/work/repo/.mcp.json")
        );
        assert_eq!(
            resolve_config_path(Agent::ClaudeDesktop, Scope::User, None, &ctx).unwrap(),
            PathBuf::from("/home/ada/.config/Claude/claude_desktop_config.json")
        );
        assert!(resolve_config_path(Agent::ClaudeDesktop, Scope::Project, None, &ctx).is_err());
        assert_eq!(
            resolve_config_path(Agent::Vscode, Scope::Project, None, &ctx).unwrap(),
            PathBuf::from("/work/repo/.vscode/mcp.json")
        );
        assert_eq!(
            resolve_config_path(Agent::Cursor, Scope::Project, None, &ctx).unwrap(),
            PathBuf::from("/work/repo/.cursor/mcp.json")
        );
        assert_eq!(
            resolve_config_path(Agent::Cursor, Scope::User, Some("/tmp/custom.json"), &ctx)
                .unwrap(),
            PathBuf::from("/tmp/custom.json")
        );
    }

    #[test]
    fn upsert_creates_cursor_mcp_remote_entry() {
        let (out, replaced) =
            upsert_corgea(Agent::Cursor, "", "https://www.corgea.app/mcp", "tok-1").unwrap();
        assert!(!replaced);
        let v: Value = serde_json::from_str(&out).unwrap();
        let server = &v["mcpServers"]["corgea"];
        assert_eq!(server["command"], "npx");
        let args = server["args"].as_array().unwrap();
        assert!(args.iter().any(|a| a == "mcp-remote"));
        assert!(args.iter().any(|a| a == "http-only"));
        assert!(args
            .iter()
            .any(|a| a.as_str() == Some("CORGEA-TOKEN:tok-1")));
        assert!(args
            .iter()
            .any(|a| a.as_str() == Some("https://www.corgea.app/mcp")));
        assert!(server.get("env").is_none());
    }

    #[test]
    fn upsert_claude_desktop_writes_token_in_env_block() {
        let (out, _) = upsert_corgea(
            Agent::ClaudeDesktop,
            "{}",
            "https://acme.corgea.app/mcp",
            "secret",
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let server = &v["mcpServers"]["corgea"];
        assert_eq!(server["env"]["CORGEA_TOKEN"], "secret");
        let args = server["args"].as_array().unwrap();
        assert!(args
            .iter()
            .any(|a| a.as_str() == Some("CORGEA-TOKEN:${CORGEA_TOKEN}")));
        assert!(!args.iter().any(|a| a == "http-only"));
    }

    #[test]
    fn upsert_claude_code_uses_typed_http() {
        let (out, _) =
            upsert_corgea(Agent::ClaudeCode, "", "https://www.corgea.app/mcp", "tok").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["mcpServers"]["corgea"]["type"], "http");
        assert_eq!(
            v["mcpServers"]["corgea"]["url"],
            "https://www.corgea.app/mcp"
        );
        assert_eq!(v["mcpServers"]["corgea"]["headers"]["CORGEA-TOKEN"], "tok");
    }

    #[test]
    fn upsert_replaces_existing_corgea_and_keeps_neighbors() {
        let existing = r#"{
            "mcpServers": {
                "github": { "command": "npx", "args": ["-y", "github"] },
                "corgea": {
                    "command": "npx",
                    "args": ["-y", "mcp-remote", "https://old.corgea.app/mcp", "--header", "CORGEA-TOKEN:old"]
                }
            }
        }"#;
        let (out, replaced) = upsert_corgea(
            Agent::Cursor,
            existing,
            "https://www.corgea.app/mcp",
            "new-token",
        )
        .unwrap();
        assert!(replaced);
        let v: Value = serde_json::from_str(&out).unwrap();
        let servers = v["mcpServers"].as_object().unwrap();
        assert!(servers.contains_key("github"));
        let args = servers["corgea"]["args"].as_array().unwrap();
        assert!(args
            .iter()
            .any(|a| a.as_str() == Some("https://www.corgea.app/mcp")));
        assert!(args
            .iter()
            .any(|a| a.as_str() == Some("CORGEA-TOKEN:new-token")));
        assert!(!args
            .iter()
            .any(|a| a.as_str().is_some_and(|s| s.contains("old"))));
    }

    #[test]
    fn upsert_removes_renamed_server_that_still_points_at_corgea() {
        let existing = r#"{
            "mcpServers": {
                "my-corgea": {
                    "url": "https://www.corgea.app/mcp",
                    "headers": { "CORGEA-TOKEN": "old" }
                }
            }
        }"#;
        let (out, replaced) = upsert_corgea(
            Agent::ClaudeCode,
            existing,
            "https://tenant.corgea.app/mcp",
            "fresh",
        )
        .unwrap();
        assert!(replaced);
        let v: Value = serde_json::from_str(&out).unwrap();
        let servers = v["mcpServers"].as_object().unwrap();
        assert!(!servers.contains_key("my-corgea"));
        assert_eq!(servers["corgea"]["url"], "https://tenant.corgea.app/mcp");
    }

    #[test]
    fn upsert_vscode_uses_servers_key() {
        let existing = r#"{"servers":{"other":{"url":"https://example.com"}}}"#;
        let (out, _) =
            upsert_corgea(Agent::Vscode, existing, "https://www.corgea.app/mcp", "tok").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("mcpServers").is_none());
        assert_eq!(v["servers"]["other"]["url"], "https://example.com");
        assert_eq!(v["servers"]["corgea"]["type"], "http");
        assert_eq!(v["servers"]["corgea"]["headers"]["CORGEA-TOKEN"], "tok");
    }

    #[test]
    fn upsert_continue_replaces_provider_and_keeps_others() {
        let existing = r#"{
            "models": [{"title": "gpt"}],
            "contextProviders": [
                {"name": "code", "params": {}},
                {"name": "corgea", "params": {"serverUrl": "https://old.corgea.app/mcp"}}
            ]
        }"#;
        let (out, replaced) = upsert_corgea(
            Agent::Continue,
            existing,
            "https://www.corgea.app/mcp",
            "tok",
        )
        .unwrap();
        assert!(replaced);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["models"][0]["title"], "gpt");
        let providers = v["contextProviders"].as_array().unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0]["name"], "code");
        assert_eq!(providers[1]["name"], "corgea");
        assert_eq!(
            providers[1]["params"]["serverUrl"],
            "https://www.corgea.app/mcp"
        );
        assert_eq!(providers[1]["params"]["headers"]["CORGEA-TOKEN"], "tok");
    }

    #[test]
    fn upsert_opencode_and_gemini_use_their_own_keys() {
        let (opencode, _) = upsert_corgea(
            Agent::OpenCode,
            r#"{"theme":"dark"}"#,
            "https://www.corgea.app/mcp",
            "tok",
        )
        .unwrap();
        let v: Value = serde_json::from_str(&opencode).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["mcp"]["corgea"]["type"], "remote");

        let (gemini, _) = upsert_corgea(
            Agent::GeminiCli,
            r#"{"selectedAuthType":"oauth"}"#,
            "https://www.corgea.app/mcp",
            "tok",
        )
        .unwrap();
        let v: Value = serde_json::from_str(&gemini).unwrap();
        assert_eq!(v["selectedAuthType"], "oauth");
        assert_eq!(
            v["mcpServers"]["corgea"]["httpUrl"],
            "https://www.corgea.app/mcp"
        );
    }

    #[test]
    fn upsert_rejects_malformed_json() {
        let err = upsert_corgea(Agent::Cursor, "{not json", "https://x/mcp", "t").unwrap_err();
        assert!(err.contains("invalid JSON"), "{err}");
    }

    #[test]
    fn upsert_rejects_non_object_root() {
        let err = upsert_corgea(Agent::Cursor, "[1,2]", "https://x/mcp", "t").unwrap_err();
        assert!(err.contains("JSON object"), "{err}");
    }

    #[test]
    fn install_to_path_creates_parents_and_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested/mcp.json");
        let replaced =
            install_to_path(&path, Agent::Cursor, "https://www.corgea.app/mcp", "first").unwrap();
        assert!(!replaced);
        assert!(path.exists());

        let replaced = install_to_path(
            &path,
            Agent::Cursor,
            "https://tenant.corgea.app/mcp",
            "second",
        )
        .unwrap();
        assert!(replaced);
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("tenant.corgea.app/mcp"));
        assert!(body.contains("CORGEA-TOKEN:second"));
        assert!(!body.contains("CORGEA-TOKEN:first"));
    }

    #[test]
    fn install_to_path_does_not_clobber_broken_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("mcp.json");
        fs::write(&path, "this is not json").unwrap();
        let err = install_to_path(&path, Agent::Cursor, "https://x/mcp", "t").unwrap_err();
        assert!(err.contains("Fix the file"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "this is not json");
    }
}
