use crate::config::Config;
use crate::utils;
use crate::utils::terminal::{set_text_color, TerminalColor};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

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
        // Continue discovers standalone block files under `mcpServers/`, in the
        // global directory and in the workspace. `config.json` is a different
        // thing entirely and does not register an MCP server.
        (Agent::Continue, Scope::User) => Ok(ctx.home.join(".continue/mcpServers/corgea.yaml")),
        (Agent::Continue, Scope::Project) => Ok(ctx.cwd.join(".continue/mcpServers/corgea.yaml")),
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

/// The host of an MCP endpoint URL, lowercased, or `None` when `value` is not
/// a URL that addresses an `mcp` path.
fn mcp_url_host(value: &str) -> Option<String> {
    let parsed = Url::parse(value.trim()).ok()?;
    let addresses_mcp = parsed
        .path_segments()
        .is_some_and(|mut segments| segments.any(|segment| segment.eq_ignore_ascii_case("mcp")));
    if !addresses_mcp {
        return None;
    }
    Some(parsed.host_str()?.to_ascii_lowercase())
}

/// Corgea's own SaaS hosts, matched on host boundaries. A substring test would
/// also accept `notcorgea.app` and `evil-corgea.attacker.test`.
fn is_corgea_saas_host(host: &str) -> bool {
    host == "corgea.app" || host.ends_with(".corgea.app")
}

/// Whether `value` addresses the Corgea MCP endpoint.
///
/// `install_host` is the host this run is installing, which is what recognizes
/// a self-hosted instance on a domain that has nothing to do with `corgea.app`.
pub fn points_at_corgea_mcp(value: &str, install_host: Option<&str>) -> bool {
    match mcp_url_host(value) {
        Some(host) => {
            is_corgea_saas_host(&host)
                || install_host.is_some_and(|expected| expected.eq_ignore_ascii_case(&host))
        }
        None => false,
    }
}

fn entry_points_at_corgea(entry: &Value, install_host: Option<&str>) -> bool {
    for key in ["url", "httpUrl"] {
        if entry
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|url| points_at_corgea_mcp(url, install_host))
        {
            return true;
        }
    }
    if let Some(args) = entry.get("args").and_then(|a| a.as_array()) {
        if args.iter().any(|arg| {
            arg.as_str()
                .is_some_and(|a| points_at_corgea_mcp(a, install_host))
        }) {
            return true;
        }
    }
    false
}

fn is_corgea_server(name: &str, entry: &Value, install_host: Option<&str>) -> bool {
    name.eq_ignore_ascii_case(SERVER_NAME) || entry_points_at_corgea(entry, install_host)
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

/// The per-server object we write for `agent`.
///
/// Continue is absent on purpose: it takes a standalone block file of its own,
/// not an entry merged into a JSON server map. See [`continue_block_yaml`].
pub fn corgea_server_entry(agent: Agent, url: &str, token: &str) -> Value {
    match agent {
        Agent::Cursor | Agent::Windsurf => mcp_remote_entry(url, token, true, false),
        Agent::ClaudeDesktop => mcp_remote_entry(url, token, false, true),
        Agent::ClaudeCode | Agent::Vscode => json!({
            "type": "http",
            "url": url,
            "headers": token_header(token)
        }),
        Agent::GeminiCli => json!({
            "httpUrl": url,
            "headers": token_header(token)
        }),
        Agent::OpenCode => json!({
            "type": "remote",
            "url": url,
            "headers": token_header(token)
        }),
        Agent::Continue => unreachable!("Continue is written as a standalone block file"),
    }
}

/// Continue reads standalone block files from `.continue/mcpServers/`, keyed by
/// a `name`/`version`/`schema` preamble and an `mcpServers` list. Its config
/// schema drops unknown keys, and an HTTP server carries its headers under
/// `requestOptions` — a top-level `headers` map is silently discarded.
#[derive(Serialize)]
struct ContinueBlock {
    name: String,
    version: String,
    schema: String,
    #[serde(rename = "mcpServers")]
    mcp_servers: Vec<ContinueMcpServer>,
}

#[derive(Serialize)]
struct ContinueMcpServer {
    name: String,
    #[serde(rename = "type")]
    transport: String,
    url: String,
    #[serde(rename = "requestOptions")]
    request_options: ContinueRequestOptions,
}

#[derive(Serialize)]
struct ContinueRequestOptions {
    headers: BTreeMap<String, String>,
}

/// The whole Continue block file. Corgea owns this file outright, so a
/// reinstall rewrites it rather than merging into the user's config.
pub fn continue_block_yaml(url: &str, token: &str) -> Result<String, String> {
    let block = ContinueBlock {
        name: "Corgea MCP".to_string(),
        version: "0.0.1".to_string(),
        schema: "v1".to_string(),
        mcp_servers: vec![ContinueMcpServer {
            name: SERVER_NAME.to_string(),
            transport: "streamable-http".to_string(),
            url: url.to_string(),
            request_options: ContinueRequestOptions {
                headers: BTreeMap::from([("CORGEA-TOKEN".to_string(), token.to_string())]),
            },
        }],
    };
    serde_yaml_ng::to_string(&block)
        .map_err(|e| format!("failed to serialize the Continue MCP block: {e}"))
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

fn remove_corgea_from_map(servers: &mut Map<String, Value>, install_host: Option<&str>) -> bool {
    let before = servers.len();
    servers.retain(|name, entry| !is_corgea_server(name, entry, install_host));
    servers.len() != before
}

fn upsert_named_server(
    root: &mut Map<String, Value>,
    container_key: &str,
    entry: Value,
    install_host: Option<&str>,
) -> Result<bool, String> {
    let servers = object_field(root, container_key)?;
    let replaced = remove_corgea_from_map(servers, install_host);
    servers.insert(SERVER_NAME.to_string(), entry);
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
    // Corgea owns Continue's block file, so there is nothing to merge: an
    // existing file is our own previous install being refreshed.
    if agent == Agent::Continue {
        let had_previous = !existing.trim().is_empty();
        return Ok((continue_block_yaml(url, token)?, had_previous));
    }

    let parsed = if existing.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(existing).map_err(|e| format!("invalid JSON: {e}"))?
    };
    let mut root = as_object_root(parsed)?;
    let entry = corgea_server_entry(agent, url, token);
    let install_host = mcp_url_host(url);
    let install_host = install_host.as_deref();
    let container = match agent {
        Agent::Vscode => "servers",
        Agent::OpenCode => "mcp",
        Agent::Cursor
        | Agent::ClaudeDesktop
        | Agent::ClaudeCode
        | Agent::Windsurf
        | Agent::GeminiCli => "mcpServers",
        Agent::Continue => unreachable!("handled above"),
    };
    let replaced = upsert_named_server(&mut root, container, entry, install_host)?;
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

    /// Continue registers MCP servers from a block file with a
    /// `name`/`version`/`schema` preamble and an `mcpServers` list — not from a
    /// `contextProviders` entry, which it does not read as an MCP server.
    #[test]
    fn continue_block_is_an_mcp_server_not_a_context_provider() {
        let (out, replaced) =
            upsert_corgea(Agent::Continue, "", "https://www.corgea.app/mcp", "tok").unwrap();
        assert!(!replaced);

        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&out).unwrap();
        assert_eq!(v["schema"], serde_yaml_ng::Value::from("v1"));
        assert!(v.get("contextProviders").is_none());
        assert!(v.get("name").is_some(), "preamble needs a name: {out}");
        assert!(
            v.get("version").is_some(),
            "preamble needs a version: {out}"
        );

        let servers = v["mcpServers"].as_sequence().expect("mcpServers list");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["name"], serde_yaml_ng::Value::from("corgea"));
        assert_eq!(
            servers[0]["type"],
            serde_yaml_ng::Value::from("streamable-http")
        );
        assert_eq!(
            servers[0]["url"],
            serde_yaml_ng::Value::from("https://www.corgea.app/mcp")
        );
        // Continue's schema carries HTTP headers under requestOptions and
        // drops an unknown top-level `headers` map.
        assert_eq!(
            servers[0]["requestOptions"]["headers"]["CORGEA-TOKEN"],
            serde_yaml_ng::Value::from("tok")
        );
        assert!(servers[0].get("headers").is_none());
    }

    /// Corgea owns the block file, so a reinstall rewrites it with the new
    /// token instead of appending a second server.
    #[test]
    fn continue_reinstall_rewrites_the_block_file() {
        let first = continue_block_yaml("https://www.corgea.app/mcp", "old").unwrap();
        let (out, replaced) = upsert_corgea(
            Agent::Continue,
            &first,
            "https://tenant.corgea.app/mcp",
            "new",
        )
        .unwrap();
        assert!(replaced);
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&out).unwrap();
        let servers = v["mcpServers"].as_sequence().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers[0]["url"],
            serde_yaml_ng::Value::from("https://tenant.corgea.app/mcp")
        );
        assert!(!out.contains("old"), "stale token must be gone: {out}");
    }

    /// The reinstall sweep matches Corgea by host, not by substring. A server
    /// on an unrelated host that merely contains "corgea" must survive.
    #[test]
    fn upsert_keeps_servers_on_lookalike_hosts() {
        let existing = r#"{
            "mcpServers": {
                "unrelated": {"url": "https://notcorgea.app/mcp"},
                "spoof": {"url": "https://evil-corgea.attacker.test/mcp"},
                "pathy": {"url": "https://internal.example.com/corgea.svc/mcp"}
            }
        }"#;
        let (out, _) = upsert_corgea(
            Agent::ClaudeCode,
            existing,
            "https://www.corgea.app/mcp",
            "tok",
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let servers = v["mcpServers"].as_object().unwrap();
        for survivor in ["unrelated", "spoof", "pathy"] {
            assert!(
                servers.contains_key(survivor),
                "{survivor} is not Corgea and must be left alone: {out}"
            );
        }
        assert_eq!(servers["corgea"]["url"], "https://www.corgea.app/mcp");
    }

    /// A self-hosted instance lives on a domain unrelated to corgea.app, so it
    /// is recognized by matching the host being installed.
    #[test]
    fn upsert_replaces_a_renamed_self_hosted_entry() {
        let existing = r#"{
            "mcpServers": {
                "corgea-onprem": {
                    "url": "https://corgea.acme.internal/mcp",
                    "headers": {"CORGEA-TOKEN": "stale"}
                }
            }
        }"#;
        let (out, replaced) = upsert_corgea(
            Agent::ClaudeCode,
            existing,
            "https://corgea.acme.internal/mcp",
            "fresh",
        )
        .unwrap();
        assert!(replaced);
        let v: Value = serde_json::from_str(&out).unwrap();
        let servers = v["mcpServers"].as_object().unwrap();
        assert!(!servers.contains_key("corgea-onprem"));
        assert_eq!(servers["corgea"]["headers"]["CORGEA-TOKEN"], "fresh");
    }

    #[test]
    fn corgea_mcp_url_matching_is_host_scoped() {
        let install = Some("corgea.acme.internal");
        assert!(points_at_corgea_mcp("https://www.corgea.app/mcp", None));
        assert!(points_at_corgea_mcp("https://tenant.corgea.app/mcp", None));
        assert!(points_at_corgea_mcp("https://corgea.app/mcp", None));
        // Lookalikes and path coincidences are not Corgea.
        assert!(!points_at_corgea_mcp("https://notcorgea.app/mcp", None));
        assert!(!points_at_corgea_mcp(
            "https://evil-corgea.attacker.test/mcp",
            None
        ));
        assert!(!points_at_corgea_mcp(
            "https://internal.example.com/corgea.svc/mcp",
            None
        ));
        // A Corgea host on a non-MCP path is some other service.
        assert!(!points_at_corgea_mcp("https://www.corgea.app/api/v1", None));
        // Self-hosted: only the host being installed matches.
        assert!(points_at_corgea_mcp(
            "https://corgea.acme.internal/mcp",
            install
        ));
        assert!(!points_at_corgea_mcp(
            "https://other.acme.internal/mcp",
            install
        ));
        // Not a URL at all.
        assert!(!points_at_corgea_mcp("mcp-remote", None));
    }

    #[test]
    fn resolve_continue_points_at_the_mcp_servers_block_dir() {
        let home = PathBuf::from("/home/ada");
        let cwd = PathBuf::from("/work/repo");
        let config_dir = PathBuf::from("/home/ada/.config");
        let ctx = ctx(&home, &cwd, &config_dir);

        assert_eq!(
            resolve_config_path(Agent::Continue, Scope::User, None, &ctx).unwrap(),
            PathBuf::from("/home/ada/.continue/mcpServers/corgea.yaml")
        );
        assert_eq!(
            resolve_config_path(Agent::Continue, Scope::Project, None, &ctx).unwrap(),
            PathBuf::from("/work/repo/.continue/mcpServers/corgea.yaml")
        );
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
