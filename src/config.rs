use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{env, fs, io};

pub const DEFAULT_VULN_API_URL: &str = "https://cve-worker-staging.corgea.workers.dev";

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub(crate) url: String,
    pub(crate) debug: i8,
    pub(crate) token: String,
    #[serde(default)]
    pub(crate) default_agent: Option<String>,
}

impl Config {
    fn config_path() -> io::Result<PathBuf> {
        let mut dir_path =
            dirs::home_dir().ok_or(io::Error::other("Unable to get home directory"))?;

        dir_path.push(".corgea");

        if !dir_path.exists() {
            fs::create_dir_all(&dir_path)?;
        }

        let mut file_path = dir_path;
        file_path.push("config.toml");

        Ok(file_path)
    }

    pub fn load() -> io::Result<Self> {
        let file_path = Self::config_path()?;

        if !file_path.exists() {
            let config = Self {
                url: "https://www.corgea.app".to_string(),
                debug: 0,
                token: "".to_string(),
                default_agent: None,
            };

            let toml = toml::to_string(&config).expect("Failed to serialize config");

            fs::write(&file_path, toml)?;
        }

        let contents = fs::read_to_string(&file_path)?;

        let mut config: Self = toml::from_str(&contents).expect("Failed to deserialize config");

        if let Ok(corgea_debug) = env::var("CORGEA_DEBUG") {
            config.debug = corgea_debug.parse::<i8>().unwrap_or(0);
        }

        Ok(config)
    }

    pub fn set_token(&mut self, token: String) -> io::Result<()> {
        self.token = token;
        self.save()
    }

    pub fn save(&self) -> io::Result<()> {
        let toml = toml::to_string(self).expect("Failed to serialize config");

        let file_path = Self::config_path()?;

        fs::write(&file_path, toml)?;

        Ok(())
    }

    pub fn set_url(&mut self, url: String) -> io::Result<()> {
        self.url = url;
        self.save()
    }

    pub fn get_url(&self) -> String {
        let url = if let Ok(corgea_url) = env::var("CORGEA_URL") {
            corgea_url
        } else {
            self.url.clone()
        };

        if url.ends_with('/') {
            url.trim_end_matches('/').to_string()
        } else {
            url
        }
    }

    pub fn get_token(&self) -> String {
        if let Ok(corgea_token) = env::var("CORGEA_TOKEN") {
            return corgea_token;
        }

        self.token.clone()
    }
    pub fn get_debug(&self) -> i8 {
        if let Ok(corgea_debug) = env::var("CORGEA_DEBUG") {
            return corgea_debug.parse::<i8>().unwrap_or(0);
        }

        self.debug
    }

    pub fn set_default_agent(&mut self, agent: String) -> io::Result<()> {
        self.default_agent = Some(agent);
        self.save()
    }

    pub fn get_default_agent(&self) -> Option<String> {
        if let Ok(agent) = env::var("CORGEA_DEFAULT_AGENT") {
            if !agent.trim().is_empty() {
                return Some(agent);
            }
        }

        self.default_agent.clone()
    }
}

/// Base URL for the vuln-api service: `CORGEA_VULN_API_URL` env var,
/// then the public default. Pure env/constant — no config file field.
pub fn vuln_api_url() -> String {
    resolve_vuln_api_url(crate::utils::generic::get_env_var_if_exists(
        "CORGEA_VULN_API_URL",
    ))
}

/// Pure resolution rule, split out so tests never mutate process-global
/// env (`set_var` races concurrent `getenv` under the parallel harness).
fn resolve_vuln_api_url(override_url: Option<String>) -> String {
    override_url
        .unwrap_or_else(|| DEFAULT_VULN_API_URL.to_string())
        .trim()
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vuln_api_url_resolution_order() {
        // Default when the env var is unset (`get_env_var_if_exists`
        // already maps empty/whitespace-only values to None).
        assert_eq!(resolve_vuln_api_url(None), DEFAULT_VULN_API_URL);

        // Override wins; whitespace and trailing slash trimmed.
        assert_eq!(
            resolve_vuln_api_url(Some(" https://env.example.com/ ".to_string())),
            "https://env.example.com"
        );
    }
}
