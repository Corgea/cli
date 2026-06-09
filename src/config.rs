use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{env, fs, io};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub(crate) url: String,
    pub(crate) debug: i8,
    pub(crate) token: String,
    /// Override for the vuln-api host (install-gate package checks).
    /// `#[serde(default)]` keeps pre-existing config files loading.
    #[serde(default)]
    pub(crate) vuln_api_url: Option<String>,
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
                vuln_api_url: None,
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

    /// Base URL for the vuln-api service: `CORGEA_VULN_API_URL` env var,
    /// then the config file's `vuln_api_url`, then the public default.
    /// Consumed by the install-gate vuln check (chunk 3); no caller yet.
    #[allow(dead_code)]
    pub fn get_vuln_api_url(&self) -> String {
        let url = crate::utils::generic::get_env_var_if_exists("CORGEA_VULN_API_URL")
            .or_else(|| self.vuln_api_url.clone())
            .unwrap_or_else(|| "https://vuln-api.corgea.app".to_string());
        url.trim().trim_end_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(vuln_api_url: Option<&str>) -> Config {
        Config {
            url: "https://www.corgea.app".to_string(),
            debug: 0,
            token: "".to_string(),
            vuln_api_url: vuln_api_url.map(str::to_string),
        }
    }

    /// All `get_vuln_api_url` cases in one test fn: the env-var cases
    /// mutate process-global state, so they must not run concurrently
    /// with each other under the parallel test harness.
    #[test]
    fn get_vuln_api_url_resolution_order() {
        env::remove_var("CORGEA_VULN_API_URL");

        // Default when neither env nor config is set.
        assert_eq!(
            config_with(None).get_vuln_api_url(),
            "https://vuln-api.corgea.app"
        );

        // Config value wins over the default; trailing slash trimmed.
        assert_eq!(
            config_with(Some("https://custom.example.com/")).get_vuln_api_url(),
            "https://custom.example.com"
        );

        // Surrounding whitespace trimmed.
        assert_eq!(
            config_with(Some("  https://ws.example.com  ")).get_vuln_api_url(),
            "https://ws.example.com"
        );

        // Env var wins over the config value (and gets the same trims).
        env::set_var("CORGEA_VULN_API_URL", " https://env.example.com/ ");
        assert_eq!(
            config_with(Some("https://custom.example.com")).get_vuln_api_url(),
            "https://env.example.com"
        );

        // Empty / whitespace-only env var is treated as unset.
        env::set_var("CORGEA_VULN_API_URL", "   ");
        assert_eq!(
            config_with(Some("https://custom.example.com")).get_vuln_api_url(),
            "https://custom.example.com"
        );
        env::remove_var("CORGEA_VULN_API_URL");
    }

    /// `Config::load()` writes the default file with `vuln_api_url: None`
    /// and `save()` reserializes every config — both must round-trip.
    #[test]
    fn config_toml_round_trips_with_and_without_vuln_api_url() {
        let without = toml::to_string(&config_with(None)).expect("serialize None field");
        let parsed: Config = toml::from_str(&without).expect("deserialize");
        assert_eq!(parsed.vuln_api_url, None);

        let with = toml::to_string(&config_with(Some("https://custom.example.com")))
            .expect("serialize Some field");
        let parsed: Config = toml::from_str(&with).expect("deserialize");
        assert_eq!(
            parsed.vuln_api_url.as_deref(),
            Some("https://custom.example.com")
        );

        // Pre-existing config files (no vuln_api_url key) must still load.
        let legacy: Config =
            toml::from_str("url = \"https://www.corgea.app\"\ndebug = 0\ntoken = \"\"\n")
                .expect("legacy config without vuln_api_url");
        assert_eq!(legacy.vuln_api_url, None);
    }
}
