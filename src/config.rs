use dirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{env, fs, io};
use toml;

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub(crate) url: String,
    pub(crate) debug: i8,
    pub(crate) token: String,
}

impl Config {
    fn config_path() -> io::Result<PathBuf> {
        let mut dir_path = dirs::home_dir().ok_or(io::Error::new(
            io::ErrorKind::Other,
            "Unable to get home directory",
        ))?;

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

        return self.token.clone();
    }
    pub fn get_debug(&self) -> i8 {
        if let Ok(corgea_debug) = env::var("CORGEA_DEBUG") {
            return corgea_debug.parse::<i8>().unwrap_or(0);
        }

        return self.debug;
    }
}
