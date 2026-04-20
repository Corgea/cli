use reqwest;
use serde_json::Value;

pub fn get_latest_release_version(repo: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    
    let response = client
        .get(&url)
        .header("User-Agent", "Corgea-CLI")
        .send()?;

    if !response.status().is_success() {
        return Err(format!("Failed to fetch release info: {}", response.status()).into());
    }

    let release_info: Value = response.json()?;
    
    match release_info.get("tag_name") {
        Some(tag) => Ok(tag.as_str().unwrap_or("").trim_start_matches("v.").trim_start_matches('v').to_string()),
        None => Err("No tag_name found in release info".into())
    }
}
