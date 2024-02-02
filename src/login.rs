use reqwest;
use std::collections::HashMap;
use std::error::Error;

pub fn verify_token(token: &str, corgea_url: &str) -> Result<bool, Box<dyn Error>> {
    let url = format!("{}/api/cli/verify/{}", corgea_url, token);
    let response = reqwest::blocking::get(url)?;

    if response.status().is_success() {
        let body: HashMap<String, String> = response.json()?;

        Ok(body.get("status").map(|s| s == "ok").unwrap_or(false))
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Request failed with status: {}", response.status()),
        )))
    }
}
