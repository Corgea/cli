use super::StubFixtures;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct FixtureFile {
    #[serde(default)]
    package_checks: HashMap<String, Value>,
    #[serde(default)]
    advisories: HashMap<String, Value>,
}

/// Load stub fixtures from JSON. Keys in `package_checks` use `{ecosystem}/{name}/{version}`.
pub fn load_from_file(path: &Path) -> Result<StubFixtures, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let file: FixtureFile = serde_json::from_str(&raw)?;

    let mut package_checks = HashMap::new();
    for (key, value) in file.package_checks {
        let (eco, name, ver) = parse_package_key(&key)?;
        let body = serde_json::to_string(&value)?;
        package_checks.insert((eco, name, ver), body);
    }

    let mut advisories = HashMap::new();
    for (id, value) in file.advisories {
        advisories.insert(id, serde_json::to_string(&value)?);
    }

    Ok(StubFixtures {
        package_checks,
        advisories,
        status_overrides: HashMap::new(),
    })
}

fn parse_package_key(key: &str) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = key.split('/').collect();
    if parts.len() != 3 {
        return Err(
            format!("package_checks key must be ecosystem/name/version, got {key:?}").into(),
        );
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_key_validates_format() {
        assert_eq!(
            parse_package_key("npm/lodash/4.17.20").unwrap(),
            (
                "npm".to_string(),
                "lodash".to_string(),
                "4.17.20".to_string()
            )
        );
        assert!(parse_package_key("npm/lodash").is_err());
    }
}
