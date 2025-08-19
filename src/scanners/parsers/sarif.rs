use serde_json::Value;
use crate::log::debug;
use super::{ScanParser, ParseResult};

pub struct SarifParser;

impl ScanParser for SarifParser {
    fn detect(&self, input: &str) -> bool {
        if let Ok(data) = serde_json::from_str::<Value>(input) {
            let schema = data.get("$schema").and_then(|v| v.as_str()).unwrap_or("unknown");
            schema.contains("sarif")
        } else {
            false
        }
    }
    
    fn parse(&self, input: &str) -> Option<ParseResult> {
        debug("Detected sarif schema");
        
        let data: Value = match serde_json::from_str(input) {
            Ok(data) => data,
            Err(_) => return None,
        };
        
        let run = data.get("runs").and_then(|v| v.as_array()).and_then(|v| v.get(0));
        let driver = run.and_then(|v| v.get("tool")).and_then(|v| v.get("driver")).and_then(|v| v.get("name"));
        let tool = driver.and_then(|v| v.as_str()).unwrap_or("unknown");

        let scanner = match tool {
            "SnykCode" => {
                debug("Detected snyk version of sarif schema");
                "snyk".to_string()
            }
            "CodeQL" => {
                debug("Detected codeql version of sarif schema");
                "codeql".to_string()
            }
            _ => {
                eprintln!("{} is not supported at this time.", tool);
                return None;
            }
        };

        let mut paths = Vec::new();
        if let Some(runs) = data.get("runs").and_then(|v| v.as_array()) {
            for run in runs {
                if let Some(results) = run.get("results").and_then(|v| v.as_array()) {
                    for result in results {
                        if let Some(locations) = result.get("locations").and_then(|v| v.as_array()) {
                            for location in locations {
                                if let Some(uri) = location.get("physicalLocation")
                                    .and_then(|v| v.get("artifactLocation"))
                                    .and_then(|v| v.get("uri"))
                                    .and_then(|v| v.as_str()) {
                                    paths.push(uri.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Some(ParseResult { paths, scanner })
    }
    
    fn scanner_name(&self) -> &str {
        "sarif"
    }
}
