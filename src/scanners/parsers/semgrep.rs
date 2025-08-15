use serde_json::Value;
use crate::log::debug;
use super::{ScanParser, ParseResult};

pub struct SemgrepParser;

impl ScanParser for SemgrepParser {
    fn detect(&self, input: &str) -> bool {
        input.contains("semgrep.dev")
    }
    
    fn parse(&self, input: &str) -> Option<ParseResult> {
        debug("Detected semgrep schema");
        
        let data: Value = match serde_json::from_str(input) {
            Ok(data) => data,
            Err(_) => return None,
        };
        
        let mut paths = Vec::new();
        if let Some(results) = data.get("results").and_then(|v| v.as_array()) {
            for result in results {
                if let Some(path) = result.get("path").and_then(|v| v.as_str()) {
                    paths.push(path.to_string());
                }
            }
        }
        
        Some(ParseResult {
            paths,
            scanner: "semgrep".to_string(),
        })
    }
    
    fn scanner_name(&self) -> &str {
        "semgrep"
    }
}
