use serde_json::Value;
use crate::log::debug;
use super::{ScanParser, ParseResult};
use quick_xml::Reader;
use quick_xml::events::Event;

pub struct CheckmarxCliParser;

impl ScanParser for CheckmarxCliParser {
    fn detect(&self, input: &str) -> bool {
        if let Ok(data) = serde_json::from_str::<Value>(input) {
            data.get("totalCount").is_some()
                && data.get("results").is_some()
                && data.get("scanID").is_some()
        } else {
            false
        }
    }

    fn parse(&self, input: &str) -> Option<ParseResult> {
        debug("Detected checkmarx cli schema");

        let data: Value = match serde_json::from_str(input) {
            Ok(data) => data,
            Err(_) => return None,
        };

        let mut paths = Vec::new();
        if let Some(results) = data.get("results").and_then(|v| v.as_array()) {
            for result in results {
                if let Some(data) = result.get("data") {
                    if let Some(nodes) = data.get("nodes").and_then(|v| v.as_array()) {
                        for node in nodes {
                            if let Some(path) = node.get("fileName") {
                                if let Some(truncated_path) = path.as_str() {
                                    paths.push(truncated_path.get(1..).unwrap_or("").to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(ParseResult {
            paths,
            scanner: "checkmarx".to_string(),
        })
    }

    fn scanner_name(&self) -> &str {
        "checkmarx-cli"
    }
}

pub struct CheckmarxWebParser;

impl ScanParser for CheckmarxWebParser {
    fn detect(&self, input: &str) -> bool {
        if let Ok(data) = serde_json::from_str::<Value>(input) {
            data.get("scanResults").is_some() && data.get("reportId").is_some()
        } else {
            false
        }
    }

    fn parse(&self, input: &str) -> Option<ParseResult> {
        debug("Detected checkmarx web schema");

        let data: Value = match serde_json::from_str(input) {
            Ok(data) => data,
            Err(_) => return None,
        };

        let mut paths = Vec::new();
        if let Some(scan_results) = data.get("scanResults") {
            if let Some(sast) = scan_results.get("sast") {
                if let Some(languages) = sast.get("languages").and_then(|v| v.as_array()) {
                    for language in languages {
                        if let Some(queries) = language.get("queries").and_then(|v| v.as_array()) {
                            for query in queries {
                                if let Some(vulns) = query.get("vulnerabilities").and_then(|v| v.as_array()) {
                                    for vuln in vulns {
                                        if let Some(nodes) = vuln.get("nodes").and_then(|v| v.as_array()) {
                                            for node in nodes {
                                                if let Some(path) = node.get("fileName") {
                                                    if let Some(truncated_path) = path.as_str() {
                                                        paths.push(truncated_path.get(1..).unwrap_or("").to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(ParseResult {
            paths,
            scanner: "checkmarx".to_string(),
        })
    }

    fn scanner_name(&self) -> &str {
        "checkmarx-web"
    }
}

pub struct CheckmarxXmlParser;

impl CheckmarxXmlParser {
    fn parse_xml_content(&self, input: &str) -> Option<ParseResult> {
        debug("Detected checkmarx xml schema");
        let mut paths = Vec::new();
        let mut reader = Reader::from_str(input);

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    if e.name().as_ref() == b"Result" {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"FileName" {
                                    if let Ok(file_name) = std::str::from_utf8(&attr.value) {
                                        let clean_path = file_name.trim_start_matches('/').trim_start_matches('\\');
                                        if !clean_path.is_empty() {
                                            paths.push(clean_path.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    } else if e.name().as_ref() == b"FileName" {
                        if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                            if let Ok(file_name) = std::str::from_utf8(text.as_ref()) {
                                let clean_path = file_name.trim_start_matches('/').trim_start_matches('\\');
                                if !clean_path.is_empty() {
                                    paths.push(clean_path.to_string());
                                }
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    eprintln!("Error parsing XML: {}", e);
                    return None;
                }
                _ => {}
            }
            buf.clear();
        }

        Some(ParseResult {
            paths,
            scanner: "checkmarx".to_string(),
        })
    }
}

impl ScanParser for CheckmarxXmlParser {
    fn detect(&self, input: &str) -> bool {
        input.trim().starts_with("<?xml") && input.contains("<CxXMLResults")
    }

    fn parse(&self, input: &str) -> Option<ParseResult> {
        self.parse_xml_content(input)
    }

    fn scanner_name(&self) -> &str {
        "checkmarx-xml"
    }
}
