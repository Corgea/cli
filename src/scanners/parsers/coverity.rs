use super::{ParseResult, ScanParser};
use crate::log::debug;
use quick_xml::events::Event;
use quick_xml::Reader;

pub struct CoverityParser;

impl ScanParser for CoverityParser {
    fn detect(&self, input: &str) -> bool {
        input.contains("xmlns:cov=\"http://coverity.com\"")
    }

    fn parse(&self, input: &str) -> Option<ParseResult> {
        debug("Detected coverity schema");

        let mut paths = Vec::new();
        let mut reader = Reader::from_str(input);
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    let is_merged_defect = e.name().as_ref() == b"cov:mergedDefect"
                        || e.name().as_ref() == b"mergedDefect";
                    if is_merged_defect {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"file" {
                                    if let Ok(file_path) = std::str::from_utf8(attr.value.as_ref())
                                    {
                                        let clean_path = file_path
                                            .trim_start_matches('/')
                                            .trim_start_matches('\\');
                                        if !clean_path.is_empty() {
                                            paths.push(clean_path.to_string());
                                        }
                                    }
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
            scanner: "coverity".to_string(),
        })
    }

    fn scanner_name(&self) -> &str {
        "coverity"
    }
}
