

#[derive(Debug)]
pub struct ParseResult {
    pub paths: Vec<String>,
    pub scanner: String,
}

pub trait ScanParser {
    fn detect(&self, input: &str) -> bool;
    
    fn parse(&self, input: &str) -> Option<ParseResult>;
    
    #[allow(dead_code)]
    fn scanner_name(&self) -> &str;
}

pub struct ScanParserFactory {
    parsers: Vec<Box<dyn ScanParser>>,
}

impl ScanParserFactory {
    pub fn new() -> Self {
        let parsers: Vec<Box<dyn ScanParser>> = vec![
            Box::new(semgrep::SemgrepParser),
            Box::new(sarif::SarifParser),
            Box::new(checkmarx::CheckmarxCliParser),
            Box::new(checkmarx::CheckmarxWebParser),
            Box::new(checkmarx::CheckmarxXmlParser),
        ];
        
        Self { parsers }
    }
    
    #[allow(dead_code)]
    pub fn find_parser(&self, input: &str) -> Option<&Box<dyn ScanParser>> {
        self.parsers.iter().find(|parser| parser.detect(input))
    }
    
    pub fn parse_scan_data(&self, input: &str) -> Result<ParseResult, String> {
        for parser in &self.parsers {
            if parser.detect(input) {
                match parser.parse(input) {
                    Some(result) => return Ok(result),
                    None => continue,
                }
            }
        }
        
        crate::log::debug("Couldn't detect what kind of report this is.");
        Err("Unsupported scan report format. Please check if your scanner is supported. Supported formats: JSON (Semgrep, SARIF, Checkmarx), XML (Checkmarx).".to_string())
    }
}

pub mod semgrep;
pub mod sarif;
pub mod checkmarx;


