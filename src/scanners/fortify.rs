use crate::scan::upload_scan;
use crate::Config;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use tempfile::TempDir;
use zip::ZipArchive;

pub fn parse(config: &Config, file_path: &str, project_name: Option<String>) {
    let temp_dir = match TempDir::new() {
        Ok(dir) => dir,
        Err(e) => {
            println!("Error creating temporary directory: {}", e);
            return;
        }
    };

    let zip_file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening file: {}", e);
            return;
        }
    };

    let mut archive = match ZipArchive::new(zip_file) {
        Ok(archive) => archive,
        Err(e) => {
            println!("Error reading zip archive: {}", e);
            return;
        }
    };

    if let Ok(mut file) = archive.by_name("audit.fvdl") {
        let outpath = temp_dir.path().join("audit.fvdl");
        let mut outfile = match File::create(&outpath) {
            Ok(f) => f,
            Err(e) => {
                println!("Error creating output file: {}", e);
                return;
            }
        };
        if let Err(e) = io::copy(&mut file, &mut outfile) {
            println!("Error copying file: {}", e);
        }

        let (scan_data, paths) = extract_file_path(outpath);
        let _scan_id = upload_scan(
            config,
            paths,
            "fortify".to_string(),
            scan_data,
            false,
            project_name,
        );
    } else {
        println!("File 'audit.fvdl' not found in the archive");
    };
}

fn extract_file_path(scan_file: PathBuf) -> (String, Vec<String>) {
    let mut paths: Vec<String> = Vec::new();

    let file = File::open(&scan_file).expect("Unable to open file");
    let mut reader = BufReader::new(file);

    let mut contents = String::new();
    reader
        .read_to_string(&mut contents)
        .expect("Unable to read file");

    let mut xml_reader = Reader::from_str(&contents);
    xml_reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut in_vulnerability = false;

    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let e_name = e.name();
                let tag_name = e_name.as_ref();

                if tag_name == b"Vulnerability" {
                    in_vulnerability = true;
                } else if tag_name == b"SourceLocation" && in_vulnerability {
                    for attr_result in e.attributes() {
                        match attr_result {
                            Ok(attr) => {
                                let attr_key = attr.key.as_ref();
                                if attr_key == b"path" {
                                    if let Ok(value) =
                                        attr.normalized_value(XmlVersion::Implicit1_0)
                                    {
                                        let path_str = value.to_string();
                                        if !paths.contains(&path_str) {
                                            paths.push(path_str);
                                        }
                                    }
                                }
                            }
                            Err(e) => println!("Error processing attribute: {}", e),
                        }
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let e_name = e.name();
                let tag_name = e_name.as_ref();

                if tag_name == b"SourceLocation" && in_vulnerability {
                    for attr_result in e.attributes() {
                        match attr_result {
                            Ok(attr) => {
                                let attr_key = attr.key.as_ref();
                                if attr_key == b"path" {
                                    if let Ok(value) =
                                        attr.normalized_value(XmlVersion::Implicit1_0)
                                    {
                                        let path_str = value.to_string();
                                        if !paths.contains(&path_str) {
                                            paths.push(path_str);
                                        }
                                    }
                                }
                            }
                            Err(e) => println!("Error processing attribute: {}", e),
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let e_name = e.name();
                let tag_name = e_name.as_ref();

                if tag_name == b"Vulnerability" {
                    in_vulnerability = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => panic!("Error parsing XML: {}", e),
            _ => (),
        }
        buf.clear();
    }

    (contents, paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Exercises the FVDL path extraction end to end on a representative
    /// report: both the `Start` and `Empty` `SourceLocation` arms, XML entity
    /// unescaping, in-`Vulnerability` scoping, and de-duplication. `fortify.rs`
    /// had no coverage; this pins the behavior across the quick-xml 0.36 -> 0.41
    /// bump (the migration replaced the deprecated `unescape_value` with
    /// `normalized_value(XmlVersion::Implicit1_0)`, which must still resolve
    /// `&amp;` -> `&` for source paths).
    #[test]
    fn extract_file_path_pulls_scoped_source_locations() {
        let fvdl = r#"<?xml version="1.0" encoding="UTF-8"?>
<FVDL>
  <Vulnerabilities>
    <Vulnerability>
      <SourceLocation path="src/start/a&amp;b.java"></SourceLocation>
      <SourceLocation path="src/empty/App.java" line="42"/>
    </Vulnerability>
    <Vulnerability>
      <SourceLocation path="src/empty/App.java" line="99"/>
    </Vulnerability>
  </Vulnerabilities>
  <SourceLocation path="outside/ignored.java" line="1"/>
</FVDL>"#;

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp fvdl");
        tmp.write_all(fvdl.as_bytes()).expect("write fvdl");
        tmp.flush().expect("flush fvdl");

        let (contents, paths) = extract_file_path(tmp.path().to_path_buf());

        assert_eq!(contents, fvdl, "returns the raw scan contents unchanged");
        assert_eq!(
            paths,
            vec![
                // Start arm, with `&amp;` unescaped by normalized_value.
                "src/start/a&b.java".to_string(),
                // Empty arm, de-duplicated across the two Vulnerability blocks.
                "src/empty/App.java".to_string(),
            ],
            "extracts in-Vulnerability SourceLocation paths, unescapes entities, \
             ignores the out-of-scope SourceLocation, and de-duplicates"
        );
    }
}
