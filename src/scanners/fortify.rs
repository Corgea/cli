use crate::scan::{upload_scan, ScanUploadResult};
use crate::Config;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use tempfile::TempDir;
use zip::ZipArchive;

pub fn parse(
    config: &Config,
    file_path: &str,
    project_name: Option<String>,
) -> Option<ScanUploadResult> {
    let temp_dir = match TempDir::new() {
        Ok(dir) => dir,
        Err(e) => {
            println!("Error creating temporary directory: {}", e);
            return None;
        }
    };

    let zip_file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening file: {}", e);
            return None;
        }
    };

    let mut archive = match ZipArchive::new(zip_file) {
        Ok(archive) => archive,
        Err(e) => {
            println!("Error reading zip archive: {}", e);
            return None;
        }
    };

    let result = if let Ok(mut file) = archive.by_name("audit.fvdl") {
        let outpath = temp_dir.path().join("audit.fvdl");
        let mut outfile = match File::create(&outpath) {
            Ok(f) => f,
            Err(e) => {
                println!("Error creating output file: {}", e);
                return None;
            }
        };
        if let Err(e) = io::copy(&mut file, &mut outfile) {
            println!("Error copying file: {}", e);
        }

        let (scan_data, paths) = extract_file_path(outpath);
        upload_scan(
            config,
            paths,
            "fortify".to_string(),
            scan_data,
            false,
            project_name,
        )
    } else {
        println!("File 'audit.fvdl' not found in the archive");
        None
    };
    result
}

/// The raw FVDL and the source files the engine will look up for it.
///
/// A vulnerability can carry several `SourceLocation`s, where the earlier ones
/// are the enclosing scope and only the last is the finding itself, and the
/// engine reads that last one only. The earlier ones can sit in an unrelated
/// tree -- Fortify records its own bundled libraries under
/// `AppData/Local/Fortify/.../_fortify_libraries_/` -- which is not on the
/// machine running the CLI, so collecting them aborted the upload of a report
/// whose real files were all present.
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
    let mut seen = HashSet::new();
    // The last SourceLocation seen in the current Vulnerability.
    let mut selected: Option<String> = None;

    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let e_name = e.name();
                let tag_name = e_name.as_ref();

                if tag_name == b"Vulnerability" {
                    in_vulnerability = true;
                } else if tag_name == b"SourceLocation" && in_vulnerability {
                    if let Some(path) = source_location_path(e) {
                        selected = Some(path);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                if e.name().as_ref() == b"SourceLocation" && in_vulnerability {
                    if let Some(path) = source_location_path(e) {
                        selected = Some(path);
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let e_name = e.name();
                let tag_name = e_name.as_ref();

                if tag_name == b"Vulnerability" {
                    in_vulnerability = false;

                    if let Some(path) = selected.take() {
                        if seen.insert(path.clone()) {
                            paths.push(path);
                        }
                    }
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

/// The `path` attribute of a `SourceLocation`, with XML entities resolved.
fn source_location_path(element: &BytesStart) -> Option<String> {
    for attr_result in element.attributes() {
        match attr_result {
            Ok(attr) if attr.key.as_ref() == b"path" => {
                if let Ok(value) = attr.normalized_value(XmlVersion::Implicit1_0) {
                    return Some(value.to_string());
                }
            }
            Ok(_) => {}
            Err(e) => println!("Error processing attribute: {}", e),
        }
    }

    None
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
    </Vulnerability>
    <Vulnerability>
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

    /// The engine reads the last SourceLocation of a vulnerability and no
    /// other, so the earlier ones must not be uploaded: they can name Fortify's
    /// own bundled libraries, which are not on the machine running the CLI and
    /// used to abort the upload before any file was sent.
    #[test]
    fn extract_file_path_keeps_only_the_location_the_finding_is_reported_at() {
        let fvdl = r#"<?xml version="1.0" encoding="UTF-8"?>
<FVDL>
  <Vulnerabilities>
    <Vulnerability>
      <SourceLocation path="C:/Users/dev/AppData/Local/Fortify/_fortify_libraries_/node/fs.d.ts" line="1"/>
      <SourceLocation path="src/App.java" line="42"/>
    </Vulnerability>
  </Vulnerabilities>
</FVDL>"#;

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp fvdl");
        tmp.write_all(fvdl.as_bytes()).expect("write fvdl");
        tmp.flush().expect("flush fvdl");

        let (_, paths) = extract_file_path(tmp.path().to_path_buf());

        assert_eq!(paths, vec!["src/App.java".to_string()]);
    }
}
