use std::fs::File;
use std::io;
use std::path::PathBuf;
use zip::ZipArchive;
use tempfile::TempDir;
use std::io::{Read, BufReader};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use crate::Config;
use crate::scan::upload_scan;

pub fn parse(config: &Config, file_path: &str) {
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
        upload_scan(config, paths, "fortify".to_string(), scan_data, false);
    } else {
        println!("File 'audit.fvdl' not found in the archive");
    };
}

fn extract_file_path(scan_file: PathBuf) -> (String, Vec<String>) {
    let mut paths: Vec<String> = Vec::new();

    let file = File::open(&scan_file).expect("Unable to open file");
    let mut reader = BufReader::new(file);

    let mut contents = String::new();
    reader.read_to_string(&mut contents).expect("Unable to read file");

    let mut xml_reader = Reader::from_str(&contents);
    xml_reader.config_mut().trim_text(true);

    let mut buf = Vec::new();

    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Empty(ref e)) if e.name().as_ref() == b"SourceLocation" => {
                for attr_result in e.attributes() {
                    match attr_result {
                        Ok(attr) => {
                            let key = attr.key.into_inner();

                            if key == b"path" {
                                if let Ok(value) = attr.unescape_value() {
                                    if !paths.contains(&value.to_string()) {
                                        paths.push(value.to_string());
                                    }
                                }
                            }
                        }
                        Err(e) => println!("Error processing attribute: {}", e),
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
