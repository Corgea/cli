use std::collections::HashSet;
use std::io::{self, Read};
use crate::{utils, Config};
use uuid::Uuid;
use std::path::Path;
use std::process::Command;
use crate::cicd::{*};
use crate::log::debug;
use reqwest::header;
use crate::scanners::parsers::ScanParserFactory;
use serde_json::Value;

pub fn run_command(base_cmd: &String, mut command: Command) -> String {
    match which::which(base_cmd) {
        Ok(_) => {
            let output = match command.output() {
                Ok(output) => output,
                Err(e) => {
                    eprintln!("Failed to execute command: {}", e);
                    std::process::exit(1);
                }
            };

            if output.status.success() || (output.status.code() == Some(1) && base_cmd == "snyk") {
                println!("{} scan completed successfully", base_cmd);
                let stdout = String::from_utf8(output.stdout).expect("Failed to parse stdout");

                if stdout.contains("run `semgrep login`") {
                    eprintln!("You are not authenticated with semgrep. Please run 'semgrep login' to authenticate.");
                    std::process::exit(1);
                }

                return stdout;
            } else {
                let stderr = String::from_utf8(output.stderr).expect("Failed to parse stderr");
                let stdout = String::from_utf8(output.stdout).expect("Failed to parse stdout");
                eprintln!("{} failed: {}", base_cmd, stderr);
                eprintln!("{}", stdout);
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("{} binary not found, is it installed?", base_cmd);
            std::process::exit(1);
        }
    }
}

pub struct ScanUploadResult {
    pub scan_id: String,
    pub project_id: Option<String>,
}

pub fn run_semgrep(config: &Config, project_name: Option<String>) {
    println!("Scanning with semgrep...");
    let base_command = "semgrep";
    let mut command = std::process::Command::new(base_command);
    command.arg("scan").arg("--config").arg("auto").arg("--json");

    println!("Running \"semgrep scan --config auto --json\"");

    let output = run_command(&base_command.to_string(), command);

    if let Some(result) = parse_scan(config, output, true, project_name) {
        crate::wait::run(config, Some(result.scan_id), result.project_id);
    }
}

pub fn run_snyk(config: &Config, project_name: Option<String>) {
    println!("Scanning with snyk...");
    let base_command = "snyk";
    let mut command = std::process::Command::new(base_command);
    command.arg("code").arg("test").arg("--json");

    println!("Running \"snyk code test --json\"");

    let output = run_command(&base_command.to_string(), command);

    if let Some(result) = parse_scan(config, output, true, project_name) {
        crate::wait::run(config, Some(result.scan_id), result.project_id);
    }
}

pub fn read_stdin_report(config: &Config, project_name: Option<String>) {
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);

    let _ = parse_scan(config, input, false, project_name);
}

pub fn read_file_report(config: &Config, file_path: &str, project_name: Option<String>) {
    let input = match std::fs::read_to_string(file_path) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            std::process::exit(1);
        }
    };

    let _ = parse_scan(config, input, false, project_name);
}

pub fn parse_scan(config: &Config, input: String, save_to_file: bool, project_name: Option<String>) -> Option<ScanUploadResult> {
    debug("Parsing the scan report");

    // Remove BOM (Byte Order Mark) if present
    let cleaned_input = input.trim_start_matches('\u{feff}').trim();

    let parser_factory = ScanParserFactory::new();

    match parser_factory.parse_scan_data(cleaned_input) {
        Ok(parse_result) => {
            if parse_result.paths.is_empty() {
                eprintln!("No issues found in scan report, exiting.");
                std::process::exit(0);
            }

            return upload_scan(config, parse_result.paths, parse_result.scanner, cleaned_input.to_string(), save_to_file, project_name);
        }

        Err(error_message) => {
            eprintln!("{}", error_message);
            std::process::exit(1);
        }
    }
}

pub fn upload_scan(config: &Config, paths: Vec<String>, scanner: String, input: String, save_to_file: bool, project_name: Option<String>) -> Option<ScanUploadResult> {
    let in_ci = running_in_ci();
    let ci_platform = which_ci();
    let github_env_vars = get_github_env_vars();

    let run_id = Uuid::new_v4().to_string();
    let base_url = config.get_url();
    let api_base = "/api/v1";
    let project;

    if in_ci {
        debug("Running in CI");
        project = format!("{}-{}",
                          github_env_vars.get("GITHUB_REPOSITORY").expect("Failed to get GITHUB_REPOSITORY").to_string(),
                          github_env_vars.get("GITHUB_PR").expect("Failed to get GITHUB_REPOSITORY").to_string())
    } else {
        project = utils::generic::determine_project_name(project_name.as_deref());
    }
    let repo_data = std::env::var("REPO_DATA").unwrap_or_else(|_| "".to_string());

    let scan_upload_url = if repo_data.is_empty() {
        format!(
            "{}{}/scan-upload?engine={}&run_id={}&project={}&ci={}&ci_platform={}", base_url, api_base, scanner, run_id, project, in_ci, ci_platform
        )
    } else {
        format!(
            "{}{}/scan-upload?engine={}&run_id={}&project={}&ci={}&ci_platform={}&repo_data={}", base_url, api_base, scanner, run_id, project, in_ci, ci_platform, repo_data
        )
    };

    let git_config_upload_url = format!(
        "{}{}/git-config-upload?run_id={}", base_url, api_base, run_id
    );
    let client = utils::api::http_client();

    println!("Uploading required files for the scan...");

    let mut uploaded_paths = HashSet::new();
    let mut uploaded_count = 0;
    let mut upload_error_count = 0;

    for path in &paths {
        if !Path::new(&path).exists() {
            eprintln!("Required file {} not found which is required for the scan, exiting.", path);
            std::process::exit(1);
        }

        if uploaded_paths.contains(path) {
            continue;
        }

        let src_upload_url = format!(
            "{}{}/code-upload?run_id={}&path={}", base_url, api_base, run_id, path
        );
        debug(&format!("Uploading file: {}", path));
        let fp = Path::new(&path);

        let mut attempts = 0;
        let mut success = false;

        while attempts < 3 && !success {
            let form = reqwest::blocking::multipart::Form::new()
                .file("file", fp)
                .expect("Failed to read file");

            debug(&format!("POST: {}", src_upload_url));
            let res = client.post(&src_upload_url)
                .multipart(form)
                .send();

            match res {
                Ok(response) => {
                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response.text().unwrap_or_else(|_| "Unable to read response body".to_string());
                        debug(&format!("Code upload failed with status: {}. Response body: {}", status, body));
                        eprintln!("Failed to upload file {} {}... retrying", status, path);
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        attempts += 1;
                    } else {
                        uploaded_count += 1;
                        success = true;
                        uploaded_paths.insert(path.clone());
                    }
                }
                Err(e) => {
                    eprintln!("Failed to send request: {}", e);
                    std::process::exit(1);
                }
            }
        }

        if attempts == 3 && !success {
            upload_error_count += 1;
            eprintln!("Failed to upload file: {} after 3 attempts. skipping...", path);
        }
    }

    if uploaded_count == 0 {
        eprintln!("Failed to upload any files for the scan, exiting.");
        std::process::exit(1);
    }

    println!("Uploading the scan...");

    // main scan upload
    let input_bytes = input.as_bytes();
    let input_size = input_bytes.len();
    let max_upload_size = 50 * 1024 * 1024; // 50mb
    let chunk_size = match std::env::var("DEBUG_CORGEA_OVERRIDE_REPORT_CHUNK_SIZE") {
        Ok(val) => {
            match val.parse::<usize>() {
                Ok(mb) if mb > 0 => {
                    debug(&format!("Overriding report chunk size to {} MB", mb));
                    mb * 1024 * 1024
                }
                _ => {
                    eprintln!("Invalid DEBUG_CORGEA_OVERRIDE_REPORT_CHUNK_SIZE value '{}', using default 1 MB", val);
                    1024 * 1024
                }
            }
        }
        Err(_) => 1024 * 1024, // default 1mb
    };
    let is_chunked = input_size > max_upload_size;
    let res = if is_chunked {
        let total_chunks = (input_size + chunk_size - 1) / chunk_size;
        debug(&format!("Uploading scan in {} chunks", total_chunks));
        let mut offset = 0usize;
        let mut last_response = None;

        for (index, chunk) in input_bytes.chunks(chunk_size).enumerate() {
            debug(&format!("POST: {} (chunk {}/{})", scan_upload_url, index + 1, total_chunks));
            let response = client.post(&scan_upload_url)
                .header(header::CONTENT_TYPE, "application/json")
                .header("Upload-Offset", offset.to_string())
                .header("Upload-Length", input_size.to_string())
                .body(chunk.to_vec())
                .send();

            let should_break = match &response {
                Ok(res) => {
                    if !res.status().is_success() {
                        true
                    } else {
                        if let Some(server_offset) = res.headers().get("Upload-Offset") {
                            let expected_offset = offset + chunk.len();
                            if let Ok(server_offset_str) = server_offset.to_str() {
                                if let Ok(server_offset_val) = server_offset_str.parse::<usize>() {
                                    if server_offset_val != expected_offset {
                                        eprintln!(
                                            "Upload offset mismatch on chunk {}/{}: server has {} bytes but expected {}. \
                                            This may indicate that chunks are being routed to different server instances. \
                                            Please contact support.",
                                            index + 1, total_chunks, server_offset_val, expected_offset
                                        );
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                },
                Err(_) => true,
            };
            last_response = Some(response);
            if should_break {
                break;
            }
            offset += chunk.len();
        }

        last_response.expect("Failed to upload scan.")
    } else {
        debug(&format!("POST: {}", scan_upload_url));
        client.post(&scan_upload_url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(input.clone())
            .send()
    };

    let mut sast_scan_id: Option<String> = None;
    let mut project_id: Option<String> = None;

    let mut upload_failed = false;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let body_text = match response.text() {
                    Ok(text) => text,
                    Err(e) => {
                        eprintln!("Failed to read response body: {}", e);
                        String::new()
                    }
                };

                if !body_text.is_empty() {
                    match serde_json::from_str::<Value>(&body_text) {
                        Ok(json) => {
                            if let Some(id_val) = json.get("sast_scan_id") {
                                if let Some(id_str) = id_val.as_str() {
                                    println!("Scan ID: {}", id_str);
                                    sast_scan_id = Some(id_str.to_string());
                                } else if let Some(id_num) = id_val.as_i64() {
                                    println!("Scan ID: {}", id_num);
                                    sast_scan_id = Some(id_num.to_string());
                                }
                            }
                            if let Some(pid_val) = json.get("project_id") {
                                if let Some(pid_str) = pid_val.as_str() {
                                    project_id = Some(pid_str.to_string());
                                } else if let Some(pid_num) = pid_val.as_i64() {
                                    project_id = Some(pid_num.to_string());
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to parse response JSON: {}", e);
                        }
                    }
                }

                if is_chunked && sast_scan_id.is_none() {
                    eprintln!("Failed to upload scan: server did not return a scan ID after all chunks were sent. The scan was not created on the platform.");
                    upload_failed = true;
                } else {
                    println!("Successfully uploaded scan.");
                }
            } else {
                upload_failed = true;
                let status = response.status();
                let body = response.text().unwrap_or_else(|_| "Unable to read response body".to_string());
                debug(&format!("Scan upload failed with status: {}. Response body: {}", status, body));
                eprintln!("Failed to upload scan: {}", status);
            }
        }
        Err(e) => {
            eprintln!("Failed to send request: {}", e);
            upload_failed = true;
        }
    }


    let git_config_path = Path::new(".git/config");

    if git_config_path.exists() {
        debug("Uploading .git/config");
        let form = reqwest::blocking::multipart::Form::new()
            .file("file", git_config_path)
            .expect("Failed to read file");

        debug(&format!("POST: {}", git_config_upload_url));
        let res = client.post(&git_config_upload_url)
            .multipart(form)
            .send();

        match res {
            Ok(response) => {
                if !response.status().is_success() {
                    eprintln!("Failed to upload git config: {}", response.status());
                }
            }
            Err(e) => {
                eprintln!("Failed to send request: {}", e);
            }
        }
    }

    if in_ci {
        let ci_data_upload_url = format!(
            "{}{}/ci-data-upload?run_id={}&platform={}", base_url, api_base, run_id, ci_platform
        );

        let mut github_env_vars_json = serde_json::Map::new();
        for (key, value) in github_env_vars {
            github_env_vars_json.insert(key, Value::String(value));
        }

        let github_env_vars_json_string = match serde_json::to_string(&github_env_vars_json) {
            Ok(json_string) => json_string,
            Err(e) => {
                eprintln!("Failed to serialize JSON: {}", e);
                std::process::exit(1);
            }
        };

        debug(&format!("POST: {}", ci_data_upload_url));
        let _res = client.post(ci_data_upload_url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(github_env_vars_json_string)
            .send();
    }

    if save_to_file {
        let mut file_path = std::env::current_dir().expect("Failed to get current directory");
        file_path.push(format!("corgea_{}_{}_report.json", scanner, run_id));

        match std::fs::write(&file_path, input.clone()) {
            Ok(_) => println!("Successfully saved scan to {}", file_path.display()),
            Err(e) => eprintln!("Failed to save scan to {}: {}", file_path.display(), e)
        }
    }

    if upload_failed {
        std::process::exit(1);
    }

    println!("Successfully scanned using {} and uploaded to Corgea.", scanner);

    if upload_error_count > 0 {
        println!("Failed to upload {} files, you may not see all fixes in Corgea.", upload_error_count);
    }

    println!("Go to {base_url} to see results.");

    sast_scan_id.map(|scan_id| ScanUploadResult { scan_id, project_id })
}
