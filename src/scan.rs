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

pub fn run_semgrep(config: &Config) {
    println!("Scanning with semgrep...");
    let base_command = "semgrep";
    let mut command = std::process::Command::new(base_command);
    command.arg("scan").arg("--config").arg("auto").arg("--json");

    println!("Running \"semgrep scan --config auto --json\"");

    let output = run_command(&base_command.to_string(), command);

    if let Some(scan_id) = parse_scan(config, output, true) {
        crate::wait::run(config, Some(scan_id));
    }
}

pub fn run_snyk(config: &Config) {
    println!("Scanning with snyk...");
    let base_command = "snyk";
    let mut command = std::process::Command::new(base_command);
    command.arg("code").arg("test").arg("--json");

    println!("Running \"snyk code test --json\"");

    let output = run_command(&base_command.to_string(), command);

    if let Some(scan_id) = parse_scan(config, output, true) {
        crate::wait::run(config, Some(scan_id));
    }
}

pub fn read_stdin_report(config: &Config) {
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);

    let _ = parse_scan(config, input, false);
}

pub fn read_file_report(config: &Config, file_path: &str) {
    let input = match std::fs::read_to_string(file_path) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            std::process::exit(1);
        }
    };

    let _ = parse_scan(config, input, false);
}

pub fn parse_scan(config: &Config, input: String, save_to_file: bool) -> Option<String> {
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

            return upload_scan(config, parse_result.paths, parse_result.scanner, cleaned_input.to_string(), save_to_file);
        }
        Err(error_message) => {
            eprintln!("{}", error_message);
            std::process::exit(1);
        }
    }
}

pub fn upload_scan(config: &Config, paths: Vec<String>, scanner: String, input: String, save_to_file: bool) -> Option<String> {
    let in_ci = running_in_ci();
    let ci_platform = which_ci();
    let github_env_vars = get_github_env_vars();

    let run_id = Uuid::new_v4().to_string();
    let token = config.get_token();
    let base_url = config.get_url();
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let project;

    if in_ci {
        debug("Running in CI");
        project = format!("{}-{}",
                          github_env_vars.get("GITHUB_REPOSITORY").expect("Failed to get GITHUB_REPOSITORY").to_string(),
                          github_env_vars.get("GITHUB_PR").expect("Failed to get GITHUB_REPOSITORY").to_string())
    } else {
        project = current_dir.file_name().expect("Failed to get directory name").to_str().expect("Failed to convert OsStr to str").to_string();
    }
    let repo_data = std::env::var("REPO_DATA").unwrap_or_else(|_| "".to_string()); //encoded data to forward.

    let scan_upload_url = if repo_data.is_empty() {
        format!(
            "{}/api/cli/scan-upload?token={}&engine={}&run_id={}&project={}&ci={}&ci_platform={}", base_url, token, scanner, run_id, project, in_ci, ci_platform
        )
    } else {
        format!(
            "{}/api/cli/scan-upload?token={}&engine={}&run_id={}&project={}&ci={}&ci_platform={}&repo_data={}", base_url, token, scanner, run_id, project, in_ci, ci_platform, repo_data
        )
    };

    let git_config_upload_url = format!(
        "{}/api/cli/git-config-upload?token={}&run_id={}", base_url, token, run_id
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
            "{}/api/cli/code-upload?token={}&run_id={}&path={}", base_url, token, run_id, path
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
                        eprintln!("Failed to upload file {} {}... retrying", response.status(), path);
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
    debug(&format!("POST: {}", scan_upload_url));
    let res = client.post(scan_upload_url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(input.clone())
        .send();

    let mut sast_scan_id: Option<String> = None;

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
                        }
                        Err(e) => {
                            eprintln!("Failed to parse response JSON: {}", e);
                        }
                    }
                }
                println!("Successfully uploaded scan.");
            } else {
                eprintln!("Failed to upload scan: {}", response.status());
            }
        }
        Err(e) => {
            eprintln!("Failed to send request: {}", e);
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
            "{}/api/cli/ci-data-upload?token={}&run_id={}&platform={}", base_url, token, run_id, ci_platform
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

    println!("Successfully scanned using {} and uploaded to Corgea.", scanner);

    if upload_error_count > 0 {
        println!("Failed to upload {} files, you may not see all fixes in Corgea.", upload_error_count);
    }

    println!("Go to {base_url} to see results.");

    sast_scan_id
}
