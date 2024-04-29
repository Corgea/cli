use std::collections::HashSet;
use serde_json::Value;
use std::io::{self, Read};
use crate::Config;
use reqwest::header;
use uuid::Uuid;
use std::path::Path;
use std::process::Command;
use crate::cicd::{*};

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

    parse_scan(config, output, true);
}

pub fn run_snyk(config: &Config) {
    println!("Scanning with snyk...");
    let base_command = "snyk";
    let mut command = std::process::Command::new(base_command);
    command.arg("code").arg("test").arg("--json");

    println!("Running \"snyk code test --json\"");

    let output = run_command(&base_command.to_string(), command);

    parse_scan(config, output, true);
}

pub fn read_stdin_report(config: &Config) {
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);

    parse_scan(config, input, false);
}

pub fn read_file_report(config: &Config, file_path: &str) {
    let input = match std::fs::read_to_string(file_path) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            std::process::exit(1);
        }
    };

    parse_scan(config, input, false);
}

pub fn parse_scan(config: &Config, input: String, save_to_file: bool) {
    let mut paths: Vec<String> = Vec::new();
    let mut scanner = String::new();
    let data: std::result::Result<Value, _> = serde_json::from_str(&input);

    match data {
        Ok(data) => {
            let schema = data.get("$schema").and_then(|v| v.as_str()).unwrap_or("unknown");

            if input.contains("semgrep.dev") {
                scanner = "semgrep".to_string();
                if let Some(results) = data.get("results").and_then(|v| v.as_array()) {
                    for result in results {
                        if let Some(path) = result.get("path").and_then(|v| v.as_str()) {
                            paths.push(path.to_string());
                        }
                    }
                }
            } else if schema.contains("sarif") {
                let run = data.get("runs").and_then(|v| v.as_array()).and_then(|v| v.get(0));
                let driver = run.and_then(|v| v.get("tool")).and_then(|v| v.get("driver")).and_then(|v| v.get("name"));
                let tool = driver.and_then(|v| v.as_str()).unwrap_or("unknown");

                if tool == "SnykCode" {
                    scanner = "snyk".to_string();
                } else if tool == "CodeQL" {
                    scanner = "codeql".to_string();
                } else {
                    eprintln!("{} is not supported as this time.", tool);
                    std::process::exit(1);
                }

                if let Some(runs) = data.get("runs").and_then(|v| v.as_array()) {
                    for run in runs {
                        if let Some(results) = run.get("results").and_then(|v| v.as_array()) {
                            for result in results {
                                if let Some(locations) = result.get("locations").and_then(|v| v.as_array()) {
                                    for location in locations {
                                        if let Some(uri) = location.get("physicalLocation").and_then(|v| v.get("artifactLocation")).and_then(|v| v.get("uri")).and_then(|v| v.as_str()) {
                                            paths.push(uri.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // checkmarx
            } else if input.contains("Cx") && data.get("results").is_some() && data.get("scanID").is_some() {
                scanner = "checkmarx".to_string();
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
            }
        }
        Err(e) => {
            eprintln!("Failed to parse JSON report: {}", e);
            eprintln!("Only reports in JSON format are supported.");
            std::process::exit(1);
        }
    }

    if paths.len() == 0 {
        eprintln!("No issues found in scan report, exiting.");
        std::process::exit(0);
    }

    upload_scan(config, paths, scanner, input, save_to_file);
}

fn upload_scan(config: &Config, paths: Vec<String>, scanner: String, input: String, save_to_file: bool) {
    let in_ci = running_in_ci();
    let ci_platform = which_ci();
    let github_env_vars = get_github_env_vars();

    let run_id = Uuid::new_v4().to_string();
    let token = config.get_token();
    let base_url = config.get_url();
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let project;

    if in_ci {
        project = format!("{}-{}",
                          github_env_vars.get("GITHUB_REPOSITORY").expect("Failed to get GITHUB_REPOSITORY").to_string(),
                          github_env_vars.get("GITHUB_PR").expect("Failed to get GITHUB_REPOSITORY").to_string())
    } else {
        project = current_dir.file_name().expect("Failed to get directory name").to_str().expect("Failed to convert OsStr to str").to_string();
    }

    let scan_upload_url = format!(
        "{}/api/cli/scan-upload?token={}&engine={}&run_id={}&project={}&ci={}&ci_platform={}", base_url, token, scanner, run_id, project, in_ci, ci_platform
    );
    let git_config_upload_url = format!(
        "{}/api/cli/git-config-upload?token={}&run_id={}", base_url, token, run_id
    );
    let client = reqwest::blocking::Client::new();

    println!("Uploading required files for the scan...");

    let mut uploaded_paths = HashSet::new();

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
        let fp = Path::new(&path);

        let form = reqwest::blocking::multipart::Form::new()
            .file("file", fp)
            .expect("Failed to read file");

        let client = reqwest::blocking::Client::new();
        let res = client.post(&src_upload_url)
            .multipart(form)
            .send();

        match res {
            Ok(response) => {
                if !response.status().is_success() {
                    eprintln!("Failed to upload file: {}", response.status());
                    std::process::exit(1);
                } else {
                    uploaded_paths.insert(path.clone());
                }
            }
            Err(e) => {
                eprintln!("Failed to send request: {}", e);
                std::process::exit(1);
            }
        }
    }

    println!("Uploading the scan...");

    // main scan upload
    let res = client.post(scan_upload_url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(input.clone())
        .send();

    match res {
        Ok(response) => {
            if response.status().is_success() {
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
        let form = reqwest::blocking::multipart::Form::new()
            .file("file", git_config_path)
            .expect("Failed to read file");

        let client = reqwest::blocking::Client::new();
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
    println!("Go to {base_url} to see results.");
}