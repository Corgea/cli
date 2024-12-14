use std::collections::HashSet;
use serde_json::Value;
use std::{io::{self, Read}, thread};
use std::sync::{Arc, Mutex};
use std::fs::File;
use std::error::Error;
use crate::Config;
use reqwest::{blocking::multipart, blocking::multipart::{Form, Part}, header};
use uuid::Uuid;
use std::path::Path;
use std::process::Command;
use crate::cicd::{*};
use crate::log::debug;
use serde_json::json;
use crate::utils;
use std::collections::HashMap;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use reqwest::StatusCode;

const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10 MB

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

pub fn run_blast(config: &Config) {
    println!("\nScanning with \x1b[31mblast\x1b[0m 🚀🚀🚀");
    let temp_path = "./.corgea/tmp";
    let project_name = utils::get_current_working_directory().unwrap_or("unknown".to_string());
    let zip_path = format!("{}/{}.zip", temp_path, project_name);
    let repo_info = match utils::get_repo_info("./") {
        Ok(info) => info,
        Err(_) => {
            None
        }
    };
    match utils::create_path_if_not_exists(temp_path) {
        Ok(_) => (),
        Err(e) => {
            eprintln!(
                "\n\nOops! Something went wrong while creating the directory at '{}'.\nPlease check if you have the necessary permissions or if the path is valid.\nError details:\n{}\n\n", 
                temp_path, e
            );
            std::process::exit(1);
        }
    }
    match utils::create_zip_from_filtered_files(".", None, &zip_path) {
        Ok(_) => { },
        Err(e) => {
            eprintln!(
                "\n\nUh-oh! We couldn't create the compressed file at '{}'.\nThis might be due to insufficient permissions, invalid file paths, or a file system error.\nPlease check the directory and try again.\nError details:\n{}\n\n", 
                zip_path, e
            );
            std::process::exit(1);
        }
    }
    let mut scan_id = String::new();
    println!("\n\nSubmitting scan to Corgea:");
    match upload_zip(&zip_path, &config.get_token(), &config.get_url(), &project_name, repo_info) {
        Ok(result) => {
            scan_id = result;
        },
        Err(e) => {
            eprintln!("\n\nOh no! We encountered an issue while uploading the zip file '{}' to the server.\nPlease ensure that:
    - Blast is enabled on your Corgea account.
    - Your network connection is stable.
    - The server URL '{}' is correct.
    - Your authentication token is valid.\n\n
    
    Error details:\n\n {}",
                zip_path,
                config.get_url(),
                e
            );
            std::process::exit(1);
        },
    }

    match utils::delete_directory(temp_path) {
        Ok(_) => { },
        Err(e) => {
            eprintln!(
                "\n\nCouldn't delete the temporary directory at '{}'.\nThis might happen if the directory is in use, you lack sufficient permissions, or the path is invalid.\nPlease check and try again.\nError details:\n{}\n\n", 
                temp_path, e
            );
        }
    }
    //print the url in green
    print!(
        "\n\nScan has started with ID: {}.\n\nYou can view it populate at the link:\n\x1b[32m{}/scan?scan_id={}\x1b[0m\n\n",
        scan_id,
        config.get_url(),
        scan_id
    );

    // Create loading animation
    let stop_signal = Arc::new(Mutex::new(false));

    // Spawn a new thread for the spinner animation
    let stop_signal_clone = Arc::clone(&stop_signal);
    thread::spawn(move || {
        utils::show_loading_message("Scanning... The Hunt Is On! ([TIME]s)", stop_signal_clone);
    });

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        match check_scan_status(&scan_id, &config.get_url(), &config.get_token()) {
            Ok(true) => {
                *stop_signal.lock().unwrap() = true;
                break;
            },
            Ok(false) => { },
            Err(e) => {
                eprintln!(
        "\n\nUnable to check the scan status for scan ID '{}'.\nPlease verify that:
        - The server URL '{}' is reachable.
        - Your authentication token is valid.
        - The scan ID '{}' exists and is correct.
        Error details:\n{}", 
                    scan_id,
                    config.get_url(),
                    scan_id,
                    e
                );
                std::process::exit(1);
            }
        }
    }
    println!(
        "\r\x1b[97m╭────────────────────────────────────────────╮\x1b[0m\n\
         \x1b[97m│ {: <42} │\x1b[0m\n\
         \x1b[97m│   🎉🎉 Scan Completed Successfully! 🎉🎉   │\x1b[0m\n\
         \x1b[97m│ {: <42} │\x1b[0m\n\
         \x1b[97m╰────────────────────────────────────────────╯\x1b[0m\n",
        " ", 
        " "
    );

    match report_scan_status(&config.get_url(), &config.get_token(), &project_name) {
        Ok(_) => {
            println!(
                "\n\nYou can view the scan results at the following link:\n\
            \x1b[32m{}/scan?scan_id={}\x1b[0m",
                config.get_url(),
                scan_id
            );
            print!("\n\nThank you for using Corgea! 😊\n\n")
        },
        Err(e) => {
            eprintln!(
                "\n\n\x1b[31mFailed to report the scan status for project: '{}'.\x1b[0m\n\n\
    However, the scan results may still be accessible at the following link:\n\n\
    \x1b[34m{}/scan?project_name={}\x1b[0m\n\n\
    \n\nPlease check your network connection, authentication token, and server URL:\n\n\
    - Server URL: {}\n\
    - Error details: {}\n",
                project_name,
                config.get_url(),
                project_name,
                config.get_url(),
                e
            );
            std::process::exit(1);
        }
    }
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
    debug("Parsing the scan report json");

    let mut paths: Vec<String> = Vec::new();
    let mut scanner = String::new();
    let data: std::result::Result<Value, _> = serde_json::from_str(&input);

    match data {
        Ok(data) => {
            let schema = data.get("$schema").and_then(|v| v.as_str()).unwrap_or("unknown");

            if input.contains("semgrep.dev") {
                debug("Detected semgrep schema");
                scanner = "semgrep".to_string();
                if let Some(results) = data.get("results").and_then(|v| v.as_array()) {
                    for result in results {
                        if let Some(path) = result.get("path").and_then(|v| v.as_str()) {
                            paths.push(path.to_string());
                        }
                    }
                }
            } else if schema.contains("sarif") {
                debug("Detected sarif schema");
                let run = data.get("runs").and_then(|v| v.as_array()).and_then(|v| v.get(0));
                let driver = run.and_then(|v| v.get("tool")).and_then(|v| v.get("driver")).and_then(|v| v.get("name"));
                let tool = driver.and_then(|v| v.as_str()).unwrap_or("unknown");

                if tool == "SnykCode" {
                    debug("Detected snyk version of sarif schema");
                    scanner = "snyk".to_string();
                } else if tool == "CodeQL" {
                    debug("Detected codeql version of sarif schema");
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
            // checkmarx report generated by CLI
            } else if data.get("totalCount").is_some() && data.get("results").is_some() && data.get("scanID").is_some() {
                debug("Detected checkmarx cli schema");
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
            // for checkmarx report generated by web
            } else if data.get("scanResults").is_some() && data.get("reportId").is_some() {
                debug("Detected checkmarx web schema");
                scanner = "checkmarx".to_string();
                if let Some(scan_results) = data.get("scanResults") {
                    if let Some(sast) = scan_results.get("sast") {
                        if let Some(languges) = sast.get("languages").and_then(|v| v.as_array()) {
                            for language in languges {
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
            } else {
                debug("Couldn't detect what kind of report this is.")
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

pub fn upload_scan(config: &Config, paths: Vec<String>, scanner: String, input: String, save_to_file: bool) {
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

    let scan_upload_url = format!(
        "{}/api/cli/scan-upload?token={}&engine={}&run_id={}&project={}&ci={}&ci_platform={}", base_url, token, scanner, run_id, project, in_ci, ci_platform
    );
    let git_config_upload_url = format!(
        "{}/api/cli/git-config-upload?token={}&run_id={}", base_url, token, run_id
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5 * 60))
        .build()
        .expect("Failed to build client");

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
}

pub fn upload_zip(file_path: &str , token: &str, url: &str, project_name: &str, repo_info: Option<utils::RepoInfo>) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5 * 60))
        .build()
        .expect("Failed to build client");

    let file_size = std::fs::metadata(file_path)?.len();
    let file_name = Path::new(file_path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let json_object = json!({
        "file_name": file_name,
        "file_size": file_size
    });

    let form = reqwest::blocking::multipart::Form::new()
        .part("files", reqwest::blocking::multipart::Part::bytes(Vec::new())
        .file_name(file_name.to_string()))
        .text("json", json_object.to_string());

    let response_object = client
        .post(format!("{}/api/start-scan", url))
        .header("CORGEA-TOKEN", token)
        .query(&[
            ("scan_type", "blast"),
        ])
        .multipart(form)
        .send();
    let response_object = match response_object {
        Ok(response) => response,
        Err(err) => return Err(format!("Network error: Unable to reach the server. Please try again later. Error: {}", err).into()),
    };
    let response_status = response_object.status();
    let response: HashMap<String, Value> = match response_object.json() {
        Ok(json) => json,
        Err(_) => return Err("Error getting server response, Please try again later.".into()),
    };

    if response_status != StatusCode::OK {
        let message = response.get("message")
            .and_then(Value::as_str)
            .unwrap_or("An unknown error occurred. Please try again or contact support.");
        return Err(format!("Request failed: {}", message).into());
    }

    let transfer_id = match response["transfer_id"].as_str() {
        Some(transfer_id) => transfer_id,
        None => return Err("Failed to retrieve transfer ID. Please check the request parameters and try again.".into()),
    };
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0; CHUNK_SIZE];
    let mut offset: u64 = 0;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];
 
        let mut form = Form::new()
        .part(
            "chunk_data", 
            Part::bytes(chunk.to_vec())
                .file_name(file_name.to_string())
                .mime_str("application/octet-stream")?,
        )
        .part("project_name", multipart::Part::text(project_name.to_string()))
        .part("file_size", multipart::Part::text(file_size.to_string()));
        if let Some(ref info) = repo_info {
            if let Some(branch) = &info.branch {
                form = form.part("branch", multipart::Part::text(branch.to_string()));
            }
            if let Some(repo_url) = &info.repo_url {
                form = form.part("repo_url", multipart::Part::text(repo_url.to_string()));
            }
            if let Some(sha) = &info.sha {
                form = form.part("sha", multipart::Part::text(sha.to_string()));
            }
        }


        let response = match client
        .patch(format!("{}/api/start-scan/{}/", url, transfer_id))
        .header("CORGEA-TOKEN", token)
        .header("Upload-Offset", offset.to_string())
        .header("Upload-Length", file_size.to_string())
        .header("Upload-Name", file_name)
        .query(&[
            ("scan_type", "blast")
        ])
        .multipart(form)
        .send() {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Failed to send request: {}", e);
                std::process::exit(1);
            }
        };
        if !response.status().is_success() {
            eprintln!("Failed to upload file: {}", response.status());
            std::process::exit(1);
        }
        utils::show_progress_bar(offset as f32 / file_size as f32);
        offset += bytes_read as u64;

        if bytes_read < CHUNK_SIZE {
            utils::show_progress_bar(1.0);
            print!("\n");
            let body: HashMap<String, Value> = response.json()?;
            if let Some(scan_id_value) = body.get("scan_id") {
                return Ok(scan_id_value.as_str().unwrap().to_string());
            } else {
                eprint!("Failed to get scan_id from response");
                std::process::exit(1);
            }
        }
    }
    
    Err("Failed to upload file".into())
}


fn check_scan_status(scan_id: &str, url: &str, token: &str) -> Result<bool, Box<dyn Error>> {
    // Construct the URL
    let url = format!("{}/api/cli/scan/{}", url, scan_id); // Adjust URL if needed

    // Create a new reqwest client
    let client = reqwest::blocking::Client::new();

    // Set the authorization token in the headers
    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());

    // Send the synchronous GET request to the Django endpoint
    let response = client
        .get(&url)
        .headers(headers)
        .send()?;

    // Check if the response is successful (status code 200)
    if response.status().is_success() {
        // Deserialize the JSON response into ScanResponse struct
        let scan_response: ScanResponse = response.json()?;
        // Return the processed status
        Ok(scan_response.processed)
    } else {
        // Handle errors (non-200 status code)
        Err(format!("Error: Unable to fetch scan status. Status code: {}", response.status()).into())
    }
}


fn report_scan_status(url: &str, token: &str, project: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "{}/api/cli/issues?token={}&project={}",
        url,
        token,
        project
    );

    let response = match reqwest::blocking::get(&url) {
        Ok(res) => res,
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    let body: ProjectIssuesResponse = match response.json() {
            Ok(body) => body,
            Err(e) => return Err(format!("Failed to parse response: {}", e).into()),
        };

    if body.status == "ok" {
        let issues = body.issues.unwrap_or_default();
        let total_issues = issues.len();

        let mut classification_counts: HashMap<String, usize> = HashMap::new();
        for issue in issues {
            *classification_counts.entry(issue.classification).or_insert(0) += 1;
        }

        // Print total issues
        println!("\x1b[31mTotal issues found: {}\x1b[0m", total_issues);

        
        // for (classification, count) in classification_counts {
        //     println!("{}: {}", classification, count);
        // }
    } else {
        println!("🎉✨ No vulnerabilities found! Your project is squeaky clean and secure! 🚀🔒");
    }

    Ok(())
}

#[derive(Deserialize, Serialize)]
struct ScanResponse {
    id: String,
    repo: Option<String>,
    branch: Option<String>,   
    processed: bool,
}


#[derive(Deserialize)]
struct Issue {
    classification: String,
}

#[derive(Deserialize)]
struct ProjectIssuesResponse {
    status: String,
    issues: Option<Vec<Issue>>,
}