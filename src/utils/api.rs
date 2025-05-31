use crate::utils;
use serde_json::json;
use std::collections::HashMap;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use reqwest::StatusCode;
use std::fs::File;
use std::error::Error;
use std::io::Read;
use std::path::Path;
use reqwest::{blocking::multipart, blocking::multipart::{Form, Part}};
use serde_json::Value;
use crate::log::debug;

const CHUNK_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const API_BASE: &str = "/api/v1";

fn check_for_warnings(headers: &HeaderMap, status: StatusCode) {
    if let Some(warning) = headers.get("warning") {
        let warnings = warning.to_str().unwrap().split(',');
        for warning in warnings {
            let code = warning.trim().split(' ').next().unwrap();
            if code == "299" {
                eprintln!("This version of the Corgea plugin is deprecated. Please upgrade to the latest version to ensure continued support and better performance.");
            }
        }
    }
    if status == StatusCode::GONE {
        eprintln!("Support for this extension version has dropped. Please upgrade Corgea extension immediately to continue using it.");
        std::process::exit(1);
    }
}

pub fn upload_zip(
    file_path: &str , 
    token: &str, 
    url: &str, 
    project_name: &str, 
    repo_info: Option<utils::generic::RepoInfo>,
    scan_type: Option<String>,
    policy: Option<String>
) -> Result<String, Box<dyn std::error::Error>> {
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
        .post(format!("{}{}/start-scan", url, API_BASE))
        .header("CORGEA-TOKEN", token)
        .query(&[
            ("scan_type", "blast"),
        ])
        .multipart(form)
        .send();
    let response_object = match response_object {
        Ok(response) => {
            check_for_warnings(response.headers(), response.status());
            response
        },
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
        if let Some(scan_type) = scan_type.clone() {
            let scan_type = if scan_type.contains("blast") {
                "base".to_string()
            } else {
                scan_type
            };
            form = form.part("scan_configs", multipart::Part::text(scan_type.to_string()));
        }
        if let Some(policy) = policy.clone() {
            form = form.part("target_policies", multipart::Part::text(policy.to_string()));
        }

        let response = match client
        .patch(format!("{}{}/start-scan/{}/", url, API_BASE, transfer_id))
        .header("CORGEA-TOKEN", token)
        .header("Upload-Offset", offset.to_string())
        .header("Upload-Length", file_size.to_string())
        .header("Upload-Name", file_name)
        .query(&[
            ("scan_type", "blast")
        ])
        .multipart(form)
        .send() {
            Ok(response) => {
                check_for_warnings(response.headers(), response.status());
                response
            },
            Err(e) => {
                return Err(format!("Failed to send request: {}", e).into());
            }
        };
        if !response.status().is_success() {
            let status_code = response.status();
            if status_code.is_client_error() && response.text().unwrap().contains("Invalid policy ids") {
                return Err("Invalid policy ids passed. Please check the policy ids and try again.".into());
            }
            return Err(format!("Failed to upload file: {}", status_code).into());

        }
        utils::terminal::show_progress_bar(offset as f32 / file_size as f32);
        offset += bytes_read as u64;

        if bytes_read < CHUNK_SIZE {
            utils::terminal::show_progress_bar(1.0);
            print!("\n");
            let body: HashMap<String, Value> = response.json()?;
            if let Some(scan_id_value) = body.get("scan_id") {
                return Ok(scan_id_value.as_str().unwrap().to_string());
            } else {
                return Err("Failed to get scan_id from response".into());
            }
        }
    }
    
    Err("Failed to upload file".into())
}

pub fn get_all_issues(url: &str, token: &str, project: &str, scan_id: Option<String>) -> Result<Vec<Issue>, Box<dyn std::error::Error>> {
    let mut all_issues = Vec::new();
    let mut current_page: u32 = 1;
    
    loop {
        let response = match get_scan_issues(url, token, project, Some(current_page as u16), Some(30), scan_id.clone()) {
            Ok(response) => response,
            Err(e) => return Err(format!("Failed to get scan issues: {}", e).into())
        };
        
        if let Some(mut issues) = response.issues {
            if issues.is_empty() {
                break;
            }
            all_issues.append(&mut issues);
            if let Some(total_pages) = response.total_pages {
                if current_page >= total_pages {
                    break;
                }
            }
            current_page += 1;
        } else {
            return Err("No issues found in response".into());
        }
    }

    Ok(all_issues)
}

pub fn get_scan_issues(
    url: &str, 
    token: &str, 
    project: &str, 
    page: Option<u16>,
    page_size: Option<u16>,
    scan_id: Option<String>
)  -> Result<ProjectIssuesResponse, Box<dyn std::error::Error>> {
    let mut seperator = "?";
    let mut url = match scan_id {
        Some(scan_id) => format!("{}{}/scan/{}/issues", url, API_BASE, scan_id),
        None => {
            seperator = "&";
            format!(
                "{}{}/issues?project={}",
                url,
                API_BASE,
                project
            )
        }
    };
    if let Some(p) = page {
        url.push_str(&format!("{}page={}", seperator, p));
    }
    if let Some(p_size) = page_size {
        url.push_str(&format!("&page_size={}", p_size));
    } else {
        url.push_str("&page_size=30");
    }
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());

    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Headers: {:?}", headers));

    let response = match client.get(&url).headers(headers).send() {
        Ok(res) => {
            check_for_warnings(res.headers(), res.status());
            res
        },
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    let response_text = response.text()?;
    let project_issues_response: ProjectIssuesResponse = serde_json::from_str(&response_text).map_err(|e| {
        debug(&format!("Failed to parse response: {}. Response body: {}", e, response_text));
        format!("Failed to parse response: {}", e)
    })?;
    
    if project_issues_response.status == "ok" {
        Ok(project_issues_response)
    } else if project_issues_response.status == "no_project_found" {
        Err("Project not found 404".into())
    } else {
        Err("Server error 500".into())
    }
}

pub fn get_scan(url: &str, token: &str, scan_id: &str) -> Result<ScanResponse, Box<dyn std::error::Error>>  {
    let url = format!("{}{}/scan/{}", url, API_BASE, scan_id);

    let client = reqwest::blocking::Client::new();

    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());
    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Headers: {:?}", headers));
    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?; 

    check_for_warnings(response.headers(), response.status());

    if response.status().is_success() {
        let response_text = response.text()?;
        let scan_response: ScanResponse = serde_json::from_str(&response_text).map_err(|e| {
            debug(&format!("Failed to parse response: {}. Response body: {}", e, response_text));
            format!("Failed to parse response: {}", e)
        })?;
        Ok(scan_response)
    } else {
        Err(format!("Error: Unable to fetch scan status. Status code: {}", response.status()).into())
    }
}


pub fn get_issue(url: &str, token: &str, issue: &str) -> Result<FullIssueResponse, Box<dyn std::error::Error>> {
    let url = format!(
        "{}{}/issue/{}",
        url,
        API_BASE,
        issue,
    );
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());
    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Headers: {:?}", headers));
    let response = match client.get(&url).headers(headers).send() {
        Ok(res) => {
            check_for_warnings(res.headers(), res.status());
            res
        },
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    let response_text = response.text()?;
    return match serde_json::from_str::<FullIssueResponse>(&response_text) {
        Ok(body) => Ok(body),
        Err(e) => {
            debug(&format!("Failed to parse response: {}. Response body: {}", e, response_text));
            Err(format!("Failed to parse response: {}", e).into())
        },
    };
}



pub fn query_scan_list(
    url: &str,
    token: &str,
    project: Option<&str>,
    page: Option<u16>,
    page_size: Option<u16>
) -> Result<ScansResponse, Box<dyn Error>> {
    let url = format!("{}{}/scans", url, API_BASE);
    let page = page.unwrap_or(1);
    let mut query_params = vec![("page", page.to_string())];
    if let Some(p_size) = page_size {
        query_params.push(("page_size", p_size.to_string()));
    } else {
        query_params.push(("page_size", "30".to_string()));
    }
    if let Some(project) = project {
        query_params.push(("project", project.to_string()));
    }


    let client = reqwest::blocking::Client::new(); 
    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());
    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Headers: {:?}", headers));
    let response = match client
        .get(url)
        .headers(headers)
        .query(&query_params)
        .send() {
            Ok(res) => {
                check_for_warnings(res.headers(), res.status());
                res
            },
            Err(e) => return Err(format!("API request failed: {}", e).into()), 
        };
        if response.status().is_success() {
            let response_text = response.text()?;
            let api_response: ScansResponse = serde_json::from_str(&response_text).map_err(|e| {
                debug(&format!("Failed to parse response: {}. Response body: {}", e, response_text));
                format!("Failed to parse response: {}", e)
            })?;
            Ok(api_response)
        } else {
            Err(format!(
                "API request failed with status: {}",
                response.status()
            ).into())
        }
}


pub fn verify_token(token: &str, corgea_url: &str) -> Result<bool, Box<dyn Error>> {
    let url = format!("{}{}/verify", corgea_url, API_BASE);
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());
    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Headers: {:?}", headers));

    let response = client
        .get(url)
        .headers(headers)
        .send()?;

    check_for_warnings(response.headers(), response.status());

    if response.status().is_success() {
        let body_text = response.text()?;
        let body: HashMap<String, String> = match serde_json::from_str(&body_text) {
            Ok(json) => json,
            Err(e) => {
                debug(&format!("Failed to parse response as JSON: {}. Response body: {}", e, body_text));
                return Err(format!("Failed to parse response").into());
            }
        };

        Ok(body.get("status").map(|s| s == "ok").unwrap_or(false))
    } else {
        Err(format!("Request failed with status: {}", response.status()).into())
    }
}

pub fn check_blocking_rules(
    url: &str,
    token: &str,
    sast_scan_id: &str,
    page: Option<u32>
) -> Result<BlockingRuleResponse, Box<dyn Error>> {
    let url = format!("{}{}/scan/{}/check_blocking_rules", url, API_BASE, sast_scan_id);
    let page = page.unwrap_or(1);
    let query_params = vec![("page", page.to_string())];

    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());

    let response = match client
        .get(url)
        .headers(headers)
        .query(&query_params)
        .send() {
            Ok(res) => {
                check_for_warnings(res.headers(), res.status());
                res
            },
            Err(e) => return Err(format!("API request failed: {}", e).into()),
        };

    if response.status().is_success() {
        let api_response: BlockingRuleResponse = response.json()?;
        Ok(api_response)
    } else {
        Err(format!(
            "API request failed with status: {}",
            response.status()
        ).into())
    }
}



#[derive(Deserialize, Serialize, Debug)]
pub struct ScanResponse  {
    pub id: String,
    pub project: String,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub status: String,
    pub engine: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProjectIssuesResponse {    
    pub status: String,
    pub issues: Option<Vec<Issue>>,
    pub page: Option<u32>,
    pub total_pages: Option<u32>,
    pub total_issues: Option<u32>
}


#[derive(Serialize, Deserialize, Debug)]
pub struct ScansResponse {
    pub status: String,
    pub page: Option<u32>,
    pub total_pages: Option<u32>,
    pub scans: Option<Vec<ScanResponse>>,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct FullIssueResponse {
    pub status: String,
    pub issue: Issue,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Issue {
    pub id: String,
    pub scan_id: Option<String>,
    pub status: String,
    pub urgency: String,
    pub created_at: String,
    pub classification: Classification,
    pub location: Location,
    pub details: Option<Details>,
    pub auto_triage: AutoTriage,
    pub auto_fix_suggestion: Option<AutoFixSuggestion>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IssueWithBlockingRules {
    pub id: String,
    pub scan_id: Option<String>,
    pub status: String,
    pub urgency: String,
    pub created_at: String,
    pub classification: Classification,
    pub location: Location,
    pub details: Option<Details>,
    pub auto_triage: AutoTriage,
    pub auto_fix_suggestion: Option<AutoFixSuggestion>,
    pub blocked: bool,
    pub blocking_rules: Option<Vec<String>>,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Classification {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Location {
    pub file: CorgeaFile,
    pub line_number: u32,
    pub project: Project,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CorgeaFile {
    pub name: String,
    pub language: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Project {
    pub name: String,
    pub branch: Option<String>,
    pub git_sha: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Details {
    pub explanation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AutoFixSuggestion {
    pub id: Option<String>,
    pub status: String,
    pub patch: Option<Patch>,
    pub full_code: Option<FullCode>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Patch {
    pub diff: String,
    pub explanation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullCode {
    pub before: String,
    pub after: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AutoTriage {
    pub false_positive_detection: FalsePositiveDetection,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FalsePositiveDetection {
    pub status: String,
    pub reasoning: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BlockingRuleResponse {
    pub block: bool,
    pub blocking_issues: Vec<BlockingIssue>,
    pub total_pages: u32,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BlockingIssue {
    pub id: String,
    pub triggered_by_rules: Vec<String>
}

