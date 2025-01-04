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


const CHUNK_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const API_BASE: &str = "/api/v1";

pub fn upload_zip(file_path: &str , token: &str, url: &str, project_name: &str, repo_info: Option<utils::generic::RepoInfo>) -> Result<String, Box<dyn std::error::Error>> {
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
            Ok(response) => response,
            Err(e) => {
                return Err(format!("Failed to send request: {}", e).into());
            }
        };
        if !response.status().is_success() {
            return Err(format!("Failed to upload file: {}", response.status()).into());

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


pub fn get_scan_issues(
    url: &str, 
    token: &str, 
    project: &str, 
    page: Option<u16>,
    page_size: Option<u16>
)  -> Result<ProjectIssuesResponse, Box<dyn std::error::Error>> {
    let mut url = format!(
        "{}{}/issues?project={}",
        url,
        API_BASE,
        project
    );
    if let Some(p) = page {
        url.push_str(&format!("&page={}", p));
    }
    if let Some(p_size) = page_size {
        url.push_str(&format!("&page_size={}", p_size));
    } else {
        url.push_str("&page_size=30");
    }
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());

    let response = match client.get(&url).headers(headers).send() {
        Ok(res) => res,
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    match response.json::<ProjectIssuesResponse>() {
        Ok(body) => {
            if body.status == "ok" {
                return Ok(body)
            } else if body.status == "no_project_found" {
                return Err("Project not found 404".into());
            } else {
                return Err("Server error 500".into());
            }
        },
        Err(e) => Err(format!("Failed to parse response: {}", e).into()),
    }
}

pub fn get_scan(url: &str, token: &str, scan_id: &str) -> Result<ScanResponse, Box<dyn std::error::Error>>  {
    let url = format!("{}{}/scan/{}", url, API_BASE, scan_id);

    let client = reqwest::blocking::Client::new();

    let mut headers = HeaderMap::new();
    headers.insert("CORGEA-TOKEN", token.parse().unwrap());

    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?; 

    if response.status().is_success() {
        let scan_response: ScanResponse = response.json().map_err(|e| format!("Failed to parse response: {}", e))?;
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
    let response = match client.get(&url).headers(headers).send() {
        Ok(res) => res,
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    return match response.json::<FullIssueResponse>() {
            Ok(body) => Ok(body),
            Err(e) => Err(format!("Failed to parse response: {}", e).into()),
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
    let response = match client
        .get(url)
        .headers(headers)
        .query(&query_params)
        .send() {
            Ok(res) => res,
            Err(e) => return Err(format!("API request failed: {}", e).into()), 
        };
        if response.status().is_success() {
            let api_response: ScansResponse = response.json()?; 
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
    pub page: u32,
    pub total_pages: u32,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct ScansResponse {
    pub status: String,
    pub page: u32,
    pub total_pages: u32,
    pub scans: Vec<ScanResponse>,
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
pub struct Classification {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Location {
    pub file: CorgeaFile,
    pub line_number: u32,
    pub project: Project,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CorgeaFile {
    pub name: String,
    pub language: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Project {
    pub name: String,
    pub branch: String,
    pub git_sha: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Details {
    pub explanation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AutoFixSuggestion {
    pub id: Option<String>,
    pub status: String,
    pub patch: Option<Patch>,
    pub full_code: Option<FullCode>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Patch {
    pub diff: String,
    pub explanation: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FullCode {
    pub before: String,
    pub after: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AutoTriage {
    pub false_positive_detection: FalsePositiveDetection,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FalsePositiveDetection {
    pub status: String,
    pub reasoning: Option<String>,
}


