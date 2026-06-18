use crate::log::debug;
use crate::utils;
use corgea::vuln_api::{auth_header, source};
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use reqwest::{
    blocking::multipart,
    blocking::multipart::{Form, Part},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const CHUNK_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const API_BASE: &str = "/api/v1";

fn auth_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let (name, value) = auth_header(token);
    headers.insert(name, value.parse().unwrap());
    headers.insert("CORGEA-SOURCE", source().parse().unwrap());
    headers
}

static AUTH_TOKEN: std::sync::LazyLock<std::sync::RwLock<String>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(String::new()));

pub fn set_auth_token(token: &str) {
    *AUTH_TOKEN.write().unwrap() = token.to_string();
}

static COOKIE_JAR: std::sync::LazyLock<std::sync::Arc<reqwest::cookie::Jar>> =
    std::sync::LazyLock::new(|| std::sync::Arc::new(reqwest::cookie::Jar::default()));

static SHARED_CLIENT: std::sync::LazyLock<reqwest::blocking::Client> =
    std::sync::LazyLock::new(|| {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5 * 30))
            .cookie_provider(COOKIE_JAR.clone());

        if let Ok(https_proxy) = std::env::var("https_proxy") {
            debug(&format!("https_proxy detected: {}", https_proxy));

            if std::env::var("CORGEA_ACCEPT_CERT").is_ok() {
                debug("Skipping CA cert validation");
                builder = builder.danger_accept_invalid_certs(true);
            }
        }

        builder.build().expect("Failed to build http client")
    });

pub struct HttpClient {
    inner: reqwest::blocking::Client,
}

pub struct DebugRequestBuilder {
    client: reqwest::blocking::Client,
    inner: reqwest::blocking::RequestBuilder,
}

impl HttpClient {
    pub fn get<U: reqwest::IntoUrl>(&self, url: U) -> DebugRequestBuilder {
        DebugRequestBuilder {
            client: self.inner.clone(),
            inner: self.inner.get(url),
        }
    }

    pub fn post<U: reqwest::IntoUrl>(&self, url: U) -> DebugRequestBuilder {
        DebugRequestBuilder {
            client: self.inner.clone(),
            inner: self.inner.post(url),
        }
    }

    pub fn patch<U: reqwest::IntoUrl>(&self, url: U) -> DebugRequestBuilder {
        DebugRequestBuilder {
            client: self.inner.clone(),
            inner: self.inner.patch(url),
        }
    }
}

impl DebugRequestBuilder {
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        reqwest::header::HeaderName: TryFrom<K>,
        <reqwest::header::HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        reqwest::header::HeaderValue: TryFrom<V>,
        <reqwest::header::HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self {
            inner: self.inner.header(key, value),
            client: self.client,
        }
    }

    pub fn query<T: Serialize + ?Sized>(self, query: &T) -> Self {
        Self {
            inner: self.inner.query(query),
            client: self.client,
        }
    }

    pub fn multipart(self, form: reqwest::blocking::multipart::Form) -> Self {
        Self {
            inner: self.inner.multipart(form),
            client: self.client,
        }
    }

    pub fn body<T: Into<reqwest::blocking::Body>>(self, body: T) -> Self {
        Self {
            inner: self.inner.body(body),
            client: self.client,
        }
    }

    pub fn send(self) -> reqwest::Result<reqwest::blocking::Response> {
        use reqwest::cookie::CookieStore;

        let token = AUTH_TOKEN.read().unwrap().clone();
        let builder = if !token.is_empty() {
            self.inner.headers(auth_headers(&token))
        } else {
            self.inner
        };

        let request = builder.build()?;

        debug(&format!("→ {} {}", request.method(), request.url()));
        debug(&format!("  Request headers: {:?}", request.headers()));
        match COOKIE_JAR.cookies(request.url()) {
            Some(cookies) => debug(&format!(
                "  Cookie: {}",
                cookies.to_str().unwrap_or("<binary>")
            )),
            None => debug("  Cookie: (none in jar for this URL)"),
        }

        let response = self.client.execute(request)?;

        debug(&format!("← {} {}", response.status(), response.url()));
        debug(&format!("  Response headers: {:?}", response.headers()));

        Ok(response)
    }
}

pub fn http_client() -> HttpClient {
    HttpClient {
        inner: SHARED_CLIENT.clone(),
    }
}

/// Returns true when the `warning` header carries an RFC 7234 code `299`,
/// which Corgea uses to signal a deprecated CLI version.
fn should_warn_deprecated(headers: &HeaderMap) -> bool {
    headers
        .get("warning")
        .and_then(|v| v.to_str().ok())
        .map(|text| {
            text.split(',')
                .any(|w| w.trim().split(' ').next() == Some("299"))
        })
        .unwrap_or(false)
}

#[cfg(not(test))]
const RETRY_BACKOFF_SECS: &[u64] = &[1, 2, 4, 8, 16, 32];

#[cfg(test)]
const RETRY_BACKOFF_SECS: &[u64] = &[0, 0, 0, 0, 0, 0];

pub fn retry_on_network_error<F, T>(operation: &str, mut make_request: F) -> reqwest::Result<T>
where
    F: FnMut() -> reqwest::Result<T>,
{
    let mut attempt = 0usize;
    loop {
        match make_request() {
            Ok(result) => return Ok(result),
            Err(e) if (e.is_connect() || e.is_timeout()) && attempt < RETRY_BACKOFF_SECS.len() => {
                let delay = RETRY_BACKOFF_SECS[attempt];
                log::warn!(
                    "Network error during {}: {}. Retrying in {}s... ({}/{})",
                    operation,
                    e,
                    delay,
                    attempt + 1,
                    RETRY_BACKOFF_SECS.len()
                );
                std::thread::sleep(std::time::Duration::from_secs(delay));
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

fn check_for_warnings(headers: &HeaderMap, status: StatusCode) {
    if should_warn_deprecated(headers) {
        log::warn!("This version of the Corgea plugin is deprecated. Please upgrade to the latest version to ensure continued support and better performance.");
    }
    if status == StatusCode::GONE {
        log::error!("Support for this extension version has dropped. Please upgrade Corgea extension immediately to continue using it.");
        std::process::exit(1);
    }
}

pub struct UploadZipResult {
    pub scan_id: String,
    pub project_id: Option<String>,
}

pub fn upload_zip(
    file_path: &str,
    url: &str,
    project_name: &str,
    repo_info: Option<utils::generic::RepoInfo>,
    scan_type: Option<String>,
    policy: Option<String>,
) -> Result<UploadZipResult, Box<dyn std::error::Error>> {
    let client = http_client();
    let file_size = std::fs::metadata(file_path)?.len();
    let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
    let json_object = json!({
        "file_name": file_name,
        "file_size": file_size
    });

    let form = reqwest::blocking::multipart::Form::new()
        .part(
            "files",
            reqwest::blocking::multipart::Part::bytes(Vec::new()).file_name(file_name.to_string()),
        )
        .text("json", json_object.to_string());

    let response_object = client
        .post(format!("{}{}/start-scan", url, API_BASE))
        .query(&[("scan_type", "blast")])
        .multipart(form)
        .send();
    let response_object = match response_object {
        Ok(response) => {
            check_for_warnings(response.headers(), response.status());
            response
        }
        Err(err) => {
            return Err(format!(
                "Network error: Unable to reach the server. Please try again later. Error: {}",
                err
            )
            .into())
        }
    };
    let response_status = response_object.status();
    let response_text = response_object.text()?;

    if response_status != StatusCode::OK {
        debug(&format!(
            "Initial scan request failed with status: {}. Response body: {}",
            response_status, response_text
        ));

        if response_status == StatusCode::BAD_REQUEST {
            if let Ok(error_response) =
                serde_json::from_str::<HashMap<String, Value>>(&response_text)
            {
                if let Some(message) = error_response.get("message").and_then(Value::as_str) {
                    return Err(format!("Request failed: {}", message).into());
                }
            }
            return Err(format!("Request failed (400): {}", response_text).into());
        }

        return Err("Error getting server response, Please try again later.".into());
    }

    let response: HashMap<String, Value> = match serde_json::from_str(&response_text) {
        Ok(json) => json,
        Err(_) => {
            debug(&format!(
                "Failed to parse initial scan response as JSON. Response body: {}",
                response_text
            ));
            return Err("Error getting server response, Please try again later.".into());
        }
    };

    let transfer_id = match response["transfer_id"].as_str() {
        Some(transfer_id) => transfer_id,
        None => return Err(
            "Failed to retrieve transfer ID. Please check the request parameters and try again."
                .into(),
        ),
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
            .part(
                "project_name",
                multipart::Part::text(project_name.to_string()),
            )
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
            .header("Upload-Offset", offset.to_string())
            .header("Upload-Length", file_size.to_string())
            .header("Upload-Name", file_name)
            .query(&[("scan_type", "blast")])
            .multipart(form)
            .send()
        {
            Ok(response) => {
                check_for_warnings(response.headers(), response.status());
                response
            }
            Err(e) => {
                return Err(format!("Failed to send request: {}", e).into());
            }
        };
        if !response.status().is_success() {
            let status_code = response.status();
            let response_text = response
                .text()
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            debug(&format!(
                "Chunk upload failed with status: {}. Response body: {}",
                status_code, response_text
            ));

            if status_code.is_client_error() && response_text.contains("Invalid policy ids") {
                return Err(
                    "Invalid policy ids passed. Please check the policy ids and try again.".into(),
                );
            }

            if status_code == StatusCode::BAD_REQUEST {
                if let Ok(error_response) =
                    serde_json::from_str::<HashMap<String, Value>>(&response_text)
                {
                    if let Some(message) = error_response.get("message").and_then(Value::as_str) {
                        return Err(format!("Upload failed: {}", message).into());
                    }
                }
                return Err(format!("Upload failed (400): {}", response_text).into());
            }

            return Err(format!("Failed to upload file: {}", status_code).into());
        }
        utils::terminal::show_progress_bar(offset as f32 / file_size as f32);
        offset += bytes_read as u64;

        if bytes_read < CHUNK_SIZE {
            utils::terminal::show_progress_bar(1.0);
            println!();
            let body: HashMap<String, Value> = response.json()?;
            if let Some(scan_id_value) = body.get("scan_id") {
                let scan_id = scan_id_value.as_str().unwrap().to_string();
                let project_id = body.get("project_id").and_then(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| v.as_i64().map(|n| n.to_string()))
                });
                return Ok(UploadZipResult {
                    scan_id,
                    project_id,
                });
            } else {
                return Err("Failed to get scan_id from response".into());
            }
        }
    }

    Err("Failed to upload file".into())
}

pub fn get_all_issues(
    url: &str,
    project: &str,
    scan_id: Option<String>,
) -> Result<Vec<Issue>, Box<dyn std::error::Error>> {
    let mut all_issues = Vec::new();
    let mut current_page: u32 = 1;

    loop {
        let response = match get_scan_issues(
            url,
            project,
            Some(current_page as u16),
            Some(30),
            scan_id.clone(),
        ) {
            Ok(response) => response,
            Err(e) => return Err(format!("Failed to get scan issues: {}", e).into()),
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
    project: &str,
    page: Option<u16>,
    page_size: Option<u16>,
    scan_id: Option<String>,
) -> Result<ProjectIssuesResponse, Box<dyn std::error::Error>> {
    let mut seperator = "?";
    let mut url = match scan_id {
        Some(scan_id) => format!("{}{}/scan/{}/issues", url, API_BASE, scan_id),
        None => {
            seperator = "&";
            format!("{}{}/issues?project={}", url, API_BASE, project)
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
    let client = http_client();

    debug(&format!("Sending request to URL: {}", url));

    let response = match client.get(&url).send() {
        Ok(res) => {
            check_for_warnings(res.headers(), res.status());
            res
        }
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    let response_text = response.text()?;
    let project_issues_response: ProjectIssuesResponse = serde_json::from_str(&response_text)
        .map_err(|e| {
            debug(&format!(
                "Failed to parse response: {}. Response body: {}",
                e, response_text
            ));
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

pub fn get_scan(url: &str, scan_id: &str) -> Result<ScanResponse, Box<dyn std::error::Error>> {
    let url = format!("{}{}/scan/{}", url, API_BASE, scan_id);

    let client = http_client();
    debug(&format!("Sending request to URL: {}", url));
    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    check_for_warnings(response.headers(), response.status());

    if response.status().is_success() {
        let response_text = response.text()?;
        let scan_response: ScanResponse = serde_json::from_str(&response_text).map_err(|e| {
            debug(&format!(
                "Failed to parse response: {}. Response body: {}",
                e, response_text
            ));
            format!("Failed to parse response: {}", e)
        })?;
        Ok(scan_response)
    } else {
        Err(format!(
            "Error: Unable to fetch scan status. Status code: {}",
            response.status()
        )
        .into())
    }
}

pub fn get_scan_report(
    url: &str,
    scan_id: &str,
    format: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = if let Some(fmt) = format {
        format!("{}{}/scan/{}/report?format={}", url, API_BASE, scan_id, fmt)
    } else {
        format!("{}{}/scan/{}/report", url, API_BASE, scan_id)
    };

    let client = http_client();

    debug(&format!("Sending request to URL: {}", url));

    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    check_for_warnings(response.headers(), response.status());

    if response.status().is_success() {
        Ok(response.text()?)
    } else {
        Err(format!(
            "Error: Unable to fetch scan report. Status code: {}",
            response.status()
        )
        .into())
    }
}

pub fn get_issue(url: &str, issue: &str) -> Result<FullIssueResponse, Box<dyn std::error::Error>> {
    let url = format!("{}{}/issue/{}", url, API_BASE, issue,);
    let client = http_client();
    debug(&format!("Sending request to URL: {}", url));
    let response = match client.get(&url).send() {
        Ok(res) => {
            check_for_warnings(res.headers(), res.status());
            res
        }
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    let response_text = response.text()?;
    match serde_json::from_str::<FullIssueResponse>(&response_text) {
        Ok(body) => Ok(body),
        Err(e) => {
            debug(&format!(
                "Failed to parse response: {}. Response body: {}",
                e, response_text
            ));
            Err(format!("Failed to parse response: {}", e).into())
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct SkillInfo {
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub is_installable: bool,
    #[serde(default)]
    pub latest_approved_version: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct SkillVersionInfo {
    pub version: String,
    pub status: String,
    #[serde(default)]
    pub is_installable: bool,
    #[serde(default)]
    pub security_concerns: String,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct SkillResponse {
    #[serde(default)]
    pub status: String,
    pub skill: SkillInfo,
    #[serde(default)]
    pub version: Option<SkillVersionInfo>,
}

/// Fetch a single skill (optionally a specific version) for installation.
///
/// Returns `Ok(None)` when no skill/version matches (HTTP 404), `Ok(Some(..))`
/// on success, and `Err(..)` for auth or other failures.
pub fn get_skill(
    url: &str,
    slug: &str,
    version: Option<&str>,
) -> Result<Option<SkillResponse>, Box<dyn Error>> {
    let mut request_url = format!("{}{}/skills/{}", url, API_BASE, slug);
    if let Some(v) = version {
        request_url = format!("{}?version={}", request_url, v);
    }

    let client = http_client();
    debug(&format!("Sending request to URL: {}", request_url));

    let response = client
        .get(&request_url)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    check_for_warnings(response.headers(), response.status());

    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == StatusCode::UNAUTHORIZED {
        return Err("Authentication failed. Please run 'corgea login'.".into());
    }
    if status == StatusCode::FORBIDDEN {
        return Err("Permission denied: you do not have access to skills.".into());
    }
    if !status.is_success() {
        return Err(format!("Unable to fetch skill. Status code: {}", status).into());
    }

    let response_text = response.text()?;
    let skill_response: SkillResponse = serde_json::from_str(&response_text).map_err(|e| {
        debug(&format!(
            "Failed to parse response: {}. Response body: {}",
            e, response_text
        ));
        format!("Failed to parse response: {}", e)
    })?;
    Ok(Some(skill_response))
}

pub fn query_scan_list(
    url: &str,
    project: Option<&str>,
    page: Option<u16>,
    page_size: Option<u16>,
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

    let client = http_client();
    debug(&format!("Sending request to URL: {}", url));
    let response = match client.get(url).query(&query_params).send() {
        Ok(res) => {
            check_for_warnings(res.headers(), res.status());
            res
        }
        Err(e) => return Err(format!("API request failed: {}", e).into()),
    };
    if response.status().is_success() {
        let response_text = response.text()?;
        let api_response: ScansResponse = serde_json::from_str(&response_text).map_err(|e| {
            debug(&format!(
                "Failed to parse response: {}. Response body: {}",
                e, response_text
            ));
            format!("Failed to parse response: {}", e)
        })?;
        Ok(api_response)
    } else {
        Err(format!("API request failed with status: {}", response.status()).into())
    }
}

pub fn exchange_code_for_token(
    base_url: &str,
    code: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();
    let exchange_url = format!("{}{}/authorize", base_url, API_BASE);

    let response = client
        .get(&exchange_url)
        .header("CORGEA-SOURCE", source())
        .query(&[("code", code)])
        .send()?;

    if response.status().is_success() {
        let response_json: HashMap<String, serde_json::Value> = response.json()?;

        if let Some(user_token) = response_json.get("user_token") {
            if let Some(user_token_str) = user_token.as_str() {
                return Ok(user_token_str.to_string());
            }
        }

        Err("User token not found in response".into())
    } else {
        let error_text = response
            .text()
            .unwrap_or_else(|_| "Unknown error".to_string());
        Err(format!("Failed to exchange code for user token: {}", error_text).into())
    }
}

pub fn verify_token(corgea_url: &str) -> Result<bool, Box<dyn Error>> {
    let url = format!("{}{}/verify", corgea_url, API_BASE);
    let client = http_client();
    debug(&format!("Sending request to URL: {}", url));

    let response = client.get(&url).send()?;

    check_for_warnings(response.headers(), response.status());

    if response.status().is_success() {
        let body_text = response.text()?;
        let body: HashMap<String, String> = match serde_json::from_str(&body_text) {
            Ok(json) => json,
            Err(e) => {
                debug(&format!(
                    "Failed to parse response as JSON: {}. Response body: {}",
                    e, body_text
                ));
                return Err("Failed to parse response".to_string().into());
            }
        };

        Ok(body.get("status").map(|s| s == "ok").unwrap_or(false))
    } else {
        Err(format!("Request failed with status: {}", response.status()).into())
    }
}

pub fn check_blocking_rules(
    url: &str,
    sast_scan_id: &str,
    page: Option<u32>,
) -> Result<BlockingRuleResponse, Box<dyn Error>> {
    let url = format!(
        "{}{}/scan/{}/check_blocking_rules",
        url, API_BASE, sast_scan_id
    );
    let page = page.unwrap_or(1);
    let query_params = vec![("page", page.to_string())];

    let client = http_client();
    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Query params: {:?}", query_params));

    let response = match client.get(url).query(&query_params).send() {
        Ok(res) => {
            check_for_warnings(res.headers(), res.status());
            debug(&format!("Response status: {}", res.status()));
            debug(&format!("Response headers: {:?}", res.headers()));
            res
        }
        Err(e) => return Err(format!("API request failed: {}", e).into()),
    };

    if response.status().is_success() {
        let response_text = response.text()?;
        let api_response: BlockingRuleResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                debug(&format!(
                    "Failed to parse response: {}. Response body: {}",
                    e, response_text
                ));
                format!("Failed to parse response: {}", e)
            })?;
        Ok(api_response)
    } else {
        let status = response.status();
        let response_text = response.text()?;
        debug(&format!("Response body: {}", response_text));
        Err(format!("API request failed with status: {}", status).into())
    }
}

pub fn get_sca_issues(
    url: &str,
    page: Option<u16>,
    page_size: Option<u16>,
    scan_id: Option<String>,
) -> Result<SCAIssuesResponse, Box<dyn std::error::Error>> {
    let client = http_client();
    let mut query_params = vec![];
    if let Some(page) = page {
        query_params.push(("page", page.to_string()));
    }
    if let Some(page_size) = page_size {
        query_params.push(("page_size", page_size.to_string()));
    }

    let endpoint = if let Some(scan_id) = scan_id {
        format!("{}{}/scan/{}/issues/sca", url, API_BASE, scan_id)
    } else {
        format!("{}{}/issues/sca", url, API_BASE)
    };

    debug(&format!("Sending request to URL: {}", endpoint));
    debug(&format!("Query params: {:?}", query_params));

    let response = client.get(&endpoint).query(&query_params).send();

    let response = match response {
        Ok(response) => {
            check_for_warnings(response.headers(), response.status());
            debug(&format!("Response status: {}", response.status()));
            debug(&format!("Response headers: {:?}", response.headers()));
            response
        }
        Err(err) => {
            return Err(format!(
                "Network error: Unable to reach the server. Please try again later. Error: {}",
                err
            )
            .into())
        }
    };

    let status = response.status();
    if !status.is_success() {
        if status == StatusCode::NOT_FOUND {
            return Err(
                "SCA issues not found. Please check the scan ID or ensure the scan has SCA issues."
                    .into(),
            );
        }
        return Err(format!("Request failed with status: {}", status).into());
    }

    let response_text = response.text()?;
    let response_data: SCAIssuesResponse = match serde_json::from_str(&response_text) {
        Ok(json) => json,
        Err(e) => {
            debug(&format!(
                "Failed to parse response: {}. Response body: {}",
                e, response_text
            ));
            return Err("Error parsing server response. Please try again later.".into());
        }
    };

    Ok(response_data)
}

pub fn get_all_sca_issues(
    url: &str,
    _project: &str,
    scan_id: Option<String>,
) -> Result<Vec<SCAIssue>, Box<dyn std::error::Error>> {
    let mut all_issues = Vec::new();
    let mut current_page: u32 = 1;

    loop {
        let response =
            match get_sca_issues(url, Some(current_page as u16), Some(30), scan_id.clone()) {
                Ok(response) => response,
                Err(e) => return Err(format!("Failed to get SCA issues: {}", e).into()),
            };

        if response.issues.is_empty() {
            break;
        }

        all_issues.extend(response.issues);

        if current_page >= response.total_pages {
            break;
        }
        current_page += 1;
    }

    Ok(all_issues)
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ScanResponse {
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
    pub total_issues: Option<u32>,
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
    pub triggered_by_rules: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SCAIssue {
    pub id: String,
    pub created_at: String,
    pub description: Option<String>,
    pub details: Option<String>,
    pub severity: Option<String>,
    pub cve: Option<String>,
    pub package: SCAPackage,
    pub location: SCALocation,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SCAPackage {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub fix_version: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SCALocation {
    pub path: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SCAIssuesResponse {
    pub status: String,
    pub issues: Vec<SCAIssue>,
    pub page: u32,
    pub total_pages: u32,
    pub total_issues: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn auth_headers_uses_bearer_for_jwt_tokens() {
        let headers = auth_headers("aaa.bbb.ccc");

        assert_eq!(
            headers.get("Authorization").map(|v| v.to_str().unwrap()),
            Some("Bearer aaa.bbb.ccc")
        );
        assert!(headers.get("CORGEA-TOKEN").is_none());
        assert!(headers.get("CORGEA-SOURCE").is_some());
    }

    #[test]
    fn auth_headers_uses_corgea_token_header_for_opaque_tokens() {
        let headers = auth_headers("opaque-token-xyz");

        assert_eq!(
            headers.get("CORGEA-TOKEN").map(|v| v.to_str().unwrap()),
            Some("opaque-token-xyz")
        );
        assert!(headers.get("Authorization").is_none());
        assert!(headers.get("CORGEA-SOURCE").is_some());
    }

    #[test]
    fn should_warn_deprecated_false_when_no_warning_header() {
        let headers = HeaderMap::new();
        assert!(!should_warn_deprecated(&headers));
    }

    #[test]
    fn should_warn_deprecated_false_for_non_299_codes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "warning",
            HeaderValue::from_static("199 - \"misc warning\""),
        );
        assert!(!should_warn_deprecated(&headers));
    }

    #[test]
    fn should_warn_deprecated_true_for_single_299() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "warning",
            HeaderValue::from_static("299 host \"deprecated\""),
        );
        assert!(should_warn_deprecated(&headers));
    }

    #[test]
    fn should_warn_deprecated_true_when_299_in_comma_separated_list() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "warning",
            HeaderValue::from_static("199 host \"first\", 299 host \"deprecated\""),
        );
        assert!(should_warn_deprecated(&headers));
    }

    use std::cell::Cell;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn connection_refused_error() -> reqwest::Error {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
        let port = listener
            .local_addr()
            .expect("failed to get listener addr")
            .port();
        drop(listener);

        reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .build()
            .expect("failed to build client")
            .get(format!("http://127.0.0.1:{port}"))
            .send()
            .expect_err("expected connection error")
    }

    fn timeout_error() -> reqwest::Error {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
        let port = listener
            .local_addr()
            .expect("failed to get listener addr")
            .port();

        thread::spawn(move || {
            if let Ok((_, _)) = listener.accept() {
                thread::sleep(Duration::from_secs(30));
            }
        });

        reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .expect("failed to build client")
            .get(format!("http://127.0.0.1:{port}"))
            .send()
            .expect_err("expected timeout error")
    }

    fn non_retryable_error() -> reqwest::Error {
        let err = reqwest::blocking::Client::new()
            .get("http://[::1:bad")
            .send()
            .expect_err("expected request error");

        assert!(
            !err.is_connect() && !err.is_timeout(),
            "expected a non-retryable reqwest error, got: {err}"
        );
        err
    }

    #[test]
    fn retry_on_network_error_returns_ok_on_first_success() {
        let attempts = Cell::new(0);

        let result = retry_on_network_error("test operation", || {
            attempts.set(attempts.get() + 1);
            Ok("success")
        });

        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn retry_on_network_error_retries_connect_errors_then_succeeds() {
        let attempts = Cell::new(0);

        let result = retry_on_network_error("test operation", || {
            let attempt = attempts.get() + 1;
            attempts.set(attempt);
            if attempt < 3 {
                Err(connection_refused_error())
            } else {
                Ok(42)
            }
        });

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn retry_on_network_error_retries_timeout_errors() {
        let attempts = Cell::new(0);

        let result = retry_on_network_error("test operation", || {
            let attempt = attempts.get() + 1;
            attempts.set(attempt);
            if attempt == 1 {
                Err(timeout_error())
            } else {
                Ok("recovered")
            }
        });

        assert_eq!(result.unwrap(), "recovered");
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn retry_on_network_error_does_not_retry_non_network_errors() {
        let attempts = Cell::new(0);

        let result: reqwest::Result<()> = retry_on_network_error("test operation", || {
            attempts.set(attempts.get() + 1);
            Err(non_retryable_error())
        });

        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn retry_on_network_error_gives_up_after_max_retries() {
        let attempts = Cell::new(0);

        let result: reqwest::Result<()> = retry_on_network_error("test operation", || {
            attempts.set(attempts.get() + 1);
            Err(connection_refused_error())
        });

        assert!(result.is_err());
        assert_eq!(attempts.get(), RETRY_BACKOFF_SECS.len() + 1);
    }
}
