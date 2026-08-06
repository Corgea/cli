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
    metadata: Option<String>,
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
        if let Some(meta) = &metadata {
            form = form.part("metadata", multipart::Part::text(meta.clone()));
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
    // Project names can contain `&`/`?`/`#`, so use `query`, not `format!`.
    let (url, mut query_params) = match scan_id {
        Some(scan_id) => (
            format!("{}{}/scan/{}/issues", url, API_BASE, scan_id),
            vec![],
        ),
        None => (
            format!("{}{}/issues", url, API_BASE),
            vec![("project", project.to_string())],
        ),
    };
    if let Some(p) = page {
        query_params.push(("page", p.to_string()));
    }
    query_params.push(("page_size", page_size.unwrap_or(30).to_string()));
    let client = http_client();

    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Query params: {:?}", query_params));

    let response = match client.get(&url).query(&query_params).send() {
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

/// Endpoint and query for a code quality listing. The backend serves code
/// quality from paths parallel to — but not named like — the security routes:
/// `/scan/{id}/issues/quality` for a scan, `/issues/code-quality` otherwise.
fn quality_issues_request(
    url: &str,
    project: &str,
    page: Option<u16>,
    page_size: Option<u16>,
    scan_id: Option<&str>,
) -> (String, Vec<(&'static str, String)>) {
    // Project names can contain `&`/`?`/`#`, so use `query`, not `format!`.
    let (endpoint, mut query_params) = match scan_id {
        Some(scan_id) => (
            format!("{}{}/scan/{}/issues/quality", url, API_BASE, scan_id),
            vec![],
        ),
        None => (
            format!("{}{}/issues/code-quality", url, API_BASE),
            vec![("project", project.to_string())],
        ),
    };
    if let Some(p) = page {
        query_params.push(("page", p.to_string()));
    }
    query_params.push(("page_size", page_size.unwrap_or(30).to_string()));
    (endpoint, query_params)
}

pub fn get_quality_issues(
    url: &str,
    project: &str,
    page: Option<u16>,
    page_size: Option<u16>,
    scan_id: Option<String>,
) -> Result<ProjectIssuesResponse, Box<dyn std::error::Error>> {
    let (endpoint, query_params) =
        quality_issues_request(url, project, page, page_size, scan_id.as_deref());
    let client = http_client();

    debug(&format!("Sending request to URL: {}", endpoint));
    debug(&format!("Query params: {:?}", query_params));

    let response = match client.get(&endpoint).query(&query_params).send() {
        Ok(res) => {
            check_for_warnings(res.headers(), res.status());
            res
        }
        Err(e) => return Err(format!("Failed to send request: {}", e).into()),
    };
    // Unlike the security routes, these endpoints answer a missing scan with a
    // bare HTTP 404 rather than a `no_project_found` body, so the status has to
    // be read before the parse or the miss surfaces as a parse failure.
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        debug(&format!(
            "Code quality request failed: HTTP {}. Response body: {}",
            status, body
        ));
        if status == StatusCode::NOT_FOUND {
            return Err("Code quality issues not found 404".into());
        }
        return Err(format!("Request failed with status: {}", status).into());
    }
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

#[derive(Deserialize, Debug)]
pub struct ProjectSummary {
    pub name: String,
    #[serde(default)]
    pub repo_url: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ProjectsResponse {
    /// Deliberately no `#[serde(default)]`: a 200 missing this key must fail
    /// the parse, not read as "no matches" and take the legacy-name fallback.
    pub projects: Vec<ProjectSummary>,
    #[serde(default)]
    pub total_pages: Option<u32>,
}

const PROJECTS_PAGE_SIZE: u16 = 50;

/// Ceiling on pages walked looking for an exact repo match, so a bogus
/// server-reported `total_pages` cannot drive an unbounded request loop.
const PROJECTS_MAX_PAGES: u32 = 20;

/// True when a stored `repo_url` points at exactly `expected_path` (a whole
/// post-host path, already lowercased). Comparing whole paths keeps the
/// backend's `repo_url__icontains` results honest: neither the sibling
/// `acme/api-v2` nor the nested `…/mirrors/acme/api` passes for `acme/api`.
/// Falls back to a normalized compare for a stored bare `acme/api`.
fn repo_url_matches_path(repo_url: &str, expected_path: &str) -> bool {
    if let Some(path) = utils::generic::extract_repo_path(repo_url) {
        return path == expected_path;
    }
    let r = repo_url.trim().trim_end_matches('/');
    let r = r.strip_suffix(".git").unwrap_or(r).to_lowercase();
    r == expected_path
}

/// True when a candidate is stored on exactly `expected_host`.
fn repo_url_on_host(repo_url: &str, expected_host: &str) -> bool {
    utils::generic::extract_repo_host(repo_url).as_deref() == Some(expected_host)
}

/// One page of GET /api/v1/projects?repo_url=…
///
/// `Ok(None)` only for a 404 (a backend without the endpoint). A 5xx or a body
/// that does not parse is an `Err`: both are hard failures, and treating them
/// as a clean miss would silently fall back to the CWD-name path.
fn fetch_projects_page(
    url: &str,
    repo_path: &str,
    page: u32,
) -> Result<Option<ProjectsResponse>, Box<dyn std::error::Error>> {
    let request_url = format!("{}{}/projects", url, API_BASE);
    let client = http_client();
    debug(&format!(
        "Resolving project via {} (repo_url={}, page={})",
        request_url, repo_path, page
    ));
    let (page, page_size) = (page.to_string(), PROJECTS_PAGE_SIZE.to_string());
    let response = client
        .get(&request_url)
        .query(&[
            ("repo_url", repo_path),
            ("page", &page),
            ("page_size", &page_size),
        ])
        .send()?;
    check_for_warnings(response.headers(), response.status());
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("/projects request failed: HTTP {}", status).into());
    }
    let text = response.text()?;
    match serde_json::from_str(&text) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(e) => {
            debug(&format!("/projects response body: {}", text));
            Err(format!("Failed to parse the /projects response: {}", e).into())
        }
    }
}

/// Resolve the canonical project for a repo path via GET /api/v1/projects?repo_url=…
///
/// The backend filters `repo_url__icontains` over a paginated list, so the
/// exact repo can sit behind a page of siblings (`acme/api-v2`, …) — pages are
/// walked until it turns up or they run out.
///
/// Old-backend safety guard: a pre-COR-1426 backend ignores the unknown
/// `repo_url` param and returns ALL company projects, so every candidate is
/// re-checked against the path here — on such a backend none match, and the
/// caller falls back to the CWD-name path.
///
/// The host is a tie-breaker, not a gate: it settles which of several
/// same-path candidates is ours (`github.com/acme/api` is not
/// `gitlab.com/acme/api`), but a lone path match is accepted whatever its
/// host — an SSH-config alias origin (`corp-github:acme/api`) never matches
/// the stored `github.com` and must still resolve. Several path matches with
/// none on our host — or several on it — is genuinely ambiguous and errors
/// rather than guessing.
///
/// `Err` for hard failures (network/auth/5xx/unparseable body/ambiguity); a
/// clean "no match" (or a 404 from a backend without the endpoint) is a soft
/// `Ok(None)`.
pub fn resolve_project_by_repo(
    url: &str,
    repo_path: &str,
    expected_host: Option<&str>,
) -> Result<Option<ProjectSummary>, Box<dyn std::error::Error>> {
    let expected = repo_path.to_lowercase();
    let mut host_matches: Vec<ProjectSummary> = Vec::new();
    let mut candidates: Vec<ProjectSummary> = Vec::new();
    let mut page = 1;
    loop {
        let Some(parsed) = fetch_projects_page(url, repo_path, page)? else {
            // Only page 1 can be a backend without the endpoint; a 404 once the
            // walk is under way (a concurrent delete shrinking the filtered set)
            // would discard the matches already found and read as a clean miss.
            if page == 1 {
                return Ok(None);
            }
            return Err(format!(
                "/projects page {} returned 404 after pagination started",
                page
            )
            .into());
        };
        let total_pages = parsed.total_pages.unwrap_or(1);
        if parsed.projects.is_empty() {
            break;
        }
        for project in parsed.projects {
            let Some(repo_url) = project.repo_url.as_deref() else {
                continue;
            };
            if !repo_url_matches_path(repo_url, &expected) {
                continue;
            }
            // A host match is preferred but not returned early: two projects
            // claiming the same host+path must reach the ambiguity check
            // below, not resolve to whichever the backend listed first.
            if expected_host.is_some_and(|h| repo_url_on_host(repo_url, h)) {
                host_matches.push(project);
            } else {
                candidates.push(project);
            }
        }
        if page >= total_pages {
            break;
        }
        // Every reported page was NOT searched, so this is not a clean miss:
        // saying so would send the caller to the legacy-name fallback, which
        // can list a different same-basename project and exit 0.
        if page >= PROJECTS_MAX_PAGES {
            return Err(format!(
                "/projects reported {} pages; refusing to guess after searching {}",
                total_pages, PROJECTS_MAX_PAGES
            )
            .into());
        }
        page += 1;
    }

    let mut matches = if host_matches.is_empty() {
        candidates
    } else {
        host_matches
    };
    if matches.len() > 1 {
        let urls: Vec<&str> = matches
            .iter()
            .filter_map(|p| p.repo_url.as_deref())
            .collect();
        return Err(format!(
            "{} Corgea projects claim repo '{}' ({}); pass --project-name <NAME> to choose one",
            matches.len(),
            repo_path,
            urls.join(", ")
        )
        .into());
    }
    Ok(matches.pop())
}

/// What `list`/`wait` need to drive the existing name-based queries.
#[derive(Debug)]
pub struct ResolvedProject {
    /// Sent as `?project=` to the listing endpoints.
    pub query_name: String,
    /// True only when /projects confirmed a backend project.
    pub confirmed: bool,
    /// Pre-formatted subject of the miss message ("repo 'org/repo'", …).
    pub tried_label: String,
}

/// How the caller asked for a project: `--project-name` and `--repo` are
/// mutually exclusive at the CLI, but both travel together to the resolver.
/// One struct so the two same-typed options cannot be transposed at a call
/// site.
#[derive(Default, Clone)]
pub struct ProjectSelector {
    pub name: Option<String>,
    pub repo: Option<String>,
}

impl ProjectSelector {
    /// True when the caller named a project or repo explicitly, rather than
    /// leaving it to auto-detection.
    pub fn is_set(&self) -> bool {
        self.name.is_some() || self.repo.is_some()
    }
}

/// Resolve which project `list`/`wait` should query: `--project-name` verbatim,
/// else the repo path from `--repo` or the discovered remote. Unconfirmed, an
/// explicit `--repo` queries that path as a name and everything else falls back
/// to what the pre-COR-1577 CLI queried. `Err` only for a hard resolver failure
/// (network/auth/5xx from /projects).
pub fn resolve_project(
    url: &str,
    selector: &ProjectSelector,
) -> Result<ResolvedProject, Box<dyn std::error::Error>> {
    let repo_override = selector.repo.as_deref();
    if let Some(name) = selector.name.as_deref() {
        // Normalize before it reaches `?project=`, which the backend matches
        // exactly: `--project-name foo/` must not miss the project `foo`.
        let name = name.trim().trim_matches('/');
        if name.is_empty() {
            return Err("--project-name must name a project".into());
        }
        return Ok(ResolvedProject {
            query_name: name.to_string(),
            confirmed: false,
            tried_label: format!("project '{}'", name),
        });
    }

    // --repo may be a bare path (`org/repo`, or a GitLab `group/subgroup/repo`)
    // rather than a URL; `extract_repo_path` returns None for those, so the
    // whole value is the path.
    let (repo_path, repo_host) = match repo_override {
        Some(r) => match utils::generic::extract_repo_path(r) {
            Some(path) => (Some(path), utils::generic::extract_repo_host(r)),
            None => (Some(r.trim().to_string()), None),
        },
        None => match utils::generic::discover_repo_url() {
            Some(u) => (
                utils::generic::extract_repo_path(&u),
                utils::generic::extract_repo_host(&u),
            ),
            None => (None, None),
        },
    };

    if let Some(repo_path) = repo_path {
        if let Some(project) = resolve_project_by_repo(url, &repo_path, repo_host.as_deref())? {
            return Ok(ResolvedProject {
                query_name: project.name,
                confirmed: true,
                tried_label: format!("repo '{}'", repo_path),
            });
        }
        // Unconfirmed: an explicit --repo queries that path as a name, and an
        // auto-detected remote queries exactly what the pre-COR-1577 CLI did,
        // so an old or not-yet-onboarded backend still resolves.
        let query_name = match repo_override {
            Some(_) => repo_path.clone(),
            None => utils::generic::determine_project_name(None),
        };
        return Ok(ResolvedProject {
            query_name,
            confirmed: false,
            tried_label: format!("repo '{}'", repo_path),
        });
    }

    let cwd =
        utils::generic::get_current_working_directory().unwrap_or_else(|| "unknown".to_string());
    Ok(ResolvedProject {
        tried_label: format!("directory '{}'", cwd),
        query_name: utils::generic::determine_project_name(None),
        confirmed: false,
    })
}

/// `resolve_project`, or a hard exit with the shared failure copy. Every
/// caller treats a resolver error as fatal.
pub fn resolve_project_or_exit(url: &str, selector: &ProjectSelector) -> ResolvedProject {
    match resolve_project(url, selector) {
        Ok(resolved) => resolved,
        Err(e) => {
            log::error!(
                "Unable to resolve the Corgea project. Please check your connection and ensure that:\n\
                - The server URL is reachable.\n\
                - Your authentication token is valid.\n\n\
                Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli\n\n\
                Error details: {}",
                e
            );
            std::process::exit(1);
        }
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

/// Evaluate a scan against blocking rules.
///
/// `block_on` is a comma-separated list of CI rule slugs. When omitted the
/// backend falls back to evaluating every active rule, which is the legacy
/// `--fail` behavior.
pub fn check_blocking_rules(
    url: &str,
    sast_scan_id: &str,
    page: Option<u32>,
    block_on: Option<&str>,
) -> Result<BlockingRuleResponse, Box<dyn Error>> {
    let url = format!(
        "{}{}/scan/{}/check_blocking_rules",
        url, API_BASE, sast_scan_id
    );
    let page = page.unwrap_or(1);
    let mut query_params = vec![("page", page.to_string())];
    if let Some(block_on) = block_on {
        query_params.push(("block_on", block_on.to_string()));
    }

    let client = http_client();
    debug(&format!("Sending request to URL: {}", url));
    debug(&format!("Query params: {:?}", query_params));

    let response = match client.get(&url).query(&query_params).send() {
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
        if status == reqwest::StatusCode::BAD_REQUEST {
            if let Ok(block_on_error) = serde_json::from_str::<BlockOnError>(&response_text) {
                return Err(block_on_error.describe().into());
            }
        }
        Err(format!("API request failed with status: {}", status).into())
    }
}

pub fn get_sca_issues(
    url: &str,
    page: Option<u16>,
    page_size: Option<u16>,
    scan_id: Option<String>,
    project: Option<&str>,
) -> Result<SCAIssuesResponse, Box<dyn std::error::Error>> {
    let client = http_client();
    let mut query_params = vec![];
    if let Some(page) = page {
        query_params.push(("page", page.to_string()));
    }
    if let Some(page_size) = page_size {
        query_params.push(("page_size", page_size.to_string()));
    }
    // Scopes the scan-less route to one project (doghouse `list_sca_issues`
    // reads `project`); the scan route already keys off the scan.
    if let Some(project) = project {
        query_params.push(("project", project.to_string()));
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
        // No project scope: every caller passes a scan id, which selects the
        // scan on its own.
        let response = match get_sca_issues(
            url,
            Some(current_page as u16),
            Some(30),
            scan_id.clone(),
            None,
        ) {
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

/// One scanner problem reported against a scan, already sanitized server-side.
///
/// Fields are optional so older servers still deserialize.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScanErrorSummary {
    #[serde(default)]
    pub scan_type: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl ScanErrorSummary {
    /// Whether this entry means the scan is missing results.
    ///
    /// `info` entries are notes. Everything else counts, including absent or
    /// unrecognized levels, which the server treats as `error`.
    pub fn is_problem(&self) -> bool {
        !self
            .level
            .as_deref()
            .is_some_and(|level| level.trim().eq_ignore_ascii_case("info"))
    }
}

/// Reads a missing field, an explicit `null`, and a list all as a list.
///
/// `#[serde(default)]` alone only covers the missing case, and the API sends
/// `"scan_errors": null` for scans with nothing to report.
fn scan_errors_or_empty<'de, D>(deserializer: D) -> Result<Vec<ScanErrorSummary>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<ScanErrorSummary>>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScanResponse {
    pub id: String,
    pub project: String,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub status: String,
    pub engine: String,
    pub created_at: String,
    #[serde(default)]
    pub git_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Why a scan ended without finishing. Only set for failed scans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_reason: Option<String>,
    /// Per-scanner problems, present on completed scans too, where they mean a
    /// scanner's results are missing. Skipped when empty, since the scan list
    /// never carries them.
    #[serde(
        default,
        deserialize_with = "scan_errors_or_empty",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub scan_errors: Vec<ScanErrorSummary>,
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

/// Doghouse `check_blocking_rules` readiness. Missing on older backends.
pub const BLOCKING_RULES_STATUS_COMPLETE: &str = "complete";
pub const BLOCKING_RULES_STATUS_PENDING: &str = "pending";

fn default_blocking_rules_status() -> String {
    BLOCKING_RULES_STATUS_COMPLETE.to_string()
}

#[derive(Deserialize, Debug, Clone)]
pub struct BlockingRuleResponse {
    pub block: bool,
    pub blocking_issues: Vec<BlockingIssue>,
    pub total_pages: u32,
    // Totals the server computes over the whole result set before paginating.
    // Optional so the CLI keeps working against backends predating the field.
    #[serde(default)]
    pub stats: Option<BlockingRuleStats>,
    /// License-deps readiness. Omitted on older backends: treated as complete.
    #[serde(default = "default_blocking_rules_status")]
    pub status: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct BlockingRuleStats {
    #[serde(default)]
    pub blocked_issues: u32,
}

impl BlockingRuleResponse {
    pub fn is_complete(&self) -> bool {
        self.status == BLOCKING_RULES_STATUS_COMPLETE
    }

    /// How many issues violated the evaluated rules, across every page.
    ///
    /// The server counts this before paginating, so one request is enough.
    /// `blocking_issues` only holds the requested page, so it is the fallback
    /// for backends that do not send `stats` and can under-report.
    pub fn blocked_count(&self) -> usize {
        self.stats
            .as_ref()
            .map(|stats| stats.blocked_issues as usize)
            .unwrap_or_else(|| self.blocking_issues.len())
    }
}

/// Retryable during blocking-rules wait: transport errors and HTTP 429/5xx.
/// Permanent 4xx (auth, not found, bad request) stay fail-fast.
pub fn is_retryable_blocking_rules_error_message(message: &str) -> bool {
    if let Some(rest) = message.strip_prefix("API request failed with status: ") {
        return rest
            .split_whitespace()
            .next()
            .and_then(|code| code.parse::<u16>().ok())
            .is_some_and(|code| code == 429 || (500..600).contains(&code));
    }
    message.starts_with("API request failed:")
}

#[derive(Deserialize, Debug, Clone)]
pub struct BlockingIssue {
    pub id: String,
    pub triggered_by_rules: Vec<String>,
    // Optional so the CLI keeps working against backends predating rule slugs.
    #[serde(default)]
    pub triggered_by_slugs: Option<Vec<String>>,
}

/// Structured 400 body returned when `--block-on` names unusable rules.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct BlockOnError {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub unknown_slugs: Vec<String>,
    #[serde(default)]
    pub inactive_slugs: Vec<String>,
    #[serde(default)]
    pub non_ci_slugs: Vec<String>,
}

impl BlockOnError {
    fn is_empty(&self) -> bool {
        self.unknown_slugs.is_empty()
            && self.inactive_slugs.is_empty()
            && self.non_ci_slugs.is_empty()
    }

    /// One line per failure category, naming the offending slugs.
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return self
                .message
                .clone()
                .unwrap_or_else(|| "Invalid --block-on value.".to_string());
        }
        let mut lines = Vec::new();
        if !self.unknown_slugs.is_empty() {
            lines.push(format!(
                "Unknown blocking rule(s): {}",
                self.unknown_slugs.join(", ")
            ));
        }
        if !self.non_ci_slugs.is_empty() {
            lines.push(format!(
                "Rule(s) not scoped to CI: {}. Change 'Applies To' to CI in the web app, or remove them from --block-on.",
                self.non_ci_slugs.join(", ")
            ));
        }
        if !self.inactive_slugs.is_empty() {
            lines.push(format!(
                "Inactive rule(s): {}. Activate them in the web app, or remove them from --block-on.",
                self.inactive_slugs.join(", ")
            ));
        }
        lines.join("\n")
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SCAIssue {
    pub id: String,
    pub created_at: String,
    pub description: Option<String>,
    pub details: Option<String>,
    pub severity: Option<String>,
    pub classification: Option<String>,
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
    fn blocking_rule_response_defaults_status_when_missing() {
        let legacy = r#"{"block":false,"blocking_issues":[],"total_pages":1}"#;
        let parsed: BlockingRuleResponse = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.status, BLOCKING_RULES_STATUS_COMPLETE);
        assert!(parsed.is_complete());

        let pending = r#"{"block":false,"blocking_issues":[],"total_pages":1,"status":"pending"}"#;
        let parsed: BlockingRuleResponse = serde_json::from_str(pending).unwrap();
        assert_eq!(parsed.status, BLOCKING_RULES_STATUS_PENDING);
        assert!(!parsed.is_complete());

        let complete = r#"{"block":true,"blocking_issues":[],"total_pages":1,"status":"complete"}"#;
        let parsed: BlockingRuleResponse = serde_json::from_str(complete).unwrap();
        assert!(parsed.is_complete());
        assert!(parsed.block);

        let unexpected =
            r#"{"block":false,"blocking_issues":[],"total_pages":1,"status":"processing"}"#;
        let parsed: BlockingRuleResponse = serde_json::from_str(unexpected).unwrap();
        assert!(!parsed.is_complete());
    }

    #[test]
    fn retryable_blocking_rules_errors_cover_transport_429_and_5xx() {
        assert!(is_retryable_blocking_rules_error_message(
            "API request failed: connection reset"
        ));
        assert!(is_retryable_blocking_rules_error_message(
            "API request failed with status: 429 Too Many Requests"
        ));
        assert!(is_retryable_blocking_rules_error_message(
            "API request failed with status: 503 Service Unavailable"
        ));
        assert!(!is_retryable_blocking_rules_error_message(
            "API request failed with status: 401 Unauthorized"
        ));
        assert!(!is_retryable_blocking_rules_error_message(
            "API request failed with status: 404 Not Found"
        ));
        assert!(!is_retryable_blocking_rules_error_message(
            "Failed to parse response: expected value"
        ));
    }

    #[test]
    fn scan_response_deserializes_git_sha_and_defaults_when_missing() {
        let with_sha = r#"{
            "id": "s1",
            "project": "p",
            "repo": null,
            "branch": "main",
            "status": "complete",
            "engine": "corgea-blast",
            "created_at": "2026-01-01T00:00:00Z",
            "git_sha": "abcdef0123456789"
        }"#;
        let parsed: ScanResponse = serde_json::from_str(with_sha).unwrap();
        assert_eq!(parsed.git_sha.as_deref(), Some("abcdef0123456789"));

        let without_sha = r#"{
            "id": "s1",
            "project": "p",
            "repo": null,
            "branch": "main",
            "status": "complete",
            "engine": "corgea-blast",
            "created_at": "2026-01-01T00:00:00Z"
        }"#;
        let parsed: ScanResponse = serde_json::from_str(without_sha).unwrap();
        assert_eq!(parsed.git_sha, None);
    }

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
    fn deserializes_code_quality_issue_response() {
        // Code quality issues carry a free-form classification label (no CWE) and
        // must deserialize into the same Issue struct used for security issues.
        let body = r#"{
            "status": "ok",
            "page": 1,
            "total_pages": 1,
            "total_issues": 1,
            "issues": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "urgency": "ME",
                    "created_at": "2026-01-01T00:00:00Z",
                    "status": "open",
                    "classification": {
                        "id": "Maintainability",
                        "name": "Maintainability",
                        "description": null
                    },
                    "location": {
                        "file": {"name": "app.py", "language": "python", "path": "app/app.py"},
                        "project": {"name": "proj", "branch": "main", "git_sha": "abc"},
                        "line_number": 20
                    },
                    "auto_triage": {"false_positive_detection": {"status": "valid"}},
                    "auto_fix_suggestion": {"status": "no_fix"}
                }
            ]
        }"#;

        let parsed: ProjectIssuesResponse =
            serde_json::from_str(body).expect("should parse code quality response");
        assert_eq!(parsed.status, "ok");
        let issues = parsed.issues.expect("issues present");
        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.classification.id, "Maintainability");
        assert_eq!(issue.classification.name, "Maintainability");
        assert!(issue.classification.description.is_none());
    }

    #[test]
    fn quality_issues_request_targets_the_documented_paths() {
        // The two code quality routes are named asymmetrically on the backend,
        // so the paths are pinned here rather than derived from each other.
        let (endpoint, query) =
            quality_issues_request("https://api.example.com", "proj", Some(2), Some(10), None);
        assert_eq!(
            endpoint,
            "https://api.example.com/api/v1/issues/code-quality"
        );
        assert_eq!(
            query,
            vec![
                ("project", "proj".to_string()),
                ("page", "2".to_string()),
                ("page_size", "10".to_string()),
            ]
        );

        let (endpoint, query) = quality_issues_request(
            "https://api.example.com",
            "proj",
            Some(1),
            None,
            Some("scan-123"),
        );
        assert_eq!(
            endpoint,
            "https://api.example.com/api/v1/scan/scan-123/issues/quality"
        );
        // A scan selects its own project, and the page size defaults to 30.
        assert_eq!(
            query,
            vec![("page", "1".to_string()), ("page_size", "30".to_string())]
        );
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

    // Single-response-per-connection JSON stub on an ephemeral port; returns
    // the base URL. Drains the request first: closing the socket with an
    // unread request still in the kernel buffer triggers a TCP RST that
    // surfaces on the client as hyper `UnexpectedMessage` (flaky).
    fn spawn_projects_stub(body: &'static str) -> String {
        spawn_projects_stub_status("200 OK", body)
    }

    fn spawn_projects_stub_status(status_line: &'static str, body: &'static str) -> String {
        use std::io::Write;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = corgea::vuln_api_stub::read_http_request(&mut stream);
                let resp = corgea::vuln_api_stub::http_response(status_line, "", body);
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        base
    }

    #[test]
    fn repo_url_matches_path_compares_the_whole_path() {
        // Same repo across scheme/.git/trailing-slash/port variants.
        for stored in [
            "https://github.com/acme/api",
            "https://github.com/acme/api.git",
            "git@github.com:acme/api",
            "acme/api",
        ] {
            assert!(repo_url_matches_path(stored, "acme/api"), "{stored}");
        }
        // Sibling / prefix repo, a different org, and — since the owner must be
        // top-level on the host — a nested mirror or a deeper path.
        for stored in [
            "https://github.com/acme/api-v2",
            "https://github.com/notacme/api",
            "https://github.com/mirrors/acme/api",
        ] {
            assert!(!repo_url_matches_path(stored, "acme/api"), "{stored}");
        }
        // Multi-segment paths compare in full.
        assert!(repo_url_matches_path(
            "https://dev.azure.com/org/project/_git/repo",
            "org/project/_git/repo"
        ));
        assert!(repo_url_matches_path(
            "git@gitlab.com:group/subgroup/repo.git",
            "group/subgroup/repo"
        ));
    }

    #[test]
    fn resolve_project_by_repo_keeps_only_repo_url_matches() {
        let base = spawn_projects_stub(
            r#"{"status":"ok","projects":[{"name":"bohappdev/dotnet-azure-web-tsb","repo_url":"https://github.com/bohappdev/dotnet-azure-web-tsb"}]}"#,
        );
        let got = resolve_project_by_repo(&base, "bohappdev/dotnet-azure-web-tsb", None).unwrap();
        assert_eq!(
            got.map(|p| p.name).as_deref(),
            Some("bohappdev/dotnet-azure-web-tsb")
        );
    }

    #[test]
    fn resolve_project_by_repo_guards_against_old_backend_returning_all() {
        // A pre-COR-1426 backend ignores ?repo_url and returns every project.
        // Without the path re-check we would confirm a stranger's project and
        // list its scans.
        let base = spawn_projects_stub(
            r#"{"status":"ok","projects":[{"name":"other/repo","repo_url":"https://github.com/other/repo"},{"name":"misc/thing","repo_url":"https://github.com/misc/thing"}]}"#,
        );
        assert!(
            resolve_project_by_repo(&base, "bohappdev/dotnet-azure-web-tsb", None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn resolve_project_by_repo_rejects_sibling_prefix_repo() {
        // `repo_url__icontains` returns the sibling `acme/api-v2` for `acme/api`.
        let base = spawn_projects_stub(
            r#"{"status":"ok","projects":[{"name":"acme/api-v2","repo_url":"https://github.com/acme/api-v2"}]}"#,
        );
        assert!(resolve_project_by_repo(&base, "acme/api", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_project_by_repo_empty_and_404_are_soft_none() {
        let base = spawn_projects_stub(r#"{"status":"ok","projects":[]}"#);
        assert!(resolve_project_by_repo(&base, "org/repo", None)
            .unwrap()
            .is_none());
        // /projects absent on a very old backend -> soft miss, not a failure.
        let base = spawn_projects_stub_status("404 Not Found", r#"{"message":"not found"}"#);
        assert!(resolve_project_by_repo(&base, "org/repo", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_project_by_repo_server_error_is_hard_err() {
        // 5xx must surface, not silently fall back to the local-dir project.
        let base = spawn_projects_stub_status("500 Internal Server Error", r#"{"error":"boom"}"#);
        assert!(resolve_project_by_repo(&base, "org/repo", None).is_err());
    }

    // Serves `page_one` until a request carries `page=2`, then `page_two`.
    fn spawn_paged_projects_stub(page_one: &'static str, page_two: &'static str) -> String {
        spawn_paged_projects_stub_status(page_one, "200 OK", page_two)
    }

    fn spawn_paged_projects_stub_status(
        page_one: &'static str,
        page_two_status: &'static str,
        page_two: &'static str,
    ) -> String {
        use std::io::Write;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let request = corgea::vuln_api_stub::read_http_request(&mut stream);
                let (status, body) = if String::from_utf8_lossy(&request).contains("page=2") {
                    (page_two_status, page_two)
                } else {
                    ("200 OK", page_one)
                };
                let resp = corgea::vuln_api_stub::http_response(status, "", body);
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        base
    }

    #[test]
    fn resolve_project_by_repo_walks_past_the_first_page() {
        // `repo_url__icontains` over a 20-per-page list: enough `acme/api-*`
        // siblings push the exact `acme/api` onto page 2, and stopping at page
        // 1 would recreate the very miss this resolves.
        let base = spawn_paged_projects_stub(
            r#"{"status":"ok","total_pages":2,"projects":[{"name":"acme/api-v2","repo_url":"https://github.com/acme/api-v2"}]}"#,
            r#"{"status":"ok","total_pages":2,"projects":[{"name":"acme/api","repo_url":"https://github.com/acme/api"}]}"#,
        );
        let got = resolve_project_by_repo(&base, "acme/api", None).unwrap();
        assert_eq!(got.map(|p| p.name).as_deref(), Some("acme/api"));
    }

    #[test]
    fn resolve_project_by_repo_mid_pagination_404_is_hard_err() {
        // Django 404s a page that a concurrent delete shrank out of existence.
        // Page 1 already held the exact match, so a soft miss here would throw
        // it away and send the caller to the legacy-name fallback.
        let base = spawn_paged_projects_stub_status(
            r#"{"status":"ok","total_pages":2,"projects":[{"name":"acme/api","repo_url":"https://github.com/acme/api"}]}"#,
            "404 Not Found",
            r#"{"message":"Invalid page."}"#,
        );
        let err = resolve_project_by_repo(&base, "acme/api", None).unwrap_err();
        assert!(err.to_string().contains("page 2"), "{err}");
        assert!(err.to_string().contains("pagination"), "{err}");
    }

    #[test]
    fn resolve_project_by_repo_truncated_search_is_hard_err() {
        // The ceiling stops the walk before every reported page was searched,
        // so "no match" would be a guess — and the caller acts on it by
        // querying the legacy name, which can list a different project.
        let base = spawn_projects_stub(
            r#"{"status":"ok","total_pages":999,"projects":[{"name":"acme/api-v2","repo_url":"https://github.com/acme/api-v2"}]}"#,
        );
        let err = resolve_project_by_repo(&base, "acme/api", None).unwrap_err();
        assert!(err.to_string().contains("999 pages"), "{err}");
    }

    #[test]
    fn resolve_project_by_repo_bad_envelope_is_hard_err() {
        // `@paginated` always emits `projects`, empty array included, so a 200
        // without it — or one that is not JSON at all — is an error envelope or
        // a foreign responder, not a clean miss.
        for body in [
            r#"{"status":"error","message":"boom"}"#,
            "<html><body>Access denied</body></html>",
        ] {
            let base = spawn_projects_stub(body);
            assert!(
                resolve_project_by_repo(&base, "org/repo", None).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn resolve_project_by_repo_picks_the_candidate_on_the_origin_host() {
        // `?repo_url=acme/api` is hostless, so `icontains` returns both forges;
        // the origin host is what says which one is ours.
        let base = spawn_projects_stub(
            r#"{"status":"ok","projects":[{"name":"gl","repo_url":"https://gitlab.com/acme/api"},{"name":"gh","repo_url":"https://github.com/acme/api"}]}"#,
        );
        let got = resolve_project_by_repo(&base, "acme/api", Some("github.com")).unwrap();
        assert_eq!(got.map(|p| p.name).as_deref(), Some("gh"));
        let got = resolve_project_by_repo(&base, "acme/api", Some("gitlab.com")).unwrap();
        assert_eq!(got.map(|p| p.name).as_deref(), Some("gl"));
    }

    #[test]
    fn resolve_project_by_repo_accepts_a_lone_match_from_an_unknown_host() {
        // An SSH-config alias origin (`corp-github:acme/api`) never equals the
        // stored `github.com`, but there is nothing to disambiguate — holding
        // out for a host match would leave COR-1577 unfixed for exactly the
        // alias remotes this repo itself uses.
        let base = spawn_projects_stub(
            r#"{"status":"ok","projects":[{"name":"acme/api","repo_url":"https://github.com/acme/api"}]}"#,
        );
        let got = resolve_project_by_repo(&base, "acme/api", Some("corp-github")).unwrap();
        assert_eq!(got.map(|p| p.name).as_deref(), Some("acme/api"));
    }

    #[test]
    fn resolve_project_by_repo_errors_when_the_path_is_claimed_twice() {
        // Two forges, neither ours: picking either would be a coin flip, and
        // reporting no match would quietly list a third project's scans.
        let base = spawn_projects_stub(
            r#"{"status":"ok","projects":[{"name":"gl","repo_url":"https://gitlab.com/acme/api"},{"name":"gh","repo_url":"https://github.com/acme/api"}]}"#,
        );
        let err = resolve_project_by_repo(&base, "acme/api", Some("corp-github")).unwrap_err();
        assert!(err.to_string().contains("--project-name"), "{err}");
    }

    #[test]
    fn resolve_project_by_repo_errors_when_two_projects_share_our_host_and_path() {
        // A host match must not short-circuit the ambiguity check: two
        // projects on the same host+path would resolve to whichever the
        // backend listed first.
        let base = spawn_projects_stub(
            r#"{"status":"ok","projects":[{"name":"first","repo_url":"https://github.com/acme/api"},{"name":"second","repo_url":"https://github.com/acme/api"}]}"#,
        );
        let err = resolve_project_by_repo(&base, "acme/api", Some("github.com")).unwrap_err();
        assert!(err.to_string().contains("--project-name"), "{err}");
    }

    #[test]
    fn resolve_project_name_override_is_normalized_and_never_empty() {
        // The name goes straight into `?project=`, which the backend matches
        // exactly, so a trailing slash would miss the project.
        let r = resolve_project(
            "http://127.0.0.1:1",
            &ProjectSelector {
                name: Some("foo/".into()),
                repo: None,
            },
        )
        .unwrap();
        assert_eq!(r.query_name, "foo");
        assert!(!r.confirmed);
        assert!(resolve_project(
            "http://127.0.0.1:1",
            &ProjectSelector {
                name: Some("/".into()),
                repo: None
            }
        )
        .is_err());
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
