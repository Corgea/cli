use crate::config::Config;
use crate::log::debug;
use crate::scanners::blast::{classify_scan_status, triggered_slugs, ScanState};
use crate::utils;
use crate::utils::api::{ProjectSelector, ScanResponse};
use serde_json::{json, Value};
use std::path::Path;

/// `blocking_verdict.status` values. Only `complete` is a final answer:
/// `pending` means the server is still resolving the scan's dependencies and
/// `unavailable` means no verdict was produced at all, so a pipeline gating on
/// either must retry or fail closed rather than read `block`.
const VERDICT_STATUS_COMPLETE: &str = "complete";
const VERDICT_STATUS_PENDING: &str = "pending";
const VERDICT_STATUS_UNAVAILABLE: &str = "unavailable";

/// How many scans on a page `--block-on` evaluates.
///
/// A verdict costs one request per scan, and the endpoint re-evaluates every
/// finding in that scan, so the pass is bounded and the default page shrinks to
/// what it can evaluate. `--sha` narrows a duplicate-scan lookup to one scan.
const BLOCKING_VERDICT_MAX_SCANS: usize = 10;

#[derive(Default)]
pub struct ListArgs {
    pub issues: bool,
    pub sca_issues: bool,
    pub code_quality: bool,
    pub json: bool,
    pub page: Option<u16>,
    pub page_size: Option<u16>,
    pub scan_id: Option<String>,
    pub selector: ProjectSelector,
    /// Normalized `--block-on` slugs: attach each listed scan's verdict against
    /// these CI blocking rules.
    pub block_on: Option<String>,
    /// Normalized `--sha`: list only the scans of one commit.
    pub sha: Option<String>,
}

pub fn run(config: &Config, args: ListArgs) {
    let ListArgs {
        issues,
        sca_issues,
        code_quality,
        json,
        page,
        page_size,
        scan_id,
        selector,
        block_on,
        sha,
    } = args;
    println!();
    if sca_issues {
        // Only an explicit --project-name/--repo scopes the SCA listing: the
        // endpoint takes `project`, but unflagged `--sca-issues` has always
        // returned the company-wide latest scan and narrowing that silently is
        // not this change's to make. Without a selector the name below stays
        // what it was — error copy only.
        let resolved = (scan_id.is_none() && selector.is_set())
            .then(|| utils::api::resolve_project_or_exit(&config.get_url(), &selector));
        let project_name = resolved
            .as_ref()
            .map(|r| r.query_name.clone())
            .unwrap_or_else(|| utils::generic::determine_project_name(None));
        let sca_issues_response = match utils::api::get_sca_issues(
            &config.get_url(),
            Some(page.unwrap_or(1)),
            page_size,
            scan_id.clone(),
            resolved.as_ref().map(|r| r.query_name.as_str()),
        ) {
            Ok(response) => response,
            Err(e) => {
                debug(&format!("Error Sending Request: {}", e));
                if e.to_string().contains("404") {
                    if let Some(id) = &scan_id {
                        log::error!("Scan with ID '{}' doesn't exist or has no SCA issues. Please run 'corgea scan' to create a new scan for this project.", id);
                    } else {
                        log::error!("No SCA issues found for project '{}'. Please run 'corgea scan' to create a new scan for this project.", project_name);
                    }
                } else {
                    log::error!(
                        "Unable to fetch SCA issues. Please check your connection and ensure that:\n\
                        - The server URL is reachable.\n\
                        - Your authentication token is valid.\n\n\
                        Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli {}",
                        e
                    );
                }
                std::process::exit(1);
            }
        };

        if json {
            let output = serde_json::json!({
                "page": sca_issues_response.page,
                "total_pages": sca_issues_response.total_pages,
                "total_issues": sca_issues_response.total_issues,
                "results": &sca_issues_response.issues
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
            return;
        }

        let mut table = vec![vec![
            "Issue ID".to_string(),
            "Package".to_string(),
            "Version".to_string(),
            "Fix Version".to_string(),
            "Severity".to_string(),
            "Classification".to_string(),
            "CVE".to_string(),
            "Ecosystem".to_string(),
            "File Path".to_string(),
        ]];

        for issue in &sca_issues_response.issues {
            let path = Path::new(&issue.location.path);
            let path_parts: Vec<&str> = path
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect();

            let shortened_path = if path_parts.len() > 2 {
                let base_part = if path_parts[0].len() > 1 {
                    path_parts[0]
                } else {
                    path_parts[1]
                };
                format!("{}/../{}", base_part, path_parts[path_parts.len() - 1]).to_string()
            } else {
                issue.location.path.clone()
            };

            table.push(vec![
                issue.id.clone(),
                issue.package.name.clone(),
                issue.package.version.clone(),
                issue
                    .package
                    .fix_version
                    .clone()
                    .unwrap_or("N/A".to_string()),
                issue.severity.clone().unwrap_or("N/A".to_string()),
                issue.classification.clone().unwrap_or("N/A".to_string()),
                issue.cve.clone().unwrap_or("N/A".to_string()),
                issue.package.ecosystem.clone(),
                shortened_path,
            ]);
        }

        utils::terminal::print_table(
            table,
            Some(sca_issues_response.page),
            Some(sca_issues_response.total_pages),
        );
    } else if issues || code_quality {
        // The --scan-id route hits /scan/{id}/issues[/quality] and ignores the
        // project.
        let resolved = scan_id
            .is_none()
            .then(|| utils::api::resolve_project_or_exit(&config.get_url(), &selector));
        let project_name = resolved
            .as_ref()
            .map(|r| r.query_name.clone())
            .unwrap_or_default();
        let issue_kind = if code_quality {
            "code quality issues"
        } else {
            "scan issues"
        };
        let fetch_result = if code_quality {
            utils::api::get_quality_issues(
                &config.get_url(),
                &project_name,
                Some(page.unwrap_or(1)),
                page_size,
                scan_id.clone(),
            )
        } else {
            utils::api::get_scan_issues(
                &config.get_url(),
                &project_name,
                Some(page.unwrap_or(1)),
                page_size,
                scan_id.clone(),
            )
        };
        let issues_response = match fetch_result {
            Ok(response) => response,
            Err(e) => {
                debug(&format!("Error Sending Request: {}", e));
                if e.to_string().contains("404") {
                    // `resolved` is None exactly on the --scan-id route.
                    match &resolved {
                        None => log::error!("Scan with ID '{}' doesn't exist. Please run 'corgea scan' to create a new scan for this project.", scan_id.as_ref().unwrap()),
                        Some(r) if r.confirmed => log::error!("Project '{}' has no issues yet. Run 'corgea scan' to create a scan for this project.", project_name),
                        Some(r) => log::error!(
                            "No Corgea project found for {}. Run 'corgea scan' to create one, or pass --project-name <NAME>.",
                            r.tried_label
                        ),
                    }
                } else {
                    log::error!(
                        "Unable to fetch {issue_kind}. Please check your connection and ensure that:\n\
                        - The server URL is reachable.\n\
                        - Your authentication token is valid.\n\n\
                        Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli {}",
                        e
                    );
                }
                std::process::exit(1);
            }
        };
        let mut render_blocking_rules = false;
        let mut blocking_rules: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        // Blocking rules are a security-listing concern. Skip the enrichment for
        // code quality so a blocking-rules API failure can't take down the CQ
        // listing and so Blocking columns aren't driven by non-CQ findings.
        if let Some(id) = scan_id.as_ref().filter(|_| !code_quality) {
            let mut page: u32 = 1;
            loop {
                match utils::api::check_blocking_rules(&config.get_url(), id, Some(page), None) {
                    Ok(rules) => {
                        if rules.block {
                            render_blocking_rules = true;
                            for issue in rules.blocking_issues {
                                blocking_rules.insert(issue.id, issue.triggered_by_rules.join(","));
                            }
                            if rules.total_pages == page {
                                break;
                            }
                            page += 1;
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to check blocking rules: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }

        if json {
            let mut json = serde_json::json!({
                "page": issues_response.page,
                "total_pages": issues_response.total_pages,
                "results": &issues_response.issues
            });
            if render_blocking_rules {
                json["results"] = serde_json::json!(issues_response
                    .issues
                    .unwrap_or_default()
                    .iter()
                    .map(|issue| {
                        serde_json::json!(utils::api::IssueWithBlockingRules {
                            id: issue.id.clone(),
                            scan_id: issue.scan_id.clone(),
                            status: issue.status.clone(),
                            urgency: issue.urgency.clone(),
                            created_at: issue.created_at.clone(),
                            classification: issue.classification.clone(),
                            location: issue.location.clone(),
                            details: issue.details.clone(),
                            auto_triage: issue.auto_triage.clone(),
                            auto_fix_suggestion: issue.auto_fix_suggestion.clone(),
                            blocked: blocking_rules.contains_key(&issue.id),
                            blocking_rules: if blocking_rules.contains_key(&issue.id) {
                                Some(vec![blocking_rules.get(&issue.id).unwrap().clone()])
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Vec<_>>());
            }
            let output = json!(json);
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
            return;
        }
        let mut table_header = vec![
            "Issue ID".to_string(),
            "Category".to_string(),
            "Urgency".to_string(),
            "File Path".to_string(),
            "Line".to_string(),
        ];
        if render_blocking_rules {
            table_header.push("Blocking".to_string());
            table_header.push("Rule ID".to_string());
        }
        let mut table = vec![table_header];

        for issue in &issues_response.issues.unwrap_or_default() {
            let classification_display = issue.classification.id.clone();
            let path = Path::new(&issue.location.file.path);
            let path_parts: Vec<&str> = path
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect();

            let shortened_path = if path_parts.len() > 2 {
                let base_part = if path_parts[0].len() > 1 {
                    path_parts[0]
                } else {
                    path_parts[1]
                };
                format!("{}/../{}", base_part, path_parts[path_parts.len() - 1]).to_string()
            } else {
                issue.location.file.path.clone()
            };
            let mut row = vec![
                issue.id.clone(),
                classification_display,
                issue.urgency.clone(),
                shortened_path,
                issue.location.line_number.to_string(),
            ];
            if render_blocking_rules {
                row.push(blocking_rules.contains_key(&issue.id).to_string());
                row.push(
                    blocking_rules
                        .get(&issue.id)
                        .unwrap_or(&"".to_string())
                        .to_string(),
                );
            }
            table.push(row);
        }

        utils::terminal::print_table(table, issues_response.page, issues_response.total_pages);
    } else {
        let resolved = utils::api::resolve_project_or_exit(&config.get_url(), &selector);
        let project_name = &resolved.query_name;
        // A verdict pass is the expensive part of the listing, so with
        // --block-on the default page is the number of scans it will evaluate.
        let page_size =
            page_size.or_else(|| block_on.as_ref().map(|_| BLOCKING_VERDICT_MAX_SCANS as u16));
        let (scans, page, total_pages) = match utils::api::query_scan_list(
            &config.get_url(),
            Some(project_name),
            page,
            page_size,
            sha.as_deref(),
        ) {
            Ok(scans) => {
                let page = scans.page;
                let total_pages = scans.total_pages;
                // The server already filtered by the resolved project; the old
                // client-side `scan.project == cwd_basename` pass would discard
                // every repo-resolved scan. (COR-1577)
                (scans.scans.unwrap_or_default(), page, total_pages)
            }
            Err(e) => {
                if e.to_string().contains("404") {
                    log::error!(
                        "No Corgea project found for {}. Run 'corgea scan' to create one, or pass --project-name <NAME>.",
                        resolved.tried_label
                    );
                } else {
                    log::error!(
                        "Unable to fetch scans. Please check your connection and ensure that:\n\
                        - The server URL is reachable.\n\
                        - Your authentication token is valid.\n\n\
                        Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli"
                    );
                }
                std::process::exit(1);
            }
        };
        let scans = match sha.as_deref() {
            Some(sha) => retain_scans_at_sha(scans, sha),
            None => scans,
        };
        let verdicts = block_on
            .as_deref()
            .map(|block_on| blocking_verdicts(config, &scans, block_on));
        if json {
            let output = json!({
                "page": page,
                "total_pages": total_pages,
                "results": scan_results_json(&scans, verdicts.as_deref())
            });
            // The envelope prints first so JSON consumers get valid stdout even
            // when the miss below exits 1.
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        // An unresolved project is a miss (exit 1, as --issues and `wait`); a
        // confirmed project with no scans is a valid empty result. So is an
        // explicit --project-name: /scans answers 200-empty either way, so the
        // caller's own exact name is the better authority. So is --sha, whose
        // empty page means "this commit has not been scanned" — the answer a
        // duplicate-skip path acts on by scanning.
        if scans.is_empty() && !resolved.confirmed && selector.name.is_none() && sha.is_none() {
            log::error!(
                "No Corgea project found for {}. Run 'corgea scan' to create one, or pass --project-name <NAME>.",
                resolved.tried_label
            );
            std::process::exit(1);
        }
        if json {
            return;
        }
        if scans.is_empty() {
            match sha.as_deref() {
                Some(sha) => println!("No scan of commit {} in project '{}'.", sha, project_name),
                None => println!(
                    "Project '{}' has no scans yet. Run 'corgea scan' to create one.",
                    project_name
                ),
            }
            return;
        }
        let mut header = vec![
            "Scan ID".to_string(),
            "Project".to_string(),
            "Status".to_string(),
            "Repo".to_string(),
            "Branch".to_string(),
            "SHA".to_string(),
        ];
        if verdicts.is_some() {
            header.push("Blocking".to_string());
        }
        let mut table = vec![header];

        for (index, scan) in scans.iter().enumerate() {
            let formatted_repo = scan.repo.clone().unwrap_or("N/A".to_string());
            let formatted_repo = if formatted_repo != "N/A" {
                if let Some(repo_name) = formatted_repo.split('/').next_back() {
                    let owner = formatted_repo.split('/').nth(3).unwrap_or("unknown");
                    let repo_name = repo_name.strip_suffix(".git").unwrap_or(repo_name);
                    format!("{}/{}", owner, repo_name)
                } else {
                    formatted_repo
                }
            } else {
                formatted_repo
            };
            let mut row = vec![
                scan.id.clone(),
                scan.project.clone(),
                scan.status.clone(),
                formatted_repo,
                scan.branch.clone().unwrap_or("N/A".to_string()),
                format_short_sha(scan.git_sha.as_deref()),
            ];
            if let Some(verdicts) = &verdicts {
                row.push(verdict_cell(verdicts.get(index)));
            }
            table.push(row);
        }

        utils::terminal::print_table(table, page, total_pages);
    }
}

/// The listed scans as JSON, each carrying its `blocking_verdict` when
/// `--block-on` asked for one.
fn scan_results_json(scans: &[ScanResponse], verdicts: Option<&[Value]>) -> Vec<Value> {
    scans
        .iter()
        .enumerate()
        .map(|(index, scan)| {
            let mut value = serde_json::to_value(scan).expect("serialize scan");
            if let (Some(verdict), Value::Object(object)) = (
                verdicts.and_then(|verdicts| verdicts.get(index)),
                &mut value,
            ) {
                object.insert("blocking_verdict".to_string(), verdict.clone());
            }
            value
        })
        .collect()
}

/// Drop the scans that are not at `sha`.
///
/// The server-side `sha` filter does the narrowing; this re-check is what keeps
/// a backend that ignores the parameter from answering with another commit's
/// scans, whose verdict would then be read as this commit's.
fn retain_scans_at_sha(scans: Vec<ScanResponse>, sha: &str) -> Vec<ScanResponse> {
    let listed = scans.len();
    let matching: Vec<ScanResponse> = scans
        .into_iter()
        .filter(|scan| {
            scan.git_sha
                .as_deref()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case(sha))
        })
        .collect();
    if matching.len() != listed {
        log::warn!(
            "Ignored {} scan(s) not at commit {}. This Corgea instance may not filter scans by commit, so scans of {} may be on a later page.",
            listed - matching.len(),
            sha,
            sha
        );
    }
    matching
}

/// Each scan's verdict against the `--block-on` rules, positionally aligned
/// with `scans`.
///
/// One request per scan, without the wait `corgea scan --block-on` does: a
/// listing reports a `pending` verdict for the caller to retry rather than
/// blocking on it.
fn blocking_verdicts(config: &Config, scans: &[ScanResponse], block_on: &str) -> Vec<Value> {
    if scans.len() > BLOCKING_VERDICT_MAX_SCANS {
        log::warn!(
            "Only the first {} scans of this page are evaluated against --block-on. Narrow the listing with --sha or --page-size.",
            BLOCKING_VERDICT_MAX_SCANS
        );
    }
    scans
        .iter()
        .enumerate()
        .map(|(index, scan)| {
            if index >= BLOCKING_VERDICT_MAX_SCANS {
                return unavailable_verdict(
                    block_on,
                    &format!(
                        "only the first {BLOCKING_VERDICT_MAX_SCANS} scans of a page are evaluated; narrow the listing with --sha or --page-size"
                    ),
                );
            }
            // Blocking rules are evaluated against the findings recorded so
            // far, so a verdict for a scan that has not finished would read as
            // a pass on findings that are still coming.
            match classify_scan_status(&scan.status) {
                ScanState::Completed => {}
                ScanState::Failed => {
                    return unavailable_verdict(
                        block_on,
                        &format!("scan did not complete (status '{}')", scan.status),
                    )
                }
                ScanState::Running => {
                    return unavailable_verdict(
                        block_on,
                        &format!("scan has not completed yet (status '{}')", scan.status),
                    )
                }
            }
            match utils::api::check_blocking_rules(
                &config.get_url(),
                &scan.id,
                None,
                Some(block_on),
            ) {
                Ok(response) => verdict_from_response(block_on, &response),
                // Fail loud: a verdict a pipeline gates on must not degrade
                // into a missing field that reads as "not blocked".
                Err(e) => {
                    log::error!(
                        "Failed to check blocking rules for scan {}: {}",
                        scan.id,
                        e
                    );
                    std::process::exit(1);
                }
            }
        })
        .collect()
}

/// One scan's verdict as reported by `check_blocking_rules`.
fn verdict_from_response(block_on: &str, response: &utils::api::BlockingRuleResponse) -> Value {
    json!({
        "block_on": slug_list(block_on),
        "status": if response.is_complete() {
            VERDICT_STATUS_COMPLETE
        } else {
            VERDICT_STATUS_PENDING
        },
        "block": response.block,
        "blocked_issues": response.blocked_count(),
        "triggered_rules": triggered_slugs(&response.blocking_issues),
    })
}

/// A verdict that could not be produced. `block` is null rather than false so
/// that a consumer reading it as a boolean cannot mistake it for a pass.
fn unavailable_verdict(block_on: &str, reason: &str) -> Value {
    json!({
        "block_on": slug_list(block_on),
        "status": VERDICT_STATUS_UNAVAILABLE,
        "block": Value::Null,
        "reason": reason,
    })
}

/// The rule slugs behind an already-normalized `--block-on` value.
fn slug_list(block_on: &str) -> Vec<&str> {
    block_on.split(',').collect()
}

/// The Blocking column for one scan.
fn verdict_cell(verdict: Option<&Value>) -> String {
    let Some(verdict) = verdict else {
        return "N/A".to_string();
    };
    match verdict["status"].as_str() {
        Some(VERDICT_STATUS_COMPLETE) => {
            if verdict["block"].as_bool() != Some(true) {
                return "pass".to_string();
            }
            let rules = verdict["triggered_rules"]
                .as_array()
                .map(|rules| {
                    rules
                        .iter()
                        .filter_map(|rule| rule.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            if rules.is_empty() {
                "BLOCKED".to_string()
            } else {
                format!("BLOCKED: {rules}")
            }
        }
        Some(VERDICT_STATUS_PENDING) => "pending".to_string(),
        _ => "N/A".to_string(),
    }
}

/// Canonicalize `--sha`.
///
/// The server matches a commit exactly, so a short SHA would answer "no scans"
/// instead of narrowing — a silent miss a duplicate-scan check would read as
/// "never scanned".
pub fn normalize_sha(raw: &str) -> Result<String, String> {
    let sha = raw.trim();
    if !(40..=64).contains(&sha.len()) || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "--sha expects a full commit SHA, as printed by `git rev-parse HEAD`, got '{sha}'."
        ));
    }
    Ok(sha.to_ascii_lowercase())
}

/// Format a git SHA for the list table. Missing/blank → "N/A"; otherwise first 8 chars.
fn format_short_sha(git_sha: Option<&str>) -> String {
    git_sha
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(8).collect::<String>())
        .unwrap_or_else(|| "N/A".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(id: &str, status: &str, git_sha: Option<&str>) -> ScanResponse {
        ScanResponse {
            id: id.to_string(),
            project: "proj".to_string(),
            repo: None,
            branch: None,
            status: status.to_string(),
            engine: "blast".to_string(),
            created_at: "2026-07-30T12:00:00Z".to_string(),
            git_sha: git_sha.map(str::to_string),
            metadata: None,
            failed_reason: None,
            scan_errors: Vec::new(),
        }
    }

    fn blocking_response(body: Value) -> utils::api::BlockingRuleResponse {
        serde_json::from_value(body).expect("blocking rules response")
    }

    #[test]
    fn normalize_sha_lowercases_a_full_sha() {
        assert_eq!(
            normalize_sha("  0123456789ABCDEF0123456789abcdef01234567 "),
            Ok("0123456789abcdef0123456789abcdef01234567".to_string())
        );
    }

    #[test]
    fn normalize_sha_rejects_a_prefix_or_a_non_sha() {
        // The server matches the commit exactly, so a prefix would answer "no
        // scans" — a miss a duplicate-scan check reads as "never scanned".
        for raw in [
            "",
            "0123456",
            "main",
            "0123456789abcdef0123456789abcdef0123456z",
        ] {
            assert!(normalize_sha(raw).is_err(), "{raw} should be rejected");
        }
    }

    #[test]
    fn verdict_from_response_reports_the_blocked_count_and_rules() {
        let verdict = verdict_from_response(
            "criticals,malicious-deps",
            &blocking_response(json!({
                "block": true,
                "blocking_issues": [{
                    "id": "issue-1",
                    "triggered_by_rules": ["7"],
                    "triggered_by_slugs": ["criticals"]
                }],
                "total_pages": 1,
                "stats": {"blocked_issues": 12},
                "status": "complete"
            })),
        );
        assert_eq!(verdict["status"], VERDICT_STATUS_COMPLETE);
        assert_eq!(verdict["block"], true);
        // The server's pre-pagination total, not the returned page length.
        assert_eq!(verdict["blocked_issues"], 12);
        assert_eq!(verdict["triggered_rules"], json!(["criticals"]));
        assert_eq!(verdict["block_on"], json!(["criticals", "malicious-deps"]));
    }

    #[test]
    fn verdict_from_response_marks_an_unfinished_evaluation_pending() {
        let verdict = verdict_from_response(
            "criticals",
            &blocking_response(json!({
                "block": false,
                "blocking_issues": [],
                "total_pages": 1,
                "status": "pending"
            })),
        );
        assert_eq!(verdict["status"], VERDICT_STATUS_PENDING);
    }

    #[test]
    fn unavailable_verdict_leaves_block_null() {
        // A consumer reading `block` as a boolean must not see a pass.
        let verdict = unavailable_verdict("criticals", "scan has not completed yet");
        assert_eq!(verdict["status"], VERDICT_STATUS_UNAVAILABLE);
        assert!(verdict["block"].is_null());
        assert_eq!(verdict["reason"], "scan has not completed yet");
    }

    #[test]
    fn verdict_cell_names_the_rules_that_blocked() {
        let blocked = json!({
            "status": VERDICT_STATUS_COMPLETE,
            "block": true,
            "triggered_rules": ["criticals", "malicious-deps"]
        });
        assert_eq!(
            verdict_cell(Some(&blocked)),
            "BLOCKED: criticals, malicious-deps"
        );
    }

    #[test]
    fn verdict_cell_renders_every_other_state() {
        let pass = json!({"status": VERDICT_STATUS_COMPLETE, "block": false});
        assert_eq!(verdict_cell(Some(&pass)), "pass");
        let pending = json!({"status": VERDICT_STATUS_PENDING, "block": false});
        assert_eq!(verdict_cell(Some(&pending)), "pending");
        let unavailable = json!({"status": VERDICT_STATUS_UNAVAILABLE, "block": null});
        assert_eq!(verdict_cell(Some(&unavailable)), "N/A");
        assert_eq!(verdict_cell(None), "N/A");
    }

    #[test]
    fn scan_results_json_attaches_the_verdict_only_when_asked() {
        let scans = vec![scan("scan-1", "complete", None)];
        let plain = scan_results_json(&scans, None);
        assert!(plain[0].get("blocking_verdict").is_none());

        let verdicts = vec![unavailable_verdict("criticals", "nope")];
        let annotated = scan_results_json(&scans, Some(&verdicts));
        assert_eq!(annotated[0]["id"], "scan-1");
        assert_eq!(
            annotated[0]["blocking_verdict"]["status"],
            VERDICT_STATUS_UNAVAILABLE
        );
    }

    #[test]
    fn retain_scans_at_sha_drops_other_commits() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let scans = vec![
            scan("scan-1", "complete", Some(&sha.to_ascii_uppercase())),
            scan("scan-2", "complete", Some("f00dcafe")),
            scan("scan-3", "complete", None),
        ];
        let kept = retain_scans_at_sha(scans, sha);
        assert_eq!(
            kept.iter().map(|scan| scan.id.as_str()).collect::<Vec<_>>(),
            vec!["scan-1"]
        );
    }

    #[test]
    fn format_short_sha_missing_or_blank_is_na() {
        assert_eq!(format_short_sha(None), "N/A");
        assert_eq!(format_short_sha(Some("")), "N/A");
        assert_eq!(format_short_sha(Some("   ")), "N/A");
    }

    #[test]
    fn format_short_sha_truncates_to_eight_chars() {
        assert_eq!(format_short_sha(Some("abcdef0123456789")), "abcdef01");
        assert_eq!(format_short_sha(Some("abc")), "abc");
    }
}
