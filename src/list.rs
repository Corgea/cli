use crate::config::Config;
use crate::log::debug;
use crate::utils;
use crate::utils::api::ProjectSelector;
use serde_json::json;
use std::path::Path;

#[derive(Default)]
pub struct ListArgs {
    pub issues: bool,
    pub sca_issues: bool,
    pub json: bool,
    pub page: Option<u16>,
    pub page_size: Option<u16>,
    pub scan_id: Option<String>,
    pub selector: ProjectSelector,
}

pub fn run(config: &Config, args: ListArgs) {
    let ListArgs {
        issues,
        sca_issues,
        json,
        page,
        page_size,
        scan_id,
        selector,
    } = args;
    if !json {
        println!();
    }
    if sca_issues {
        // Only an explicit --project-name/--repo scopes the SCA listing: the
        // endpoint takes `project`, but unflagged `--sca-issues` has always
        // returned the company-wide latest scan and narrowing that silently is
        // not this change's to make. Without a selector the CWD basename stays
        // what it was — error copy only.
        let resolved = (scan_id.is_none() && selector.is_set())
            .then(|| utils::api::resolve_project_or_exit(&config.get_url(), &selector));
        let project_name = resolved
            .as_ref()
            .map(|r| r.query_name.clone())
            .unwrap_or_else(|| {
                utils::generic::get_current_working_directory().unwrap_or("unknown".to_string())
            });
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
        return;
    }

    if issues {
        // The --scan-id issue route hits /scan/{id}/issues and ignores the
        // project, so it needs no resolution.
        let resolved = scan_id
            .is_none()
            .then(|| utils::api::resolve_project_or_exit(&config.get_url(), &selector));
        let project_name = resolved
            .as_ref()
            .map(|r| r.query_name.clone())
            .unwrap_or_default();
        let issues_response = match utils::api::get_scan_issues(
            &config.get_url(),
            &project_name,
            Some(page.unwrap_or(1)),
            page_size,
            scan_id.clone(),
        ) {
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
                        "Unable to fetch scan issues. Please check your connection and ensure that:\n\
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

        if let Some(id) = &scan_id {
            let mut page: u32 = 1;
            loop {
                match utils::api::check_blocking_rules(&config.get_url(), id, Some(page)) {
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
        let (scans, page, total_pages) = match utils::api::query_scan_list(
            &config.get_url(),
            Some(project_name),
            page,
            page_size,
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
        if json {
            let output = json!({
                "page": page,
                "total_pages": total_pages,
                "results": scans
            });
            // The envelope prints first so JSON consumers get valid stdout
            // even when the miss below exits 1.
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        // An unresolved project is a miss (exit 1, as --issues and `wait`); a
        // confirmed project with no scans is a valid empty result. So is an
        // explicit --project-name: /scans answers 200-empty either way, so the
        // caller's own exact name is the better authority than a guess that it
        // does not exist.
        if scans.is_empty() && !resolved.confirmed && selector.name.is_none() {
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
            println!(
                "Project '{}' has no scans yet. Run 'corgea scan' to create one.",
                project_name
            );
            return;
        }
        let mut table = vec![vec![
            "Scan ID".to_string(),
            "Project".to_string(),
            "Status".to_string(),
            "Repo".to_string(),
            "Branch".to_string(),
            "SHA".to_string(),
        ]];

        for scan in &scans {
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

            table.push(vec![
                scan.id.clone(),
                scan.project.clone(),
                scan.status.clone(),
                formatted_repo,
                scan.branch.clone().unwrap_or("N/A".to_string()),
                format_short_sha(scan.git_sha.as_deref()),
            ]);
        }

        utils::terminal::print_table(table, page, total_pages);
    }
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
