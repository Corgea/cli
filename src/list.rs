use crate::utils;
use crate::config::Config;
use std::path::Path;
use serde_json::json;
use crate::log::debug;

pub fn run(config: &Config, issues: &bool, json: &bool, page: &Option<u16>, page_size: &Option<u16>, scan_id: &Option<String>) {
    let project_name = utils::generic::get_current_working_directory().unwrap_or("unknown".to_string());
    println!("");
    if *issues {
        let issues_response = match utils::api::get_scan_issues(&config.get_url(), &config.get_token(), &project_name, Some((*page).unwrap_or(1)), *page_size, scan_id.clone()) {
            Ok(response) => response,
            Err(e) => {
                debug(&format!("Error Sending Request: {}", e.to_string()));
                if e.to_string().contains("404") {
                    if scan_id.is_some() {
                        eprintln!("Scan with ID '{}' doesn't exist. Please run 'corgea scan' to create a new scan for this project.", scan_id.as_ref().unwrap());
                    } else {
                        eprintln!("Project with name '{}' doesn't exist. Please run 'corgea scan' to create a new scan for this project.", project_name);
                    }
                } else {
                    eprintln!(
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
        let mut blocking_rules: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        if scan_id.is_some() {
            let mut page: u32 = 1;
            loop {
                match utils::api::check_blocking_rules(&config.get_url(), &config.get_token(), scan_id.as_ref().unwrap(), Some(page)) {
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
                        eprintln!("Failed to check blocking rules: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }


        if *json {
            let mut json = serde_json::json!({
                "page": issues_response.page,
                "total_pages": issues_response.total_pages,
                "results": &issues_response.issues
            });
            if render_blocking_rules {
                json["results"] = serde_json::json!(
                    issues_response.issues.unwrap_or_default().iter().map(|issue| {
                        serde_json::json!(
                            utils::api::IssueWithBlockingRules {
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
                            }
                        )
                    }).collect::<Vec<_>>()
                );
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
        let mut table = vec![
            table_header
        ];

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
                row.push(blocking_rules.get(&issue.id).is_some().to_string());
                row.push(blocking_rules.get(&issue.id).unwrap_or(&"".to_string()).to_string());
            }
            table.push(row);
        }

        utils::terminal::print_table(table, issues_response.page, issues_response.total_pages);
    } else {
        let (scans, page, total_pages) = match utils::api::query_scan_list(&config.get_url(), &config.get_token(), Some(&project_name), *page, *page_size) {
            Ok(scans) => {
                let page = scans.page;
                let total_pages = scans.total_pages;
                let filtered_scans: Vec<utils::api::ScanResponse> = scans.scans.unwrap_or_default().into_iter()
                    .filter(|scan| scan.project == project_name)
                    .collect();
                (filtered_scans, page, total_pages)
            },
            Err(e) => {
                if e.to_string().contains("404") {
                    eprintln!("Project with name '{}' doesn't exist. Please run 'corgea scan' to create a new scan for this project.", project_name);
                } else {
                    eprintln!(
                        "Unable to fetch scans. Please check your connection and ensure that:\n\
                        - The server URL is reachable.\n\
                        - Your authentication token is valid.\n\n\
                        Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli"
                    );
                }
                std::process::exit(1);
            }
        };
        if *json {
            let output = json!({
                "page": page,
                "total_pages": total_pages,
                "results": scans
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
            return;
        }
        let mut table = vec![
            vec![
                "Scan ID".to_string(),
                "Project".to_string(),
                "Status".to_string(),
                "Repo".to_string(),
                "Branch".to_string(),
            ],
        ];

        for scan in &scans {
            let formatted_repo = scan.repo.clone().unwrap_or("N/A".to_string());
            let formatted_repo = if formatted_repo != "N/A" {
                if let Some(repo_name) = formatted_repo.split('/').last() {
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
            ]);
        }

        utils::terminal::print_table(table, page, total_pages);
    }
}
