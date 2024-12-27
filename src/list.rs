use crate::utils;
use crate::config::Config;
use std::path::Path;

pub fn run(config: &Config, issues: &bool, json: &bool) {
    let small_column_length = 5;
    let column_length = 8;
    let medium_column_length = 20;
    let long_column_length = 40;
    let separator = " ";
    let project_name = utils::generic::get_current_working_directory().unwrap_or("unknown".to_string());

    if *issues {
        let issues_response = match utils::api::get_scan_issues(&config.get_url(), &config.get_token(), &project_name) {
            Ok(response) => response,
            Err(e) => {
                if e.to_string().contains("404") {
                    eprintln!("Project with name '{}' doesn't exist. Please run 'corgea scan' to create a new scan for this project.", project_name);
                } else {
                    eprintln!(
                        "\n\nUnable to fetch scan issues. Please check your connection and ensure that:\n\
                        - The server URL is reachable.\n\
                        - Your authentication token is valid.\n\n\
                        Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli"
                    );
                }
                std::process::exit(1);
            }
        };


        if *json {
            println!("{}", serde_json::to_string_pretty(&issues_response.issues).unwrap());
            return;
        }
        println!("{:<long_width$}{}{: <width$}{}{: <small_width$}{}{: <long_width$}{}{: <small_width$}", 
            "Issue ID", separator, "Class", separator, "Risk", separator, "File Path", separator, "Line", 
            width = column_length, long_width=long_column_length, small_width=small_column_length);
        
        println!("");

        for issue in &issues_response.issues.unwrap_or_default() {
            let classification_parts: Vec<&str> = issue.classification.split(':').collect();
            let classification_display = if classification_parts.len() > 1 {
                classification_parts[0].trim()
            } else {
                issue.classification.as_str() 
            };
            let path = Path::new(&issue.file_path);
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
                format!("{}/../{}", base_part, path_parts[path_parts.len() - 1])
            } else {
                issue.file_path.clone()
            };
            println!("{:<long_width$}{}{: <width$}{}{: <small_width$}{}{: <long_width$}{}{: <small_width$}", 
                (*issue).id, separator, classification_display, separator, issue.urgency, separator, shortened_path, separator, issue.line_num, 
                width = column_length, long_width=long_column_length, small_width=small_column_length);
        }
    
    } else {
        let scans = match utils::api::query_scan_list(&config.get_url(), &config.get_token(), None, None) {
            Ok(scans) => {
                let filtered_scans: Vec<utils::api::ScanResponse> = scans.scans.into_iter()
                    .filter(|scan| scan.project == project_name)
                    .collect();
                filtered_scans
            },
            Err(e) => {
                if e.to_string().contains("404") {
                    eprintln!("Project with name '{}' doesn't exist. Please run 'corgea scan' to create a new scan for this project.", project_name);
                } else {
                    eprintln!(
                        "\n\nUnable to fetch scans. Please check your connection and ensure that:\n\
                        - The server URL is reachable.\n\
                        - Your authentication token is valid.\n\n\
                        Check out our docs at https://docs.corgea.app/install_cli#login-with-the-cli"
                    );
                }
                std::process::exit(1);
            }
        };
        if *json {
            println!("{}", serde_json::to_string_pretty(&scans).unwrap());
            return;
        }

        println!("{:<long_width$}{}{: <med_width$}{}{: <width$}{}{: <med_width$}{}{: <med_width$}", "Scan ID", separator, "Project", separator, "Done", separator, "Repo",  separator, "Branch", 
            width = column_length, long_width=long_column_length, med_width=medium_column_length);
        println!("");
    
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

            println!("{:<long_width$}{}{: <med_width$}{}{: <width$}{}{: <med_width$}{}{: <med_width$}", 
               scan.id, separator, scan.project, separator, scan.processed, separator, formatted_repo, separator, scan.branch.clone().unwrap_or("N/A".to_string()), 
               width = column_length, long_width=long_column_length, med_width=medium_column_length);
        }
    }
}
