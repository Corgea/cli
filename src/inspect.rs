use crate::utils;
use crate::config::Config;
use std::time::SystemTime;
use crate::scanners;
pub fn run(
    config: &Config, 
    issues: &bool, 
    json: &bool, 
    summary: &bool, 
    fix_explanation: &bool, 
    fix_diff: &bool, 
    id: &String,

) {
    fn print_section(title: &str, value: impl ToString) {
        println!("{:<15}: {}", title, value.to_string());
        println!("-------------------------");
    }
    println!();
    if *issues {
        let show_everything = !*summary && !*fix_explanation && !*fix_diff;
        let issue_details = match utils::api::get_issue(&config.get_url(), &config.get_token(), id) {
            Ok(issue) => issue,
            Err(e) => {
                eprintln!("Failed to fetch issue details for issue ID {} with error:\n{}", id, e);
                if e.to_string().contains("404") {
                    println!("If you're trying to inspect a scan make sure to remove the --issue argument");
                }
                std::process::exit(1);
            }
        };
        if *json {
            println!("{}", serde_json::to_string_pretty(&issue_details).unwrap());
            return;
        }
        if *summary || show_everything {
            print_section("Issue ID", &issue_details.issue.id);
            print_section("Urgency", &issue_details.issue.urgency);
            print_section("Category", &issue_details.issue.classification.name);
            print_section("File Path", &issue_details.issue.location.file.path);
            print_section("Line Num", issue_details.issue.location.line_number.to_string());
            print_section("Status", utils::generic::get_status(&issue_details.issue.status));
        }
        if let Some(ref details) = issue_details.issue.details {
            if let Some(ref explanation) = details.explanation {
                if *summary || show_everything {
                    println!("Explanation:\n\n{}\n-------------------------", utils::terminal::format_code(explanation))
                }
            }
        } 
        if let Some(auto_fix_suggestion) = issue_details.issue.auto_fix_suggestion {
            if *fix_explanation || show_everything {
                if show_everything {
                    utils::terminal::prompt_to_continue_or_exit(Some("\nTo continue to viewing the fix explanation please press enter, otherwise Ctrl+C to exit.\n".into()));
                }
                if let Some(ref patch) = &auto_fix_suggestion.patch {
                    utils::terminal::print_with_pagination(&format!(
                        "Fix Explanation:\n\n{}\n-------------------------", utils::terminal::format_code(&patch.explanation)
                    ));
                }
            }
            if *fix_diff || show_everything {   
                if show_everything {
                    utils::terminal::prompt_to_continue_or_exit(Some("\nTo continue to viewing the diff of the fix please press enter, otherwise Ctrl+C to exit.\n".into()));
                }
                if let Some(ref patch) = &auto_fix_suggestion.patch {
                    utils::terminal::print_with_pagination(&utils::terminal::format_diff(&patch.diff));
                }
            }
        }
    } else {
        let scan_details = match utils::api::get_scan(&config.get_url(), &config.get_token(), id) {
            Ok(details) => details,
            Err(e) => {
                eprintln!("Failed to fetch scan details for scan ID {}: {}", id, e);
                if e.to_string().contains("404") {
                    println!("If you're trying to inspect an issues make sure to pass --issue argument");
                }
                std::process::exit(1);
            }
        };
        if *json {
            println!("{}", serde_json::to_string_pretty(&scan_details).unwrap());
            return;
        }
        print_section("Scan ID", &scan_details.id);
        print_section("Repository", scan_details.repo.as_deref().unwrap_or("N/A"));
        print_section("Branch", scan_details.branch.as_deref().unwrap_or("N/A"));

        print_section("Status", scan_details.status);
        print_section("Project", &scan_details.project);
        print_section("Engine", &scan_details.engine);
        let created_at = chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).format("%Y-%m-%d %H:%M:%S").to_string();
        print_section("Created At", &created_at);
        match scanners::blast::fetch_and_group_scan_issues(&config.get_url(), &config.get_token(), &scan_details.project) {
            Ok(counts) => {
                let total_issues = counts.values().sum::<usize>();
                let order = vec!["CR", "HI", "ME", "LO"];
                for urgency in order {
                    if let Some(count) = counts.get(urgency) {
                        print_section(&format!("{} Issues", urgency), &count.to_string());
                    }
                }
                print_section("Total Issues", &total_issues);
            },
            Err(_) => { }
        };

    }
}
