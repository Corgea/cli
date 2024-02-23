
pub fn running_in_ci() -> bool {
    // this will need to be updated to include other CI systems
    std::env::var("CI").is_ok() && std::env::var("GITHUB_ACTIONS").is_ok()
}

pub fn which_ci() -> String {
    return if std::env::var("GITHUB_ACTIONS").is_ok() {
        "github".to_string()
    } else {
        "unknown".to_string()
    }
}


pub fn get_github_env_vars() -> std::collections::HashMap<String, String> {
    let mut github_env_vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for (key, value) in std::env::vars() {
        if key.starts_with("GITHUB_") {
            github_env_vars.insert(key, value);
        }
    }

    github_env_vars
}
