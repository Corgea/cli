pub fn running_in_ci() -> bool {
    // this will need to be updated to include other CI systems
    std::env::var("CI").is_ok() && std::env::var("GITHUB_ACTIONS").is_ok()
}

pub fn which_ci() -> String {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        "github".to_string()
    } else {
        "unknown".to_string()
    }
}

pub fn get_github_env_vars() -> std::collections::HashMap<String, String> {
    let mut github_env_vars: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for (key, value) in std::env::vars() {
        if key.starts_with("GITHUB_") {
            github_env_vars.insert(key, value);
        }
    }

    github_env_vars
}

/// The branch the CI system says this build is for, when it names one.
///
/// CI systems check out a commit rather than a branch, so git itself reports a
/// detached HEAD and the pipeline's variables are the only record of the branch.
/// A pull request build reports the branch under review. A tag build, and a
/// pull request build whose source branch is unknown, report none: a tag or a
/// merge ref recorded as a branch would file the scan under a branch that does
/// not exist.
pub fn ci_branch() -> Option<String> {
    ci_branch_from(crate::utils::generic::get_env_var_if_exists)
}

fn ci_branch_from(env: impl Fn(&str) -> Option<String>) -> Option<String> {
    let set = |name: &str| env(name).is_some();
    let raw = if set("GITHUB_ACTIONS") {
        // GITHUB_HEAD_REF is only set on pull request events, where GITHUB_REF
        // is `refs/pull/<n>/merge`.
        env("GITHUB_HEAD_REF").or_else(|| env("GITHUB_REF"))
    } else if set("TF_BUILD") {
        // Build.SourceBranchName is only the last path segment, so
        // `feature/tools` would arrive as `tools`.
        env("SYSTEM_PULLREQUEST_SOURCEBRANCH").or_else(|| env("BUILD_SOURCEBRANCH"))
    } else if set("GITLAB_CI") {
        // CI_COMMIT_BRANCH is unset in merge request and tag pipelines.
        env("CI_COMMIT_BRANCH").or_else(|| env("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"))
    } else if set("BITBUCKET_BUILD_NUMBER") {
        env("BITBUCKET_BRANCH")
    } else if set("JENKINS_URL") {
        // On a change request build BRANCH_NAME is the job's name (`PR-123`),
        // not a branch.
        if set("CHANGE_ID") {
            env("CHANGE_BRANCH")
        } else {
            env("BRANCH_NAME")
        }
    } else {
        None
    };
    raw.as_deref().and_then(branch_name_from_ref)
}

/// The branch a ref names: `refs/heads/` is stripped, any other `refs/`
/// namespace (pull request merge refs, tags) is not a branch, and a value
/// outside `refs/` is already a branch name.
fn branch_name_from_ref(value: &str) -> Option<String> {
    let value = value.trim();
    let name = match value.strip_prefix("refs/heads/") {
        Some(name) => name,
        None if value.starts_with("refs/") => return None,
        None => value,
    };
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branch(vars: &[(&str, &str)]) -> Option<String> {
        ci_branch_from(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        })
    }

    #[test]
    fn each_ci_system_reports_the_branch_it_builds() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (
                &[
                    ("GITHUB_ACTIONS", "true"),
                    ("GITHUB_REF", "refs/heads/main"),
                ],
                "main",
            ),
            (
                &[
                    ("TF_BUILD", "True"),
                    ("BUILD_SOURCEBRANCH", "refs/heads/feature/tools"),
                    ("BUILD_SOURCEBRANCHNAME", "tools"),
                ],
                "feature/tools",
            ),
            (
                &[("GITLAB_CI", "true"), ("CI_COMMIT_BRANCH", "develop")],
                "develop",
            ),
            (
                &[
                    ("BITBUCKET_BUILD_NUMBER", "7"),
                    ("BITBUCKET_BRANCH", "release/1.2"),
                ],
                "release/1.2",
            ),
            (
                &[("JENKINS_URL", "https://ci/"), ("BRANCH_NAME", "main")],
                "main",
            ),
        ];
        for (vars, expected) in cases {
            assert_eq!(branch(vars).as_deref(), Some(*expected), "{vars:?}");
        }
    }

    #[test]
    fn a_pull_request_build_reports_the_branch_under_review() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (
                &[
                    ("GITHUB_ACTIONS", "true"),
                    ("GITHUB_HEAD_REF", "fix/login"),
                    ("GITHUB_REF", "refs/pull/12/merge"),
                ],
                "fix/login",
            ),
            (
                &[
                    ("TF_BUILD", "True"),
                    ("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/fix/login"),
                    ("BUILD_SOURCEBRANCH", "refs/pull/12/merge"),
                ],
                "fix/login",
            ),
            (
                &[
                    ("GITLAB_CI", "true"),
                    ("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "fix/login"),
                ],
                "fix/login",
            ),
            (
                &[
                    ("JENKINS_URL", "https://ci/"),
                    ("CHANGE_ID", "12"),
                    ("BRANCH_NAME", "PR-12"),
                    ("CHANGE_BRANCH", "fix/login"),
                ],
                "fix/login",
            ),
        ];
        for (vars, expected) in cases {
            assert_eq!(branch(vars).as_deref(), Some(*expected), "{vars:?}");
        }
    }

    #[test]
    fn a_merge_ref_or_a_tag_is_not_a_branch() {
        let cases: &[&[(&str, &str)]] = &[
            &[
                ("TF_BUILD", "True"),
                ("BUILD_SOURCEBRANCH", "refs/pull/123/merge"),
            ],
            &[("TF_BUILD", "True"), ("BUILD_SOURCEBRANCH", "refs/tags/v1")],
            &[("GITHUB_ACTIONS", "true"), ("GITHUB_REF", "refs/tags/v1")],
            &[
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_REF", "refs/pull/123/merge"),
            ],
            &[("GITLAB_CI", "true"), ("CI_COMMIT_TAG", "v1")],
            &[
                ("JENKINS_URL", "https://ci/"),
                ("CHANGE_ID", "12"),
                ("BRANCH_NAME", "PR-12"),
            ],
        ];
        for vars in cases {
            assert_eq!(branch(vars), None, "{vars:?}");
        }
    }

    #[test]
    fn no_branch_outside_a_known_ci_system() {
        assert_eq!(branch(&[]), None);
        // BRANCH_NAME is too common a name to trust without Jenkins around it.
        assert_eq!(branch(&[("BRANCH_NAME", "main")]), None);
    }
}
