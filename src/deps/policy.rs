#[derive(Debug, Clone)]
pub struct Policy {
    pub require_lockfile: bool,
    pub fail_on_missing_lockfile: bool,
    pub fail_on_stale_lockfile: bool,
    pub fail_on_wildcard: bool,
    pub fail_on_latest: bool,
    pub fail_on_mutable_sources: bool,
    pub warn_on_semver_range: bool,
    pub require_integrity_hashes: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_lockfile: true,
            fail_on_missing_lockfile: true,
            fail_on_stale_lockfile: true,
            fail_on_wildcard: true,
            fail_on_latest: true,
            fail_on_mutable_sources: true,
            warn_on_semver_range: true,
            require_integrity_hashes: true,
        }
    }
}

#[derive(Debug)]
pub struct PolicyError(pub String);

#[derive(serde::Deserialize)]
struct PolicyFile {
    dependency_policy: Option<PolicyYaml>,
}

#[derive(serde::Deserialize)]
struct PolicyYaml {
    require_lockfile: Option<bool>,
    fail_on_missing_lockfile: Option<bool>,
    fail_on_stale_lockfile: Option<bool>,
    direct_dependencies: Option<DirectDepsYaml>,
}

#[derive(serde::Deserialize)]
struct DirectDepsYaml {
    fail_on_wildcard: Option<bool>,
    fail_on_latest: Option<bool>,
    warn_on_semver_range: Option<bool>,
}

impl Policy {
    pub fn from_yaml(yaml: &str) -> Result<Policy, PolicyError> {
        let parsed: PolicyFile = serde_yaml_ng::from_str(yaml)
            .map_err(|e| PolicyError(format!("invalid policy YAML: {e}")))?;
        let mut policy = Policy::default();
        if let Some(dp) = parsed.dependency_policy {
            if let Some(v) = dp.require_lockfile {
                policy.require_lockfile = v;
            }
            if let Some(v) = dp.fail_on_missing_lockfile {
                policy.fail_on_missing_lockfile = v;
            }
            if let Some(v) = dp.fail_on_stale_lockfile {
                policy.fail_on_stale_lockfile = v;
            }
            if let Some(dd) = dp.direct_dependencies {
                if let Some(v) = dd.fail_on_wildcard {
                    policy.fail_on_wildcard = v;
                }
                if let Some(v) = dd.fail_on_latest {
                    policy.fail_on_latest = v;
                }
                if let Some(v) = dd.warn_on_semver_range {
                    policy.warn_on_semver_range = v;
                }
            }
        }
        Ok(policy)
    }

    pub fn default_yaml() -> &'static str {
        r#"dependency_policy:
  require_lockfile: true
  fail_on_missing_lockfile: true
  fail_on_stale_lockfile: true
  direct_dependencies:
    fail_on_wildcard: true
    fail_on_latest: true
    warn_on_semver_range: true
"#
    }
}
