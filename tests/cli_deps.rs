use std::process::Command;
use tempfile::TempDir;

fn corgea_isolated() -> (Command, TempDir) {
    let home = TempDir::new().expect("temp HOME");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_corgea"));
    cmd.env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("CORGEA_TOKEN")
        .env_remove("CORGEA_URL")
        .env_remove("AI_AGENT")
        .env_remove("CODEX_SANDBOX")
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE")
        .env_remove("CURSOR_AGENT")
        .env_remove("CURSOR_TRACE_ID")
        .env_remove("GEMINI_CLI")
        .env_remove("PI_AGENT");
    (cmd, home)
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn cli_scan_runs_without_token_or_config() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("python-poetry"),
            "--out-format",
            "json",
        ])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(parsed.get("findings").is_some());
}

#[test]
fn cli_scan_does_not_write_outside_home() {
    let (mut cmd, home) = corgea_isolated();
    cmd.args(["deps", "scan", &fixture("node-app")])
        .output()
        .expect("failed to run corgea");
    assert!(home.path().exists());
}

#[test]
fn cli_scan_fail_on_high_exits_one() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "scan", &fixture("node-app"), "--fail-on", "high"])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn cli_scan_clean_fixture_fail_on_high_exits_zero() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("python-poetry"),
            "--fail-on",
            "high",
        ])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn cli_scan_agent_env_defaults_to_agent_format() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .env("AI_AGENT", "1")
        .args(["deps", "scan", &fixture("node-app")])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("record\troot\t"), "stdout: {stdout}");
    assert!(
        stdout.contains("\nfinding\tDEP004\tHigh\tpkg:npm/lodash@4.17.21\t"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_scan_format_human_overrides_agent_env() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .env("AI_AGENT", "1")
        .args(["deps", "scan", &fixture("node-app"), "--format", "human"])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Corgea dependency inventory"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_scan_format_json_outputs_parseable_inventory() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "scan", &fixture("node-app"), "--format", "json"])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(parsed.get("nodes").is_some());
    assert!(parsed.get("findings").is_some());
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("Hint:"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Hint: Run `corgea deps explain"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Hint: Run `corgea deps diff"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_scan_format_quiet_suppresses_stdout_and_preserves_fail_code() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("node-app"),
            "--format",
            "quiet",
            "--fail-on",
            "high",
        ])
        .output()
        .expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"");
}

#[test]
fn cli_scan_agent_hints_go_to_stderr_only() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "scan", &fixture("node-app"), "--format", "agent"])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.starts_with("record\troot\t"), "stdout: {stdout}");
    assert!(!stdout.contains("Hint:"), "stdout: {stdout}");
    assert!(
        stderr.contains("Hint: Run `corgea deps explain"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Hint: Run `corgea deps diff"),
        "stderr: {stderr}"
    );
}

#[test]
fn cli_graph_format_json_outputs_parseable_nodes() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "graph", &fixture("node-app"), "--format", "json"])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    let nodes = parsed["nodes"].as_array().expect("nodes array");
    assert!(nodes
        .iter()
        .any(|node| node["id"] == "pkg:npm/left-pad@1.3.0"));
}

#[test]
fn cli_deps_help_includes_copy_paste_examples() {
    let cases = [
        (
            vec!["deps", "scan", "--help"],
            vec![
                "Examples:",
                "corgea deps scan --format agent",
                "corgea deps scan --out-format sarif --out-file deps.sarif",
            ],
        ),
        (
            vec!["deps", "graph", "--help"],
            vec![
                "Examples:",
                "corgea deps graph --format agent",
                "corgea deps graph tests/fixtures/node-app --format json",
            ],
        ),
        (
            vec!["deps", "explain", "--help"],
            vec![
                "Examples:",
                "corgea deps explain lodash --format agent",
                "corgea deps explain left-pad tests/fixtures/node-app --format json",
            ],
        ),
        (
            vec!["deps", "diff", "--help"],
            vec![
                "Examples:",
                "corgea deps diff --base origin/main --format json",
                "corgea deps diff --base HEAD . --fail-on-new high",
            ],
        ),
        (
            vec!["deps", "sbom", "--help"],
            vec![
                "Examples:",
                "corgea deps sbom --format cyclonedx",
                "corgea deps sbom --format cyclonedx --out bom.json",
            ],
        ),
        (
            vec!["deps", "policy", "init", "--help"],
            vec![
                "Examples:",
                "corgea deps policy init",
                "corgea deps policy init --exist-ok --format quiet",
            ],
        ),
    ];

    for (args, expected) in cases {
        let (mut cmd, _home) = corgea_isolated();
        let out = cmd
            .args(args.clone())
            .output()
            .expect("failed to run corgea");
        assert!(
            out.status.success(),
            "args: {:?}\nstderr: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        for needle in expected {
            assert!(
                stdout.contains(needle),
                "args: {:?}\nmissing: {needle}\nstdout: {stdout}",
                args
            );
        }
    }
}

#[test]
fn cli_deps_rejects_invalid_render_format() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "graph", &fixture("node-app"), "--format", "typo"])
        .output()
        .expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unsupported --format"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_deps_without_subcommand_exits_nonzero() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd.args(["deps"]).output().expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn cli_scan_out_file_writes_json() {
    let (mut cmd, home) = corgea_isolated();
    let out_file = home.path().join("deps.json");
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("java-gradle"),
            "--out-format",
            "json",
            "--out-file",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = std::fs::read_to_string(&out_file).expect("out-file should exist");
    let _: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
}

#[test]
fn cli_scan_rejects_invalid_out_format() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "scan", &fixture("node-app"), "--out-format", "typo"])
        .output()
        .expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unsupported --out-format"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_scan_rejects_render_format_with_out_format() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args([
            "deps",
            "scan",
            &fixture("node-app"),
            "--format",
            "agent",
            "--out-format",
            "json",
        ])
        .output()
        .expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--format cannot be used with --out-format"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_scan_rejects_invalid_fail_on_severity() {
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "scan", &fixture("node-app"), "--fail-on", "hihg"])
        .output()
        .expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unsupported severity for --fail-on"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_scan_loads_policy_created_by_policy_init() {
    let project = TempDir::new().expect("temp project");
    write_exact_node_project(project.path(), "lodash", "*", "4.17.21");

    let (mut default_cmd, _home) = corgea_isolated();
    let default_out = default_cmd
        .args([
            "deps",
            "scan",
            project.path().to_str().unwrap(),
            "--out-format",
            "json",
        ])
        .output()
        .expect("failed to run corgea");
    assert!(default_out.status.success());
    let default_json: serde_json::Value =
        serde_json::from_slice(&default_out.stdout).expect("valid JSON");
    assert!(finding_ids(&default_json).contains(&"DEP004".to_string()));

    let (mut init_cmd, _home) = corgea_isolated();
    let init_out = init_cmd
        .args(["deps", "policy", "init", project.path().to_str().unwrap()])
        .output()
        .expect("failed to run corgea");
    assert!(
        init_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    let policy_path = project.path().join(".corgea").join("deps.yml");
    let policy = std::fs::read_to_string(&policy_path)
        .expect("policy init should create .corgea/deps.yml")
        .replace("fail_on_wildcard: true", "fail_on_wildcard: false")
        .replace("fail_on_latest: true", "fail_on_latest: false");
    std::fs::write(&policy_path, policy).expect("write edited policy");

    let (mut scan_cmd, _home) = corgea_isolated();
    let out = scan_cmd
        .args([
            "deps",
            "scan",
            project.path().to_str().unwrap(),
            "--out-format",
            "json",
        ])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(!finding_ids(&parsed).contains(&"DEP004".to_string()));
}

#[test]
fn cli_policy_init_exist_ok_preserves_existing_policy() {
    let project = TempDir::new().expect("temp project");
    let policy_dir = project.path().join(".corgea");
    std::fs::create_dir_all(&policy_dir).expect("create policy dir");
    let policy_path = policy_dir.join("deps.yml");
    std::fs::write(&policy_path, "custom: true\n").expect("write existing policy");

    let (mut init_cmd, _home) = corgea_isolated();
    let init_out = init_cmd
        .args([
            "deps",
            "policy",
            "init",
            project.path().to_str().unwrap(),
            "--exist-ok",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run corgea");
    assert!(
        init_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&init_out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["created"], false);
    assert!(
        !String::from_utf8_lossy(&init_out.stdout).contains("Hint:"),
        "stdout: {}",
        String::from_utf8_lossy(&init_out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&init_out.stderr).contains("Hint: Run `corgea deps scan"),
        "stderr: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&policy_path).expect("read existing policy"),
        "custom: true\n"
    );
}

#[test]
fn cli_scan_fails_closed_on_invalid_policy_yaml() {
    let project = TempDir::new().expect("temp project");
    write_exact_node_project(project.path(), "lodash", "4.17.21", "4.17.21");
    let policy_dir = project.path().join(".corgea");
    std::fs::create_dir_all(&policy_dir).expect("create policy dir");
    std::fs::write(policy_dir.join("deps.yml"), "dependency_policy: [")
        .expect("write invalid policy");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .args(["deps", "scan", project.path().to_str().unwrap()])
        .output()
        .expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("invalid policy YAML")
            || String::from_utf8_lossy(&out.stderr).contains("invalid policy"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_diff_same_ref_has_empty_diff() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project(repo.path(), "left-pad", "1.3.0", "1.3.0");
    commit_all(repo.path(), "base");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args(["deps", "diff", "--base", "HEAD", "."])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("\n  + "), "stdout: {stdout}");
    assert!(!stdout.contains("\n  - "), "stdout: {stdout}");
    assert!(!stdout.contains("\n  ~ "), "stdout: {stdout}");
}

#[test]
fn cli_diff_reports_real_version_change_from_base_ref() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project(repo.path(), "left-pad", "1.3.0", "1.3.0");
    commit_all(repo.path(), "base");
    write_exact_node_project(repo.path(), "left-pad", "1.3.1", "1.3.1");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args(["deps", "diff", "--base", "HEAD", "."])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("~ left-pad 1.3.0 -> 1.3.1"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_diff_format_json_reports_real_version_change_from_base_ref() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project(repo.path(), "left-pad", "1.3.0", "1.3.0");
    commit_all(repo.path(), "base");
    write_exact_node_project(repo.path(), "left-pad", "1.3.1", "1.3.1");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args(["deps", "diff", "--base", "HEAD", ".", "--format", "json"])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["changed"][0]["name"], "left-pad");
    assert_eq!(parsed["changed"][0]["from"], "1.3.0");
    assert_eq!(parsed["changed"][0]["to"], "1.3.1");
}

#[test]
fn cli_diff_reports_same_version_integrity_change_from_base_ref() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project_with_artifact(repo.path(), "left-pad", "1.3.0", "1.3.0", "sha512-old");
    commit_all(repo.path(), "base");
    write_exact_node_project_with_artifact(repo.path(), "left-pad", "1.3.0", "1.3.0", "sha512-new");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args(["deps", "diff", "--base", "HEAD", "."])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("~ left-pad 1.3.0 integrity changed"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_diff_format_json_reports_same_version_integrity_change_from_base_ref() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project_with_artifact(repo.path(), "left-pad", "1.3.0", "1.3.0", "sha512-old");
    commit_all(repo.path(), "base");
    write_exact_node_project_with_artifact(repo.path(), "left-pad", "1.3.0", "1.3.0", "sha512-new");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args(["deps", "diff", "--base", "HEAD", ".", "--format", "json"])
        .output()
        .expect("failed to run corgea");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["artifact_changed"][0]["name"], "left-pad");
    assert_eq!(parsed["artifact_changed"][0]["version"], "1.3.0");
    assert_eq!(
        parsed["artifact_changed"][0]["integrity"]["from"],
        "sha512-old"
    );
    assert_eq!(
        parsed["artifact_changed"][0]["integrity"]["to"],
        "sha512-new"
    );
}

#[test]
fn cli_diff_fail_on_new_ignores_existing_high_findings() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project(repo.path(), "lodash", "*", "4.17.21");
    commit_all(repo.path(), "base");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args([
            "deps",
            "diff",
            "--base",
            "HEAD",
            ".",
            "--fail-on-new",
            "high",
        ])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_diff_fail_on_new_applies_severity_to_new_findings() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project(repo.path(), "left-pad", "1.3.0", "1.3.0");
    commit_all(repo.path(), "base");

    write_exact_node_project(repo.path(), "left-pad", "^1.3.0", "1.3.0");
    let (mut medium_cmd, _home) = corgea_isolated();
    let medium_out = medium_cmd
        .current_dir(repo.path())
        .args([
            "deps",
            "diff",
            "--base",
            "HEAD",
            ".",
            "--fail-on-new",
            "high",
        ])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        medium_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&medium_out.stderr)
    );

    write_exact_node_project(repo.path(), "left-pad", "*", "1.3.0");
    let (mut high_cmd, _home) = corgea_isolated();
    let high_out = high_cmd
        .current_dir(repo.path())
        .args([
            "deps",
            "diff",
            "--base",
            "HEAD",
            ".",
            "--fail-on-new",
            "high",
        ])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        high_out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&high_out.stderr)
    );
}

#[test]
fn cli_diff_fail_on_new_blocks_same_version_integrity_change() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project_with_artifact(repo.path(), "left-pad", "1.3.0", "1.3.0", "sha512-old");
    commit_all(repo.path(), "base");
    write_exact_node_project_with_artifact(repo.path(), "left-pad", "1.3.0", "1.3.0", "sha512-new");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args([
            "deps",
            "diff",
            "--base",
            "HEAD",
            ".",
            "--fail-on-new",
            "high",
        ])
        .output()
        .expect("failed to run corgea");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_diff_rejects_invalid_fail_on_new_severity() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project(repo.path(), "left-pad", "1.3.0", "1.3.0");
    commit_all(repo.path(), "base");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args([
            "deps",
            "diff",
            "--base",
            "HEAD",
            ".",
            "--fail-on-new",
            "hihg",
        ])
        .output()
        .expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unsupported severity for --fail-on-new"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_diff_rejects_unknown_base_ref() {
    let repo = TempDir::new().expect("temp repo");
    init_git_repo(repo.path());
    write_exact_node_project(repo.path(), "left-pad", "1.3.0", "1.3.0");
    commit_all(repo.path(), "base");

    let (mut cmd, _home) = corgea_isolated();
    let out = cmd
        .current_dir(repo.path())
        .args(["deps", "diff", "--base", "missing-ref", "."])
        .output()
        .expect("failed to run corgea");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("git failed"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn finding_ids(json: &serde_json::Value) -> Vec<String> {
    json["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|finding| finding["id"].as_str().map(str::to_string))
        .collect()
}

fn write_exact_node_project(root: &std::path::Path, name: &str, declared: &str, resolved: &str) {
    write_exact_node_project_with_artifact(root, name, declared, resolved, "sha512-example");
}

fn write_exact_node_project_with_artifact(
    root: &std::path::Path,
    name: &str,
    declared: &str,
    resolved: &str,
    integrity: &str,
) {
    let package_json = format!(
        r#"{{
  "name": "diff-project",
  "version": "1.0.0",
  "dependencies": {{
    "{name}": "{declared}"
  }}
}}
"#
    );
    let package_lock = format!(
        r#"{{
  "name": "diff-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{
      "name": "diff-project",
      "version": "1.0.0",
      "dependencies": {{
        "{name}": "{declared}"
      }}
    }},
    "node_modules/{name}": {{
      "version": "{resolved}",
      "resolved": "https://registry.npmjs.org/{name}/-/{name}-{resolved}.tgz",
      "integrity": "{integrity}"
    }}
  }}
}}
"#
    );
    std::fs::write(root.join("package.json"), package_json).expect("write package.json");
    std::fs::write(root.join("package-lock.json"), package_lock).expect("write package-lock.json");
}

fn init_git_repo(repo: &std::path::Path) {
    run_git(repo, &["init", "-q"]);
}

fn commit_all(repo: &std::path::Path, message: &str) {
    run_git(repo, &["add", "."]);
    run_git(
        repo,
        &[
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test User",
            "commit",
            "-q",
            "-m",
            message,
        ],
    );
}

fn run_git(repo: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed\nstdout: {}\nstderr: {}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
