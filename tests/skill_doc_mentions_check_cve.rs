use std::path::PathBuf;
use std::process::Command;

#[test]
fn deps_help_mentions_login_and_docs() {
    let output = Command::new(env!("CARGO_BIN_EXE_corgea"))
        .args(["deps", "--help"])
        .output()
        .expect("spawn corgea deps --help");

    assert!(
        output.status.success(),
        "deps --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("corgea login") || stdout.contains("CORGEA_TOKEN"),
        "expected login precondition in deps --help, got: {stdout}"
    );
    assert!(
        stdout.contains("docs.corgea.app/cli/deps"),
        "expected docs URL in deps --help, got: {stdout}"
    );
    assert!(
        stdout.contains("--check-cve"),
        "expected --check-cve flag in deps --help, got: {stdout}"
    );
}

#[test]
fn top_level_help_mentions_cve_in_deps_summary() {
    let output = Command::new(env!("CARGO_BIN_EXE_corgea"))
        .arg("--help")
        .output()
        .expect("spawn corgea --help");

    assert!(
        output.status.success(),
        "corgea --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CVE") || stdout.contains("cve") || stdout.contains("vulnerabilit"),
        "expected CVE mention in corgea --help deps summary, got: {stdout}"
    );
}

#[test]
fn skill_md_mentions_check_cve() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("skills/corgea/SKILL.md");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    assert!(
        content.contains("--check-cve"),
        "SKILL.md missing --check-cve"
    );
    assert!(
        content.contains("corgea login") || content.contains("CORGEA_TOKEN"),
        "SKILL.md missing auth precondition"
    );
    assert!(
        content.contains("--fail-cve"),
        "SKILL.md missing --fail-cve"
    );
    assert!(
        content.contains("docs.corgea.app/cli/deps") || content.contains("vuln-api.corgea.app"),
        "SKILL.md missing docs or vuln-api reference"
    );
}

#[test]
fn readme_mentions_deps_cve() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    assert!(
        content.contains("corgea deps"),
        "README.md missing corgea deps"
    );
    assert!(
        content.contains("--check-cve"),
        "README.md missing --check-cve"
    );
    assert!(
        content.contains("docs.corgea.app/cli/deps"),
        "README.md missing link to public docs"
    );
}
