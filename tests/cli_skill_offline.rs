//! Binary-level cover for the offline skill path: `corgea skill show` and
//! `corgea skill install --local` must work with no token and no usable home,
//! because that is the sandbox an agent drives the CLI from.
//!
//! These assert on the process, not on the embedded constant. A unit test that
//! reads `EMBEDDED_SKILL` keeps passing when the dispatch or the auth bypass in
//! `main` regresses; these do not.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// A home directory that cannot be created: `/dev/null` is not a directory, so
/// `create_dir_all` under it fails with ENOTDIR. Stands in for the read-only
/// home of a sandboxed agent without needing root or a mount.
#[cfg(unix)]
const UNUSABLE_HOME: &str = "/dev/null/corgea-no-home";

/// The skill file compiled into the binary under test.
fn skill_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("skills")
        .join("corgea")
        .join("SKILL.md")
}

fn skill_bytes() -> Vec<u8> {
    fs::read(skill_source()).expect("skills/corgea/SKILL.md should be readable")
}

/// Where `--dir <base>` puts the skill.
fn installed_skill(base: &Path) -> PathBuf {
    base.join("corgea").join("SKILL.md")
}

#[test]
fn skill_show_prints_the_skill_byte_for_byte() {
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd.args(["skill", "show"]).output().expect("run corgea");

    assert!(
        out.status.success(),
        "skill show failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout,
        skill_bytes(),
        "stdout must match skills/corgea/SKILL.md exactly"
    );
}

#[cfg(unix)]
#[test]
fn skill_show_survives_a_home_that_cannot_be_created() {
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        .env("HOME", UNUSABLE_HOME)
        .env("USERPROFILE", UNUSABLE_HOME)
        .args(["skill", "show"])
        .output()
        .expect("run corgea");

    assert!(
        out.status.success(),
        "skill show must not need a writable home: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, skill_bytes());
}

#[cfg(unix)]
#[test]
fn local_install_writes_the_skill_without_a_token_or_a_home() {
    let dest = TempDir::new().expect("temp dest");
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        .env("HOME", UNUSABLE_HOME)
        .env("USERPROFILE", UNUSABLE_HOME)
        .args(["skill", "install", "corgea", "--local", "--dir"])
        .arg(dest.path())
        .output()
        .expect("run corgea");

    assert!(
        out.status.success(),
        "--local must not need a writable home when --dir is given: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(installed_skill(dest.path())).expect("skill should have been written"),
        skill_bytes()
    );
}

/// Resolving the destination from `--agent`/`--scope` rather than `--dir` still
/// only touches the working directory, so it is no more dependent on a home.
#[cfg(unix)]
#[test]
fn local_install_resolves_a_project_agent_dir_without_a_home() {
    let project = TempDir::new().expect("temp project");
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        .env("HOME", UNUSABLE_HOME)
        .env("USERPROFILE", UNUSABLE_HOME)
        .current_dir(project.path())
        .args([
            "skill", "install", "corgea", "--local", "--agent", "cursor", "--scope", "project",
        ])
        .output()
        .expect("run corgea");

    assert!(
        out.status.success(),
        "project-scoped --local failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(project.path().join(".cursor/skills/corgea/SKILL.md"))
            .expect("skill should have been written into the project"),
        skill_bytes()
    );
}

/// Persisting the default agent is the one part of `--local` that wants a
/// writable home. It must stay best-effort: the install already succeeded.
#[cfg(unix)]
#[test]
fn local_install_with_set_default_still_succeeds_without_a_home() {
    let dest = TempDir::new().expect("temp dest");
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        .env("HOME", UNUSABLE_HOME)
        .env("USERPROFILE", UNUSABLE_HOME)
        .args([
            "skill",
            "install",
            "corgea",
            "--local",
            "--agent",
            "cursor",
            "--set-default",
            "--dir",
        ])
        .arg(dest.path())
        .output()
        .expect("run corgea");

    assert!(
        out.status.success(),
        "an unsaveable default agent must not fail the install: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(installed_skill(dest.path())).expect("skill should have been written"),
        skill_bytes()
    );
}

/// Serving the embedded skill is a read, so it must not leave `~/.corgea`
/// behind on a home it *could* have written to.
#[test]
fn skill_show_creates_no_config() {
    let (mut cmd, home) = common::corgea_isolated();
    let out = cmd.args(["skill", "show"]).output().expect("run corgea");

    assert!(out.status.success());
    assert!(
        !home.path().join(".corgea").exists(),
        "skill show must not create ~/.corgea"
    );
}

#[test]
fn local_install_creates_no_config() {
    let dest = TempDir::new().expect("temp dest");
    let (mut cmd, home) = common::corgea_isolated();
    let out = cmd
        .args(["skill", "install", "corgea", "--local", "--dir"])
        .arg(dest.path())
        .output()
        .expect("run corgea");

    assert!(out.status.success());
    assert!(
        !home.path().join(".corgea").exists(),
        "--local must not create ~/.corgea"
    );
}

/// `config.toml` is a file the user can edit, so a broken one must not take the
/// offline commands down with it.
#[test]
fn offline_commands_survive_a_malformed_config() {
    let dest = TempDir::new().expect("temp dest");
    let (mut show, home) = common::corgea_isolated();
    let config_dir = home.path().join(".corgea");
    fs::create_dir_all(&config_dir).expect("create config dir");
    fs::write(
        config_dir.join("config.toml"),
        "this is not = valid = toml\n",
    )
    .expect("write malformed config");

    let shown = show.args(["skill", "show"]).output().expect("run corgea");
    assert!(
        shown.status.success(),
        "skill show must survive a malformed config: {}",
        String::from_utf8_lossy(&shown.stderr)
    );
    assert_eq!(shown.stdout, skill_bytes());

    let (mut install, _unused_home) = common::corgea_isolated();
    let installed = install
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .args(["skill", "install", "corgea", "--local", "--dir"])
        .arg(dest.path())
        .output()
        .expect("run corgea");
    assert!(
        installed.status.success(),
        "--local must survive a malformed config: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert_eq!(
        fs::read(installed_skill(dest.path())).expect("skill should have been written"),
        skill_bytes()
    );
}

/// The tolerance above is scoped to the embedded path. A command that needs the
/// config must still refuse to run on one it cannot parse.
#[test]
fn a_malformed_config_still_stops_commands_that_need_it() {
    let dest = TempDir::new().expect("temp dest");
    let (mut cmd, home) = common::corgea_isolated();
    let config_dir = home.path().join(".corgea");
    fs::create_dir_all(&config_dir).expect("create config dir");
    fs::write(
        config_dir.join("config.toml"),
        "this is not = valid = toml\n",
    )
    .expect("write malformed config");

    let out = cmd
        .args(["skill", "install", "corgea", "--dir"])
        .arg(dest.path())
        .output()
        .expect("run corgea");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a registry install must not silently ignore a broken config"
    );
    assert!(
        stderr.contains("config.toml"),
        "the error should name the file to fix: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "an editable file being wrong is not a crash: {stderr}"
    );
}

#[test]
fn registry_install_without_a_token_stops_at_the_auth_gate() {
    let dest = TempDir::new().expect("temp dest");
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        // Nothing listens here, so if the token gate ever stopped
        // short-circuiting, this fails locally instead of reaching a real host.
        .env("CORGEA_URL", "http://127.0.0.1:1")
        .args(["skill", "install", "corgea", "--dir"])
        .arg(dest.path())
        .output()
        .expect("run corgea");

    assert!(
        !out.status.success(),
        "a tokenless registry install must fail"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("No token set"),
        "it must fail at the auth gate, before any request: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !installed_skill(dest.path()).exists(),
        "nothing should be written when auth fails"
    );
}

#[test]
fn local_install_refuses_a_skill_this_binary_does_not_carry() {
    let dest = TempDir::new().expect("temp dest");
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        .args(["skill", "install", "sighthound", "--local", "--dir"])
        .arg(dest.path())
        .output()
        .expect("run corgea");

    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--local can only install"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dest.path().join("sighthound").exists());
}

#[test]
fn local_install_refuses_a_pinned_version() {
    let dest = TempDir::new().expect("temp dest");
    let (mut cmd, _home) = common::corgea_isolated();
    let out = cmd
        .args(["skill", "install", "corgea@1.0.0", "--local", "--dir"])
        .arg(dest.path())
        .output()
        .expect("run corgea");

    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("version cannot be"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!installed_skill(dest.path()).exists());
}
