//! `config.toml` is a file the user can edit, so a bad one must read as an
//! error naming the file, not as a Rust panic.

mod common;

use std::fs;

fn write_malformed_config(home: &std::path::Path) {
    let dir = home.join(".corgea");
    fs::create_dir_all(&dir).expect("create config dir");
    fs::write(dir.join("config.toml"), "this is not = valid = toml\n").expect("write config");
}

#[test]
fn a_malformed_config_fails_cleanly_instead_of_panicking() {
    let (mut cmd, home) = common::corgea_isolated();
    write_malformed_config(home.path());

    let out = cmd.args(["ls"]).output().expect("run corgea");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "a broken config must stop the run");
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
fn a_valid_config_is_still_read() {
    let (mut cmd, home) = common::corgea_isolated();
    let dir = home.path().join(".corgea");
    fs::create_dir_all(&dir).expect("create config dir");
    fs::write(
        dir.join("config.toml"),
        "url = \"https://example.invalid\"\ndebug = 0\ntoken = \"\"\n",
    )
    .expect("write config");

    let out = cmd.args(["--help"]).output().expect("run corgea");

    assert!(
        out.status.success(),
        "a parseable config must not stop the run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
