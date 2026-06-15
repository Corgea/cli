use std::path::Path;
use std::process::ExitCode;

use corgea::deps::skill::{check_skill_file, generated_marked_section, update_skill_file};

const SKILL_PATH: &str = "skills/corgea/SKILL.md";

fn main() -> ExitCode {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "print".to_string());
    let skill_path = Path::new(SKILL_PATH);

    let result = match mode.as_str() {
        "print" => {
            println!("{}", generated_marked_section());
            Ok(())
        }
        "check" => check_skill_file(skill_path),
        "update" => update_skill_file(skill_path),
        _ => Err("usage: cargo run --example deps_skill -- [print|check|update]".to_string()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
