use std::path::Path;

#[test]
fn generated_deps_skill_block_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("skills")
        .join("corgea")
        .join("SKILL.md");
    corgea::deps::skill::check_skill_file(&path).expect("deps skill block should be current");
}
