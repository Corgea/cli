use std::path::Path;

use corgea::deps::catalog::FINDING_DEFINITIONS;

#[test]
fn generated_deps_skill_block_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("skills")
        .join("corgea")
        .join("SKILL.md");
    corgea::deps::skill::check_skill_file(&path).expect("deps skill block should be current");
}

#[test]
fn generated_deps_skill_documents_the_catalog_in_declaration_order() {
    let section = corgea::deps::skill::generated_deps_skill_section();
    let positions: Vec<_> = FINDING_DEFINITIONS
        .iter()
        .map(|definition| {
            let row = format!("| `{}` |", definition.id);
            assert_eq!(
                section.matches(&row).count(),
                1,
                "catalog definition must appear exactly once: {}",
                definition.id
            );
            section
                .find(&row)
                .expect("catalog definition must be documented")
        })
        .collect();

    assert!(positions.windows(2).all(|window| window[0] < window[1]));
    assert!(section.contains("| `DEP004` | emitted | High | Wildcard or latest dependency |"));
    assert!(section.contains("| `DEP010` | reserved | Medium | Vulnerable package advisory |"));
    assert!(section.contains(
        "Reserved for vulnerable-package/advisory findings; `corgea deps` does not emit it."
    ));
}
