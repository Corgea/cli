use crate::deps::model::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    Emitted,
    Reserved,
    Deprecated,
}

impl FindingStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emitted => "emitted",
            Self::Reserved => "reserved",
            Self::Deprecated => "deprecated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingDefinition {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub remediation: &'static str,
    pub status: FindingStatus,
}

pub const FINDING_DEFINITIONS: &[FindingDefinition] = &[
    FindingDefinition {
        id: "DEP001",
        title: "Missing lockfile",
        severity: Severity::High,
        description:
            "The dependency manifest has no expected lockfile, so resolution is not reproducible.",
        remediation: "Generate and commit the ecosystem lockfile.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP002",
        title: "Stale lockfile",
        severity: Severity::High,
        description: "A manifest dependency is missing from its lockfile.",
        remediation: "Regenerate and commit the lockfile.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP003",
        title: "Direct dependency uses broad range",
        severity: Severity::Medium,
        description: "A direct dependency uses a bounded version range.",
        remediation: "Pin an exact version or explicitly allow the range by policy.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP004",
        title: "Wildcard or latest dependency",
        severity: Severity::High,
        description: "A direct dependency uses wildcard, latest, or another unbounded range.",
        remediation: "Pin an exact version.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP005",
        title: "Mutable Git branch dependency",
        severity: Severity::High,
        description: "A direct dependency is sourced from a mutable Git branch reference.",
        remediation: "Pin a commit SHA or immutable release tag.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP006",
        title: "URL/tarball dependency without checksum",
        severity: Severity::High,
        description: "A direct URL or tarball dependency has no integrity checksum.",
        remediation: "Add an integrity checksum or pin a registry package.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP008",
        title: "Lockfile integrity hash missing",
        severity: Severity::Medium,
        description: "A lockfile entry lacks its integrity hash.",
        remediation: "Add the integrity hash to the lockfile entry.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP010",
        title: "Vulnerable package advisory",
        severity: Severity::Medium,
        description:
            "Reserved for vulnerable-package/advisory findings; `corgea deps` does not emit it.",
        remediation:
            "Handle this code in an advisory or install-wrapper flow, never in `corgea deps`.",
        status: FindingStatus::Reserved,
    },
    FindingDefinition {
        id: "DEP014",
        title: "Duplicate versions of same package",
        severity: Severity::Low,
        description: "More than one resolved version of a package is present.",
        remediation: "Align or deduplicate the resolved dependency versions.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP019",
        title: "Unsupported lockfile",
        severity: Severity::Medium,
        description: "A detected lockfile format is not supported by the parser.",
        remediation: "Use a supported lockfile or wait for parser support.",
        status: FindingStatus::Emitted,
    },
    FindingDefinition {
        id: "DEP021",
        title: "Mutable artifact version",
        severity: Severity::High,
        description: "A direct artifact version is mutable, such as a Maven SNAPSHOT.",
        remediation: "Pin an immutable release version.",
        status: FindingStatus::Emitted,
    },
];

pub fn definition(id: &str) -> Option<&'static FindingDefinition> {
    FINDING_DEFINITIONS
        .iter()
        .find(|definition| definition.id == id)
}

pub fn emitted_definition(id: &str) -> Option<&'static FindingDefinition> {
    definition(id).filter(|definition| definition.status == FindingStatus::Emitted)
}

#[cfg(test)]
mod tests {
    use super::{definition, emitted_definition, FindingStatus, FINDING_DEFINITIONS};

    const EXPECTED_IDS: &[&str] = &[
        "DEP001", "DEP002", "DEP003", "DEP004", "DEP005", "DEP006", "DEP008", "DEP010", "DEP014",
        "DEP019", "DEP021",
    ];
    const EXPECTED_EMITTED_IDS: &[&str] = &[
        "DEP001", "DEP002", "DEP003", "DEP004", "DEP005", "DEP006", "DEP008", "DEP014", "DEP019",
        "DEP021",
    ];

    #[test]
    fn definitions_have_exact_ordered_unique_ids() {
        let ids: Vec<_> = FINDING_DEFINITIONS
            .iter()
            .map(|definition| definition.id)
            .collect();
        assert_eq!(ids, EXPECTED_IDS);
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn definitions_have_nonempty_canonical_metadata() {
        for definition in FINDING_DEFINITIONS {
            assert!(!definition.id.is_empty());
            assert!(!definition.title.is_empty());
            assert!(!definition.description.is_empty());
            assert!(!definition.remediation.is_empty());
        }
    }

    #[test]
    fn general_lookup_round_trips_registered_definitions() {
        for expected in FINDING_DEFINITIONS {
            assert_eq!(definition(expected.id), Some(expected));
        }
        assert!(definition("DEP999").is_none());
    }

    #[test]
    fn definitions_have_exact_emitted_ids() {
        let emitted_ids: Vec<_> = FINDING_DEFINITIONS
            .iter()
            .filter(|definition| definition.status == FindingStatus::Emitted)
            .map(|definition| definition.id)
            .collect();
        assert_eq!(emitted_ids, EXPECTED_EMITTED_IDS);
    }

    #[test]
    fn emitted_lookup_excludes_reserved_dep010() {
        assert_eq!(
            definition("DEP010").unwrap().status,
            FindingStatus::Reserved
        );
        assert!(emitted_definition("DEP010").is_none());
        assert!(emitted_definition("DEP999").is_none());
    }

    #[test]
    fn statuses_have_lowercase_strings() {
        assert_eq!(FindingStatus::Emitted.as_str(), "emitted");
        assert_eq!(FindingStatus::Reserved.as_str(), "reserved");
        assert_eq!(FindingStatus::Deprecated.as_str(), "deprecated");
    }
}
