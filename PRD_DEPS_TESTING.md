# PRD: Corgea Dependency Inventory — TDD Test Plan

**Product area:** Corgea CLI / SCA / Dependency Scanning
**Companion to:** `PRD_DEPS.md` (the feature spec)
**Working name:** `corgea deps` test suite
**Status:** Draft PRD — revision 3
**Primary readers:** Engineers implementing `corgea deps`, AppSec reviewers, CI owners
**Core thesis:** Every core behavior in `PRD_DEPS.md` ships behind a test that was **written first and observed failing**. The test suite *is* the executable specification. Implementation is "done" when the suite goes from red to green — not before.

This document is a test-driven-development (TDD) plan. It defines a stub API to land first, fixture projects for **three ecosystems (Python, Node.js, Java)**, and the concrete failing tests that pin the MVP behavior described in `PRD_DEPS.md` §7–§9.

> **Revision 2 changelog.** After a design review (recorded in §14): work is now sequenced as **vertical slices**, not one 52-test red batch (§9); the stub keeps **real constructors** and stubs only leaf behavior (§5); package identity is a typed **`PackageId`** (purl), not a name string (§5.2); tests that depend on an unresolved policy question assert only the **stable invariant** (§3.4); CLI integration tests are **hermetic** — isolated `HOME`, no token, no network (§8.11); one new dependency (`serde_yaml_ng`) is required for policy YAML (§4.3); a robustness / determinism / malformed-input slice is added (§6.8, §8.12).
>
> **Revision 3 changelog.** The seven §13 open questions are now **resolved decisions** (§13). Consequences: a new taxonomy code **DEP021 "Mutable artifact version"** for Maven `SNAPSHOT` (decision 1); unbounded `>=` / bare names are **DEP004 High** (decision 2); **DEP010 "vulnerable resolved package" stays in the MVP** behind a mocked vulnerability source — new **Slice 8** (§8.13, §9) — while DEP016/DEP017 and the Go graph remain deferred (decision 7). The two formerly decision-gated tests (§8.6) now assert exact codes. Test count: ~58 → ~64.

---

## 1. Summary

`PRD_DEPS.md` specifies a large feature: `corgea deps scan / explain / graph / diff / sbom / policy / fix`. None of it exists yet. This is the ideal condition for strict TDD.

This plan does three things:

1. **Defines a stub API** (`src/deps/`) — types and signatures. Constructors and pure helpers are *real*; only the leaf behaviors under test are `unimplemented!()`. Tests *compile* and *fail at the function they target*.
2. **Defines fixture projects** for Python, Node.js, and Java — real manifests and lockfiles in `tests/fixtures/`.
3. **Defines the failing tests** — unit tests against the internal API plus hermetic CLI integration tests against the built binary.

The work is sequenced into **vertical slices** (§9). Each slice is one PR that adds that slice's red tests *and* the implementation that turns them green. The feature branch accumulates green; `main` stays green throughout.

```text
Per slice:  RED  → commit the slice's tests; cargo test shows them failing
            GREEN → implement until the slice's tests pass; nothing else regresses
            REFACTOR → clean up with the now-green slice as a safety net
```

---

## 2. Scope — what "core new deps features" means here

`PRD_DEPS.md` is broad. This test plan covers the **MVP slice** (`PRD_DEPS.md` §10) and only the MVP.

| PRD ref | Core feature | Covered here |
|---|---|---|
| FR1 | Detect manifests & lockfiles | §8.1 |
| FR3 | Classify direct unpinned dependencies | §8.2 |
| FR2 | Build dependency graph (nodes/edges, direct/transitive) | §8.3 |
| FR4 / §7.1 | Manifest-vs-lockfile correctness (do **not** flag locked transitive ranges) | §8.4 |
| FR5 / §7.4 | Lockfile health — missing / stale / missing integrity | §8.5 |
| §7.3 | Package source classification — mutable git / URL without checksum | §8.6 |
| FR8 + §9 | Policy evaluation & finding taxonomy (DEP001–DEP008) | §8.7 |
| §7.5 / DEP010 | Vulnerable resolved package — via a mocked vulnerability source | §8.13 |
| FR6 | `explain` a dependency path | §8.8 |
| FR7 | Dependency diff (graph-level) | §8.9 |
| FR9 / FR11 | Machine-readable output — JSON, SARIF, CycloneDX SBOM | §8.10 |
| §6.4 | CLI behavior — exit codes, `--fail-on`, `--out-file`, hermeticity | §8.11 |
| §18 R2 | Robustness — malformed input, determinism, monorepo | §8.12 |

The three MVP ecosystems under full test: **npm** (Node.js), **PyPI** (Python), **Maven/Gradle** (Java).

### 2.1 Scope — what is in, what is deferred (reconciled with `PRD_DEPS.md` §10)

`PRD_DEPS.md` §10 lists DEP010, DEP016, DEP017 and Go in the MVP. Per §13 decision 7:

- **DEP010 (vulnerable resolved package) is kept in the MVP.** It is the center of gravity of an SCA tool. Because it needs an external advisory source, it is tested behind a **mocked `VulnerabilitySource`** (§5.3, §8.13) — that proves finding construction, severity propagation, and dependency-path attribution offline and deterministically. The production advisory source is a separate, non-test concern.
- **DEP016 (license) and DEP017 (registry) are deferred.** They are config-heavy and secondary, and each needs its own data source. They reuse the same `FindingSource` trait seam (§5.3) and belong in a follow-up plan.
- **Go / Rust / Ruby** get *detection* smoke coverage only (§8.1); their graph building is Beta (`PRD_DEPS.md` §17 Phase 2).

---

## 3. TDD methodology

### 3.1 Why a stub API, and how narrow it is

In Rust, a test referencing a nonexistent module fails to **compile**, and a single non-compiling test file blocks `cargo test` from running *any* test. That is a useless red state.

The useful red state: tests **compile and run**, then **fail at the function under test**. We get that from a stub API — but the stub is *narrow*:

- **Real**: every type, every constructor (`Policy::default`, `DependencyGraph::default`), and every pure helper (`PackageId::name`). These never panic. A test must never fail inside a constructor — that would obscure which behavior is missing.
- **`unimplemented!()`**: only the leaf behaviors a test directly targets — `classify_constraint`, `detect_dependency_files`, `scan`, `evaluate`, `from_yaml`, `explain`, `diff_graphs`, the `report::*` functions.

```rust
pub fn scan(root: &Path, policy: &Policy) -> Result<Inventory, DepsError> {
    unimplemented!("deps::scan — PRD_DEPS_TESTING.md §8")
}
```

A `scan()` test fails with a panic *inside `scan`* — pointing straight at the missing behavior. It does not fail inside `Policy::default()`.

### 3.2 The three states, per slice

1. **RED** — the slice's tests land and fail at their target function.
2. **GREEN** — implement the minimum to pass them. No test is weakened or `#[ignore]`-d to "make it pass". Earlier slices stay green.
3. **REFACTOR** — restructure with the green suite as the net.

### 3.3 Rules for every test

- **Fails first, for the right reason.** Before implementation the failure is the `unimplemented!()` panic of the *targeted* function. The PR adding a test quotes its red `cargo test` output.
- **Pins behavior, not storage.** Tests assert on the public contract (`Inventory`, `Finding`, `DependencyGraph` queried through accessor methods) and fixture inputs — never on private fields or `Vec` ordering (ordering has its own determinism test, §8.12).
- **Positive and negative are paired.** Every "X produces DEPNNN" test is paired with "Y does not". A scanner that flags everything and one that flags nothing must each fail at least one test in every pair.
- **Deterministic & offline.** No network, no wall clock, no real git history. Fixtures are static files; staleness is content divergence, not file mtime (mtime is not preserved by `git`).
- **Hermetic.** Tests touch no real user state. CLI tests run with an isolated `HOME` (§8.11).
- **One behavior per test.** Names read as specifications: `npm_wildcard_direct_dep_is_dep004_high`.

### 3.4 Decision-gated assertions

All seven revision-2 open questions are now resolved (§13), so the two formerly decision-gated tests (`maven_snapshot_is_dep021_high`, `pypi_open_ended_range_is_dep004_high`) assert exact codes as of revision 3. The mechanism is retained for any future open question:

Rule: where an unresolved policy question would change the outcome, the test asserts only the **stable invariant** — a finding exists / does not exist, and its broad severity class (High vs not-High) — and carries a `// DECISION-GATED: <ref>` comment. When the question is resolved, the test is tightened in the same PR that records the decision. Tests that assert an exact code+severity must trace to an unambiguous `PRD_DEPS.md` §9 taxonomy row.

---

## 4. Test architecture

### 4.1 Two layers

| Layer | Location | Exercises | Tests |
|---|---|---|---|
| **Unit** | inline `#[cfg(test)]` submodules under `src/deps/tests/` | the internal `deps` API directly | parsing, classification, graph, findings, policy, diff, report — the language matrix |
| **CLI integration** | `tests/cli_deps.rs` | the compiled binary as a subprocess | argument parsing, exit codes, `--fail-on`, `--out-format`, `--out-file`, hermeticity |

The crate is binary-only (no `src/lib.rs`), so `tests/` integration tests cannot import internal modules — they invoke the binary via the Cargo-provided `CARGO_BIN_EXE_corgea`. Unit tests live inline, matching the existing convention (`src/authorize.rs`).

### 4.2 Directory layout (new)

```text
cli/
  src/
    deps/
      mod.rs              # pub(crate) API: scan(), Inventory; declares #[cfg(test)] mod tests
      model.rs            # PackageId, Ecosystem, Scope, SourceType, ConstraintKind, Severity, nodes/edges/graph
      detect.rs           # detect_dependency_files()
      ecosystems/
        mod.rs            # classify_constraint(); dispatch
        npm.rs            # package.json / package-lock.json / yarn.lock / pnpm-lock.yaml
        pypi.rs           # requirements.txt / constraints.txt / pyproject.toml / poetry.lock / uv.lock
        maven.rs          # pom.xml / build.gradle / gradle.lockfile
      findings.rs         # Finding, evaluate()
      policy.rs           # Policy (real Default), from_yaml()
      diff.rs             # diff_graphs(), GraphDiff
      explain.rs          # explain(), Explanation
      report.rs           # to_json(), to_sarif(), to_cyclonedx()
      vuln.rs             # VulnerabilitySource (mocked) — DEP010 enrichment
      tests/              # #[cfg(test)] only — full internal-API access
        mod.rs
        common.rs         # fixture loaders, scan helpers
        detect_tests.rs
        npm_tests.rs
        pypi_tests.rs
        maven_tests.rs
        correctness_tests.rs
        findings_tests.rs
        policy_tests.rs
        explain_tests.rs
        diff_tests.rs
        report_tests.rs
        robustness_tests.rs
        vuln_tests.rs
  tests/
    cli_deps.rs           # integration: runs the binary, isolated HOME
    fixtures/
      node-app/           package.json, package-lock.json
      node-stale/         package.json, package-lock.json
      node-monorepo/      package.json (workspaces), packages/a/*, packages/b/*, package-lock.json
      python-poetry/      pyproject.toml, poetry.lock
      python-pip-nolock/  requirements.txt
      java-maven/         pom.xml
      java-gradle/        build.gradle, gradle.lockfile
      go-mod-smoke/       go.mod, go.sum                  # detection smoke only
      malformed/          bad-package-lock.json, truncated-poetry.lock, not-xml-pom.xml
      vuln-db.json        # static advisory DB for the mocked VulnerabilitySource
```

### 4.3 Dependencies

Parsing reuses crates already in `Cargo.toml`: `serde_json` (npm), `toml` (poetry.lock, pyproject.toml, uv.lock), `quick-xml` (pom.xml), `regex` (requirements.txt, build.gradle, gradle.lockfile), `git2`/`url` (ref classification), `tempfile` (runtime test scaffolding).

**One new dependency is required.** `Policy::from_yaml` parses YAML (`.corgea/deps.yml` and the `PRD_DEPS.md` §6.6 examples are YAML). The crate has `toml` but **no YAML parser**. Add to `[dependencies]`:

```toml
serde_yaml_ng = "0.10"   # §13 decision 6: confirmed. serde_yaml is archived; serde_yml rejected (provenance).
```

`assert_cmd` + `predicates` were considered as a `[dev-dependencies]` ergonomic upgrade for §8.11 and **rejected** (§13 decision 5): the CLI tests need hand-written `HOME` isolation regardless, and `CARGO_BIN_EXE_corgea` already supplies the binary path. The plan uses plain `std::process::Command`.

### 4.4 Naming & running

Snake_case specification names, prefixed by area: `npm_*`, `pypi_*`, `maven_*`, `detect_*`, `policy_*`, `robust_*`, `cli_*`.

```bash
cargo test                    # whole crate
cargo test deps               # every deps test
cargo test npm_               # one ecosystem's matrix
cargo test --test cli_deps    # CLI integration only
```

---

## 5. Phase 0 — the stub API (lands with Slice 1)

Phase 0 is the only code that lands *with* its first slice's tests rather than after them: it is scaffolding, not behavior. **Definition of done for Phase 0: `cargo test` compiles with zero errors; Slice 1's tests (§8.2) fail inside `classify_constraint`; no test fails inside a constructor.**

### 5.1 Wire the subcommand (`src/main.rs`)

Add a `Deps` variant to `Commands`, a match arm dispatching to `deps::run(...)`, and `mod deps;` at the top of `main.rs` — per `cli/CLAUDE.md` "adding a new subcommand". `deps scan` is a **local, offline** operation: it must **not** call `verify_token_and_exit_when_fail` and must not require config or network (see §8.11).

```rust
/// Dependency inventory and supply-chain policy scanning
Deps {
    #[command(subcommand)]
    command: DepsCommand,
},
```

```rust
#[derive(Subcommand)]
enum DepsCommand {
    /// Scan manifests and lockfiles, build inventory, evaluate policy
    Scan {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long, help = "Fail (exit 1) at or above this severity: critical, high, medium, low")]
        fail_on: Option<String>,
        #[arg(long, help = "Output format: table, json, sarif")]
        out_format: Option<String>,
        #[arg(long, help = "Write output to this file")]
        out_file: Option<String>,
    },
    /// Print the dependency graph
    Graph { #[arg(default_value = ".")] path: String },
    /// Explain why a package is present
    Explain { package: String },
    /// Generate an SBOM
    Sbom { #[arg(long, default_value = "cyclonedx")] format: String },
}
```

### 5.2 The model — typed identity (`src/deps/model.rs`)

Package identity is a typed **`PackageId`** (a canonical purl), not a bare name. A bare name is ambiguous across Maven `group:artifact` coordinates and across duplicate versions of the same package (`PRD_DEPS.md` DEP014). `PackageId` and its accessors are **real** — pure string parsing, never `unimplemented!()`.

```rust
/// Canonical package identity: a Package URL, e.g. "pkg:npm/express@4.18.2".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageId(pub String);

impl PackageId {
    /// The package-name component ("express", "guava", "commons-lang3").
    pub fn name(&self) -> &str {
        let before_at = self.0.rsplit_once('@').map(|(l, _)| l).unwrap_or(&self.0);
        before_at.rsplit_once('/').map(|(_, r)| r).unwrap_or(before_at)
    }
    /// The resolved-version component, if the purl carries one.
    pub fn version(&self) -> Option<&str> {
        self.0.rsplit_once('@').map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem { Npm, PyPI, Maven, Go, Cargo, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope { Production, Development, Optional, Peer }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Registry, PrivateRegistry, GitCommit, GitBranch, GitTag,
    LocalPath, RemoteTarball, Url, Workspace, Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity { Info, Low, Medium, High, Critical }

/// How a declared version constraint behaves — the classification that drives findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintKind {
    Exact,                          // 1.2.3  ==1.2.3  [1.2.3]
    BoundedRange,                   // ^1.2.0  ~1.2  >=1,<2  [1.0,2.0)  3.+
    Unbounded,                      // *  x  >=1  latest  latest.release  LATEST  bare name
    Mutable,                        // SNAPSHOT and other coordinates whose content can change
    GitRef { mutable: bool },       // mutable=true → branch ref; false → 40-char commit SHA
    Url { checksum: bool },         // checksum=false → tarball/URL with no integrity hash
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyNode {
    pub(crate) id: PackageId,
    pub(crate) name: String,
    pub(crate) ecosystem: Ecosystem,
    pub(crate) version: Option<String>,   // resolved version; None if unresolved
    pub(crate) direct: bool,
    pub(crate) scope: Scope,
    pub(crate) depth: u32,
    pub(crate) source_type: SourceType,
    pub(crate) manifest_file: Option<String>,
    pub(crate) lockfile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEdge {
    pub(crate) from: PackageId,            // root id or a package id
    pub(crate) to: PackageId,
    pub(crate) declared_constraint: String,
    pub(crate) resolved_version: Option<String>,
    pub(crate) scope: Scope,
    pub(crate) source_file: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyGraph {
    pub(crate) nodes: Vec<DependencyNode>,
    pub(crate) edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    /// First node with this package name. Safe for fixtures with unique names.
    pub fn node(&self, name: &str) -> Option<&DependencyNode> {
        self.nodes.iter().find(|n| n.name == name)
    }
    /// Every node with this package name (use when duplicates are possible).
    pub fn nodes_named(&self, name: &str) -> Vec<&DependencyNode> {
        self.nodes.iter().filter(|n| n.name == name).collect()
    }
    pub fn node_by_id(&self, id: &PackageId) -> Option<&DependencyNode> {
        self.nodes.iter().find(|n| &n.id == id)
    }
}
```

Fields are `pub(crate)` — internal model, queried through accessor methods. Tests read `node.id()`, `node.is_direct()`, etc. via small real accessors (shown where first used). Constructors used by tests (e.g. `DependencyNode::new(...)` for §8.9) are real builder functions, not stubs.

### 5.3 Detection, classification, findings, policy

```rust
// src/deps/detect.rs
use std::path::{Path, PathBuf};
use crate::deps::model::Ecosystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepFileKind {
    NpmManifest, NpmLockfile, YarnLockfile, PnpmLockfile,
    PipRequirements, PipConstraints, PyProject, PoetryLock, UvLock,
    MavenPom, GradleBuild, GradleLockfile,
    GoMod, GoSum, CargoManifest, CargoLock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedFile {
    pub path: PathBuf,
    pub kind: DepFileKind,
    pub ecosystem: Ecosystem,
}

/// Recursively detect supported dependency files; skip vendored/VCS dirs. FR1.
pub fn detect_dependency_files(root: &Path) -> Vec<DetectedFile> {
    unimplemented!("deps::detect_dependency_files — PRD_DEPS_TESTING.md §8.1")
}
```

```rust
// src/deps/ecosystems/mod.rs
use crate::deps::model::{ConstraintKind, Ecosystem};

/// Classify a raw declared constraint string. FR3 / PRD_DEPS.md §7.1.
pub fn classify_constraint(ecosystem: Ecosystem, raw: &str) -> ConstraintKind {
    unimplemented!("deps::ecosystems::classify_constraint — PRD_DEPS_TESTING.md §8.2")
}
```

```rust
// src/deps/findings.rs
use crate::deps::model::{PackageId, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: String,                       // taxonomy code, e.g. "DEP004"
    pub severity: Severity,
    pub title: String,
    pub package: Option<PackageId>,
    pub source_file: String,
    pub declared_constraint: Option<String>,
    pub resolved_version: Option<String>,
    pub recommendation: String,
    /// True when the install is still deterministic despite the finding
    /// (e.g. a manifest range that a committed lockfile resolves exactly).
    pub reproducible: bool,
    pub paths: Vec<Vec<PackageId>>,       // dependency paths, root-first
}
```

```rust
// src/deps/policy.rs  — Default and field access are REAL; only from_yaml is stubbed.
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
    /// The recommended default from PRD_DEPS.md §19. REAL — never panics.
    fn default() -> Self {
        Policy {
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

impl Policy {
    pub fn from_yaml(yaml: &str) -> Result<Policy, PolicyError> {
        unimplemented!("deps::Policy::from_yaml — PRD_DEPS_TESTING.md §8.7")
    }
}
```

```rust
// src/deps/mod.rs
pub mod model;
pub mod detect;
pub mod ecosystems;
pub mod findings;
pub mod policy;
pub mod diff;
pub mod explain;
pub mod report;
pub mod vuln;

use std::path::{Path, PathBuf};
use detect::DetectedFile;
use model::{DependencyGraph, DependencyNode, PackageId};
use findings::Finding;
use policy::Policy;

#[derive(Debug)]
pub struct DepsError(pub String);

/// Full result of a dependency scan of one directory tree.
#[derive(Debug)]
pub struct Inventory {
    pub root: PathBuf,
    pub detected_files: Vec<DetectedFile>,
    pub graph: DependencyGraph,
    pub findings: Vec<Finding>,
}

impl Inventory {                           // all REAL — pure filters over owned data
    /// Findings carrying a specific taxonomy code, e.g. "DEP004".
    pub fn with_code(&self, code: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.id == code).collect()
    }
    /// Findings about a package, matched on the purl name component exactly.
    pub fn findings_for(&self, name: &str) -> Vec<&Finding> {
        self.findings.iter()
            .filter(|f| f.package.as_ref().is_some_and(|id| id.name() == name))
            .collect()
    }
    pub fn node(&self, name: &str) -> Option<&DependencyNode> {
        self.graph.node(name)
    }
}

/// Scan a directory tree: detect files, build the graph, evaluate policy.
pub fn scan(root: &Path, policy: &Policy) -> Result<Inventory, DepsError> {
    unimplemented!("deps::scan — PRD_DEPS_TESTING.md §8")
}

/// CLI entry point for `corgea deps ...`.
pub fn run(/* DepsCommand */) {
    unimplemented!("deps::run — PRD_DEPS_TESTING.md §8.11")
}

#[cfg(test)]
mod tests;
```

`diff.rs`, `explain.rs`, `report.rs` follow the same pattern — signatures inline in §8.9 / §8.8 / §8.10.

**External-source seam.** DEP010/016/017 read from external data sources. The seam is a trait declared in `findings.rs`:

```rust
// src/deps/findings.rs
pub trait FindingSource {
    /// Enrich a built graph with findings that require external data.
    fn enrich(&self, graph: &DependencyGraph) -> Vec<Finding>;
}
```

Per §13 decision 7, **DEP010 is built in the MVP** behind this trait: Slice 8 adds a `VulnerabilitySource: FindingSource` implementor backed by an offline fixture advisory DB (§6.9, §8.13). Keeping enrichment a separate step from `scan()` preserves the offline/determinism guarantees of §8.12. DEP016/DEP017 stay deferred — same trait, no MVP implementor, follow-up plan.

---

## 6. Test fixtures

Fixtures are static, checked-in projects, chosen so **every MVP finding code fires in at least one fixture and stays silent in at least one other**. Fixture contents below are normative.

### 6.1 Node.js — `tests/fixtures/node-app/` (the "many findings" fixture)

`package.json`:

```json
{
  "name": "node-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "*",
    "left-pad": "latest",
    "internal-utils": "git+https://github.com/acme/internal-utils.git#main"
  },
  "devDependencies": {
    "jest": "29.7.0"
  }
}
```

`package-lock.json` (lockfileVersion 3):

```json
{
  "name": "node-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "node-app",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.2",
        "lodash": "*",
        "left-pad": "latest",
        "internal-utils": "git+https://github.com/acme/internal-utils.git#main"
      },
      "devDependencies": { "jest": "29.7.0" }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ==",
      "dependencies": { "qs": "6.11.0" }
    },
    "node_modules/qs": {
      "version": "6.11.0",
      "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz",
      "integrity": "sha512-MvjoMCJwEarSbUYk5O+nmoSzSutSsTwF85zcHPQ9OrlFoZOYIjaqBAJIqIXjptyD5vThxGq52Xu/MaJzRkDtA=="
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvKw=="
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}
```

`left-pad` deliberately has **no `integrity`** → DEP008. Per-package expectation (normative):

| Package | Declared | Kind | Expected |
|---|---|---|---|
| `express` | `^4.18.2` | direct, prod | DEP003 (broad range), **Medium**, `reproducible: true` |
| `lodash` | `*` | direct, prod | DEP004 (wildcard), **High** |
| `left-pad` | `latest` | direct, prod | DEP004 (`latest`), **High**; **and** DEP008 (no integrity) |
| `internal-utils` | `git+…#main` | direct, prod | DEP005 (mutable git branch), **High**, `source_type: GitBranch` |
| `jest` | `29.7.0` | direct, **dev** | no finding; `scope: Development` |
| `qs` | `6.11.0` (by express) | **transitive**, prod | **no finding** — locked & exact (§8.4) |

### 6.2 Node.js — `tests/fixtures/node-stale/` (stale lockfile)

`package.json` declares `chalk`; the lockfile does not contain it:

```json
{
  "name": "node-stale",
  "version": "1.0.0",
  "dependencies": { "express": "^4.18.2", "chalk": "^5.3.0" }
}
```

`package-lock.json` — `express` only, **no `chalk`**:

```json
{
  "name": "node-stale",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "node-stale", "version": "1.0.0",
          "dependencies": { "express": "^4.18.2" } },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="
    }
  }
}
```

Staleness = **content divergence** (`chalk` in manifest, absent from lockfile), not mtime. Expected: DEP002, High.

### 6.3 Node.js — `tests/fixtures/node-monorepo/` (workspaces)

Root `package.json` with `"workspaces": ["packages/*"]`, two workspace manifests `packages/a/package.json` and `packages/b/package.json`, and a single root `package-lock.json`. Used by §8.12 to assert every workspace manifest is detected and attributed. Keep each manifest to 1–2 dependencies.

### 6.4 Python — `tests/fixtures/python-poetry/` (well-locked)

`pyproject.toml`:

```toml
[tool.poetry]
name = "python-poetry-app"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "^2.31.0"
flask = "2.3.3"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0.0"
```

`poetry.lock`:

```toml
[[package]]
name = "requests"
version = "2.31.0"
optional = false
python-versions = ">=3.7"

[package.dependencies]
urllib3 = ">=1.21.1,<3"

[[package]]
name = "urllib3"
version = "2.0.7"
optional = false
python-versions = ">=3.7"

[[package]]
name = "flask"
version = "2.3.3"
optional = false
python-versions = ">=3.8"

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "0000000000000000000000000000000000000000000000000000000000000000"
```

Expected: `requests` `^2.31.0` direct → DEP003 Medium, `reproducible: true`. `flask 2.3.3` → no finding (exact). `urllib3` transitive, declared as a range by `requests`, locked → **no finding** (§8.4). Lockfile present → **no DEP001**.

### 6.5 Python — `tests/fixtures/python-pip-nolock/` (no lockfile)

`requirements.txt`, no `constraints.txt`, no lockfile:

```text
flask==2.3.3
requests
urllib3>=1.26
internal-lib @ git+https://github.com/acme/internal-lib.git@main
```

Expected: DEP001 (missing lockfile), High. `flask==2.3.3` exact → no pin finding. `requests` bare → DEP004 High. `urllib3>=1.26` open-ended → DEP004 High (§13 decision 2). `internal-lib @ git+…@main` → DEP005, High.

### 6.6 Java — `tests/fixtures/java-maven/` (Maven, no lockfile)

`pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>java-maven-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.3-jre</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>[3.0,4.0)</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>LATEST</version>
    </dependency>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-bom</artifactId>
      <version>2.0-SNAPSHOT</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.1</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
```

Expected: `guava 32.1.3-jre` exact → no finding. `commons-lang3 [3.0,4.0)` Maven range → DEP003 Medium. `slf4j-api LATEST` → DEP004 High. `internal-bom 2.0-SNAPSHOT` → mutable → DEP021 High (§13 decision 1). `junit-jupiter` `<scope>test</scope>` → `scope: Development`, no finding. Maven has no first-class lockfile → DEP001 High.

### 6.7 Java — `tests/fixtures/java-gradle/` (Gradle, with lockfile)

`build.gradle`:

```groovy
plugins {
    id 'java'
}

dependencies {
    implementation 'com.google.guava:guava:32.1.3-jre'
    implementation 'org.apache.commons:commons-lang3:3.+'
    implementation 'org.slf4j:slf4j-api:latest.release'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.1'
}
```

`gradle.lockfile`:

```text
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:32.1.3-jre=compileClasspath,runtimeClasspath
org.apache.commons:commons-lang3:3.14.0=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:2.0.9=compileClasspath,runtimeClasspath
org.junit.jupiter:junit-jupiter:5.10.1=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor
```

Expected: `guava` exact → no finding. `commons-lang3 3.+` dynamic, resolved by lockfile to `3.14.0` → DEP003 Medium, `reproducible: true`. `slf4j-api latest.release` → DEP004 High **even though resolved** — `latest.release` violates policy regardless of locking. `gradle.lockfile` present → **no DEP001**.

### 6.8 Smoke & robustness fixtures

- `tests/fixtures/go-mod-smoke/` — minimal `go.mod` + `go.sum`, so §8.1 asserts detection of a non-MVP-graph ecosystem.
- `tests/fixtures/malformed/` — three deliberately broken files: `bad-package-lock.json` (invalid JSON, e.g. a trailing comma and an unclosed brace), `truncated-poetry.lock` (TOML cut off mid-table), `not-xml-pom.xml` (a `pom.xml` whose body is not XML). §8.12 asserts the scanner returns an error and never panics.

Note: `.gitignore` excludes `node_modules/`, so a "skip `node_modules`" fixture cannot be committed. §8.12 builds that scenario in a `tempfile::TempDir` at runtime instead.

### 6.9 Vulnerability advisory fixture (Slice 8)

`tests/fixtures/vuln-db.json` — a static, offline advisory database for the mocked `VulnerabilitySource` (§8.13). It maps a package name + vulnerable versions to an advisory `{ id, severity, summary }`. It deliberately flags one **transitive** package present in `node-app` — `qs@6.11.0` — and leaves the direct, in-sync packages (`express@4.18.2`, `lodash@4.17.21`) unflagged, so DEP010 has a positive case (a transitive hit) and negative controls.

```json
{
  "advisories": [
    {
      "name": "qs",
      "vulnerable_versions": ["6.11.0"],
      "id": "GHSA-FIXTURE-qs-0001",
      "severity": "high",
      "summary": "Fixture advisory for qs (test data — not a live CVE mapping)."
    }
  ]
}
```

This file is test data only. It is not a real advisory feed and must never be wired into a production code path.

---

## 7. Traceability matrix

Every MVP behavior maps to ≥1 named test; every test maps back to a PRD requirement. A finding code is "covered" only when it has **both** a positive and a negative test.

| PRD ref | Behavior | Test(s) | Slice |
|---|---|---|---|
| FR3 | npm constraint classification | `npm_classify_*` (6) | 1 |
| FR3 | PyPI constraint classification | `pypi_classify_*` (5) | 1 |
| FR3 | Maven/Gradle constraint classification | `maven_classify_*`, `gradle_classify_*` (6) | 1 |
| FR1 | Detect npm files | `detect_finds_npm_files` | 2 |
| FR1 | Detect Python files | `detect_finds_python_poetry_files`, `detect_finds_pip_requirements` | 2 |
| FR1 | Detect Java files | `detect_finds_maven_pom`, `detect_finds_gradle_files` | 2 |
| FR1 | Non-MVP ecosystem still detected | `detect_finds_go_mod_smoke` | 2 |
| FR2 | npm graph: direct/transitive, scope, source | `npm_graph_*` (4) | 3 |
| FR2 / FR9 | npm purl identity, JSON output, CLI scan | `npm_purl_*`, `report_json_*`, `cli_scan_*` | 3 |
| §7.1 / FR4 | npm locked transitive range → no finding | `node_locked_transitive_range_yields_no_finding`, `node_direct_locked_range_is_medium_not_high` | 3 |
| DEP002 | Stale lockfile (pos/neg) | `node_manifest_dep_missing_from_lock_is_dep002`, `node_app_lock_in_sync_no_dep002` | 3 |
| DEP008 | Missing integrity (pos/neg) | `npm_lock_entry_without_integrity_is_dep008`, `npm_lock_entry_with_integrity_no_dep008` | 3 |
| DEP003/004/005 | npm pinning & source findings | `npm_caret_*`, `npm_wildcard_*`, `npm_latest_*`, `npm_git_branch_*`, `git_commit_sha_*`, `npm_url_*` | 3 |
| FR2 | PyPI graph build | `pypi_graph_*` (2) | 4 |
| §7.1 / FR4 | PyPI locked transitive range → no finding | `pypi_locked_transitive_range_yields_no_finding` | 4 |
| DEP001 | Missing lockfile (pos/neg) | `pip_no_lockfile_is_dep001`, `poetry_lock_present_no_dep001` | 4 |
| DEP004/005 | PyPI pinning & source | `pypi_bare_name_is_dep004`, `pypi_open_ended_range_is_dep004_high`, `pypi_git_branch_dep_is_dep005` | 4 |
| FR2 | Maven/Gradle graph build | `maven_graph_*`, `gradle_graph_*` | 5 |
| §7.1 / FR4 | Gradle locked dynamic version reproducible | `gradle_locked_dynamic_version_is_reproducible` | 5 |
| DEP001 | Maven no lockfile / Gradle lock present | `maven_no_lockfile_is_dep001`, `gradle_lock_present_no_dep001` | 5 |
| DEP003/004/021 | Maven/Gradle pinning & SNAPSHOT | `maven_range_direct_dep_is_dep003`, `maven_latest_keyword_is_dep004`, `maven_snapshot_is_dep021_high` | 5 |
| FR8 | Default policy & YAML parse | `default_policy_fails_on_wildcard`, `policy_from_yaml_parses_prd_example`, `policy_disabling_rule_silences_finding` | 5 |
| FR6 | Explain dependency path | `explain_transitive_shows_path`, `explain_unknown_package_is_none` | 6 |
| FR7 | Graph diff | `diff_detects_added_removed_changed` | 6 |
| FR9 | SARIF output | `report_sarif_has_rules_and_results` | 6 |
| FR11 | CycloneDX SBOM | `report_cyclonedx_has_components_and_deps` | 6 |
| §6.4 | CLI exit codes, out-file, hermeticity, no-token | `cli_*` (5) | 3–6 |
| §18 R2 | Malformed input → error not panic | `robust_malformed_*` (3) | 7 |
| §18 R2 | Determinism of graph & JSON output | `robust_graph_order_deterministic`, `robust_json_output_byte_stable` | 7 |
| §18 R2 | Monorepo / skip vendored / classifier never panics | `robust_monorepo_*`, `robust_scan_skips_node_modules`, `robust_classify_never_panics` | 7 |
| §7.5 / DEP010 | Vulnerable resolved package — pos/neg, mocked source, path attribution | `vuln_*` (6) | 8 |

Total: ~64 tests.

---

## 8. The failing tests

All code below is the deliverable of its slice (§9). Written first, observed failing, committed with red `cargo test` output in the PR.

### 8.0 Shared helpers — `src/deps/tests/common.rs`

```rust
use std::path::PathBuf;
use crate::deps::{scan, Inventory, policy::Policy};

/// Absolute path to a fixture project directory.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Read one file inside a fixture project.
pub fn read(name: &str, file: &str) -> String {
    let path = fixture(name).join(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing fixture file {}: {e}", path.display()))
}

/// Scan a fixture with the default policy; panic with context on failure.
pub fn scan_fixture(name: &str) -> Inventory {
    scan(&fixture(name), &Policy::default())
        .unwrap_or_else(|e| panic!("scan of fixture {name} failed: {e:?}"))
}
```

`src/deps/tests/mod.rs`:

```rust
mod common;
mod detect_tests;
mod npm_tests;
mod pypi_tests;
mod maven_tests;
mod correctness_tests;
mod findings_tests;
mod policy_tests;
mod explain_tests;
mod diff_tests;
mod report_tests;
mod robustness_tests;
mod vuln_tests;
```

### 8.1 File detection — `detect_tests.rs` (Slice 2)

```rust
use super::common::fixture;
use crate::deps::detect::{detect_dependency_files, DepFileKind};
use crate::deps::model::Ecosystem;

fn kinds(root: &str) -> Vec<DepFileKind> {
    let mut k: Vec<_> = detect_dependency_files(&fixture(root))
        .into_iter().map(|f| f.kind).collect();
    k.sort_by_key(|x| format!("{x:?}"));
    k
}

#[test]
fn detect_finds_npm_files() {
    let k = kinds("node-app");
    assert!(k.contains(&DepFileKind::NpmManifest), "expected package.json");
    assert!(k.contains(&DepFileKind::NpmLockfile), "expected package-lock.json");
}

#[test]
fn detect_finds_python_poetry_files() {
    let k = kinds("python-poetry");
    assert!(k.contains(&DepFileKind::PyProject));
    assert!(k.contains(&DepFileKind::PoetryLock));
}

#[test]
fn detect_finds_pip_requirements() {
    let files = detect_dependency_files(&fixture("python-pip-nolock"));
    assert!(files.iter().any(|f| f.kind == DepFileKind::PipRequirements));
    assert!(files.iter().all(|f| f.ecosystem == Ecosystem::PyPI));
}

#[test]
fn detect_finds_maven_pom() {
    assert!(kinds("java-maven").contains(&DepFileKind::MavenPom));
}

#[test]
fn detect_finds_gradle_files() {
    let k = kinds("java-gradle");
    assert!(k.contains(&DepFileKind::GradleBuild));
    assert!(k.contains(&DepFileKind::GradleLockfile));
}

#[test]
fn detect_finds_go_mod_smoke() {
    // Non-MVP ecosystem: detection must still work even before graph support.
    assert!(kinds("go-mod-smoke").contains(&DepFileKind::GoMod));
}
```

(The "skip `node_modules`" assertion needs a runtime-built fixture — see `robust_scan_skips_node_modules`, §8.12.)

### 8.2 Constraint classification — `npm_tests.rs`, `pypi_tests.rs`, `maven_tests.rs` (Slice 1)

The per-language heart of FR3. `classify_constraint` is a pure function — the cheapest, sharpest TDD unit, and the first thing implemented.

`npm_tests.rs` (classification section):

```rust
use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::{ConstraintKind, Ecosystem::Npm};

#[test]
fn npm_classify_exact_version() {
    assert_eq!(classify_constraint(Npm, "4.18.2"), ConstraintKind::Exact);
}

#[test]
fn npm_classify_caret_is_bounded_range() {
    assert_eq!(classify_constraint(Npm, "^4.18.2"), ConstraintKind::BoundedRange);
}

#[test]
fn npm_classify_wildcard_is_unbounded() {
    assert_eq!(classify_constraint(Npm, "*"), ConstraintKind::Unbounded);
}

#[test]
fn npm_classify_latest_is_unbounded() {
    assert_eq!(classify_constraint(Npm, "latest"), ConstraintKind::Unbounded);
}

#[test]
fn npm_classify_git_branch_is_mutable_ref() {
    assert_eq!(
        classify_constraint(Npm, "git+https://github.com/acme/x.git#main"),
        ConstraintKind::GitRef { mutable: true }
    );
}

#[test]
fn npm_classify_git_commit_sha_is_immutable_ref() {
    let sha = "git+https://github.com/acme/x.git#0bc1a2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    assert_eq!(
        classify_constraint(Npm, sha),
        ConstraintKind::GitRef { mutable: false }
    );
}
```

`pypi_tests.rs` (classification section):

```rust
use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::{ConstraintKind, Ecosystem::PyPI};

#[test]
fn pypi_classify_exact_pin() {
    assert_eq!(classify_constraint(PyPI, "==2.3.3"), ConstraintKind::Exact);
}

#[test]
fn pypi_classify_bare_name_is_unbounded() {
    // A bare `requests` with no specifier accepts any version.
    assert_eq!(classify_constraint(PyPI, "requests"), ConstraintKind::Unbounded);
}

#[test]
fn pypi_classify_open_greater_equal_is_unbounded() {
    assert_eq!(classify_constraint(PyPI, ">=1.26"), ConstraintKind::Unbounded);
}

#[test]
fn pypi_classify_compatible_release_is_bounded_range() {
    assert_eq!(classify_constraint(PyPI, "~=2.3"), ConstraintKind::BoundedRange);
}

#[test]
fn pypi_classify_git_branch_is_mutable_ref() {
    assert_eq!(
        classify_constraint(PyPI, "git+https://github.com/acme/x.git@main"),
        ConstraintKind::GitRef { mutable: true }
    );
}
```

`maven_tests.rs` (classification section):

```rust
use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::{ConstraintKind, Ecosystem::Maven};

#[test]
fn maven_classify_hard_version_is_exact() {
    assert_eq!(classify_constraint(Maven, "32.1.3-jre"), ConstraintKind::Exact);
}

#[test]
fn maven_classify_version_range_is_bounded_range() {
    assert_eq!(classify_constraint(Maven, "[3.0,4.0)"), ConstraintKind::BoundedRange);
}

#[test]
fn maven_classify_latest_keyword_is_unbounded() {
    assert_eq!(classify_constraint(Maven, "LATEST"), ConstraintKind::Unbounded);
    assert_eq!(classify_constraint(Maven, "RELEASE"), ConstraintKind::Unbounded);
}

#[test]
fn maven_classify_snapshot_is_mutable() {
    assert_eq!(classify_constraint(Maven, "2.0-SNAPSHOT"), ConstraintKind::Mutable);
}

#[test]
fn gradle_classify_dynamic_plus_is_bounded_range() {
    assert_eq!(classify_constraint(Maven, "3.+"), ConstraintKind::BoundedRange);
}

#[test]
fn gradle_classify_latest_release_is_unbounded() {
    assert_eq!(classify_constraint(Maven, "latest.release"), ConstraintKind::Unbounded);
}
```

### 8.3 npm graph, findings, output — `npm_tests.rs` (Slice 3)

Slice 3 is the **full npm vertical**: parse → graph → findings → JSON → CLI. It is the deepest single slice; getting it green proves the whole pipeline shape before Python and Java reuse it.

Accessors used below (`id`, `is_direct`, `scope`, `version`, `depth`, `source_type`) are small real getters over the `pub(crate)` fields.

```rust
use super::common::{fixture, scan_fixture};
use crate::deps::model::{PackageId, Scope, SourceType};

// --- graph -------------------------------------------------------------------

#[test]
fn npm_graph_classifies_express_as_direct_production() {
    let inv = scan_fixture("node-app");
    let express = inv.node("express").expect("express node missing");
    assert!(express.is_direct(), "express is a direct dependency");
    assert_eq!(express.scope(), Scope::Production);
    assert_eq!(express.version(), Some("4.18.2"));
}

#[test]
fn npm_graph_classifies_qs_as_transitive() {
    let inv = scan_fixture("node-app");
    let qs = inv.node("qs").expect("qs node missing");
    assert!(!qs.is_direct(), "qs is pulled in transitively by express");
    assert!(qs.depth() >= 2, "qs sits at depth >= 2");
}

#[test]
fn npm_graph_classifies_jest_as_development_scope() {
    let inv = scan_fixture("node-app");
    assert_eq!(inv.node("jest").expect("jest node missing").scope(),
               Scope::Development);
}

#[test]
fn npm_graph_marks_git_dep_source_type() {
    let inv = scan_fixture("node-app");
    let git_dep = inv.node("internal-utils").expect("internal-utils node missing");
    assert_eq!(git_dep.source_type(), SourceType::GitBranch);
}

#[test]
fn npm_purl_identity_is_canonical() {
    let inv = scan_fixture("node-app");
    assert_eq!(*inv.node("lodash").unwrap().id(),
               PackageId("pkg:npm/lodash@4.17.21".into()));
}

// --- DEP003 / DEP004 / DEP005 / DEP008 (npm) --------------------------------

#[test]
fn npm_caret_direct_dep_is_dep003() {
    let inv = scan_fixture("node-app");
    assert!(!inv.findings_for("express").is_empty()
            && inv.findings_for("express").iter().any(|f| f.id == "DEP003"),
        "express `^4.18.2` is a direct bounded range — expected DEP003");
}

#[test]
fn npm_exact_dev_dep_has_no_pinning_finding() {
    // jest is exactly pinned (29.7.0) — the negative control for DEP003/DEP004.
    let inv = scan_fixture("node-app");
    assert!(inv.findings_for("jest").iter()
            .all(|f| f.id != "DEP003" && f.id != "DEP004"),
        "an exact pin must not raise a pinning finding");
}

#[test]
fn npm_wildcard_direct_dep_is_dep004_high() {
    use crate::deps::model::Severity;
    let inv = scan_fixture("node-app");
    let f = inv.findings_for("lodash").into_iter()
        .find(|f| f.id == "DEP004").expect("lodash `*` must raise DEP004");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn npm_latest_direct_dep_is_dep004() {
    let inv = scan_fixture("node-app");
    assert!(inv.findings_for("left-pad").iter().any(|f| f.id == "DEP004"),
        "left-pad `latest` must raise DEP004");
}

#[test]
fn npm_git_branch_dep_is_dep005() {
    use crate::deps::model::Severity;
    let inv = scan_fixture("node-app");
    let f = inv.findings_for("internal-utils").into_iter()
        .find(|f| f.id == "DEP005")
        .expect("internal-utils @ #main is a mutable git branch — expected DEP005");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn git_commit_sha_is_not_dep005() {
    // A git dependency pinned to a 40-char commit SHA is immutable — no finding.
    use crate::deps::ecosystems::classify_constraint;
    use crate::deps::model::{ConstraintKind, Ecosystem::Npm};
    let pinned = "git+https://github.com/acme/x.git#0bc1a2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    assert_eq!(classify_constraint(Npm, pinned),
               ConstraintKind::GitRef { mutable: false });
}

#[test]
fn npm_url_dep_without_checksum_is_dep006() {
    use crate::deps::ecosystems::classify_constraint;
    use crate::deps::model::{ConstraintKind, Ecosystem::Npm};
    assert_eq!(classify_constraint(Npm, "https://example.com/pkg/foo-1.0.0.tgz"),
               ConstraintKind::Url { checksum: false });
}

#[test]
fn npm_lock_entry_without_integrity_is_dep008() {
    let inv = scan_fixture("node-app");
    assert!(inv.findings_for("left-pad").iter().any(|f| f.id == "DEP008"),
        "left-pad lacks an integrity hash — expected DEP008");
}

#[test]
fn npm_lock_entry_with_integrity_no_dep008() {
    let inv = scan_fixture("node-app");
    for pkg in ["express", "qs", "lodash"] {
        assert!(inv.findings_for(pkg).iter().all(|f| f.id != "DEP008"),
            "{pkg} has an integrity hash — must not raise DEP008");
    }
}

// --- DEP002 stale lockfile (npm) --------------------------------------------

#[test]
fn node_manifest_dep_missing_from_lock_is_dep002() {
    use crate::deps::model::Severity;
    let inv = scan_fixture("node-stale");
    let f = inv.with_code("DEP002");
    assert!(!f.is_empty(), "manifest/lockfile drift must raise DEP002");
    assert_eq!(f[0].severity, Severity::High);
}

#[test]
fn node_app_lock_in_sync_no_dep002() {
    let inv = scan_fixture("node-app");
    assert!(inv.with_code("DEP002").is_empty(), "in-sync lockfile — no DEP002");
}
```

### 8.4 Manifest-vs-lockfile correctness — `correctness_tests.rs` (Slices 3–5)

The single most important correctness requirement (`PRD_DEPS.md` §7.1, §18 Risk 1). A transitive range that the lockfile resolves is **not** a finding; a direct range that the lockfile resolves is at most **Medium** and is marked `reproducible`.

```rust
use super::common::scan_fixture;
use crate::deps::model::Severity;

#[test]
fn node_locked_transitive_range_yields_no_finding() {       // Slice 3
    // qs is declared by express and resolved by package-lock.json.
    // It must NOT produce DEP003 or DEP004 — the install is reproducible.
    let inv = scan_fixture("node-app");
    assert!(
        inv.findings_for("qs").iter().all(|f| f.id != "DEP003" && f.id != "DEP004"),
        "locked transitive dependency must not raise a pinning finding, got: {:?}",
        inv.findings_for("qs").iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn node_direct_locked_range_is_medium_not_high() {           // Slice 3
    // express is `^4.18.2` (a range) but package-lock.json pins 4.18.2.
    // Policy may warn (DEP003 Medium) — it must NOT escalate to High.
    let inv = scan_fixture("node-app");
    let dep003 = inv.findings_for("express").into_iter()
        .find(|f| f.id == "DEP003")
        .expect("expected a DEP003 informational finding for express");
    assert_eq!(dep003.severity, Severity::Medium);
    assert!(dep003.reproducible, "lockfile resolves it — install is reproducible");
}

#[test]
fn pypi_locked_transitive_range_yields_no_finding() {        // Slice 4
    // urllib3 is declared as a range by requests and locked by poetry.lock.
    let inv = scan_fixture("python-poetry");
    assert!(inv.findings_for("urllib3").is_empty(),
        "locked transitive urllib3 must produce no findings");
}

#[test]
fn gradle_locked_dynamic_version_is_reproducible() {         // Slice 5
    // commons-lang3 `3.+` is dynamic but gradle.lockfile pins 3.14.0.
    let inv = scan_fixture("java-gradle");
    let dep003 = inv.findings_for("commons-lang3").into_iter()
        .find(|f| f.id == "DEP003")
        .expect("dynamic direct version should still warn (DEP003)");
    assert_eq!(dep003.severity, Severity::Medium);
    assert!(dep003.reproducible, "gradle.lockfile makes the install reproducible");
}
```

### 8.5 Lockfile health — DEP001 (`findings_tests.rs`, Slices 4–5)

DEP002/DEP008 live with their npm vertical (§8.3). DEP001 spans Python and Java:

```rust
use super::common::scan_fixture;
use crate::deps::model::Severity;

#[test]
fn pip_no_lockfile_is_dep001() {                             // Slice 4
    let inv = scan_fixture("python-pip-nolock");
    let f = inv.with_code("DEP001");
    assert!(!f.is_empty(), "requirements.txt with no lockfile must raise DEP001");
    assert_eq!(f[0].severity, Severity::High);
}

#[test]
fn poetry_lock_present_no_dep001() {                         // Slice 4
    assert!(scan_fixture("python-poetry").with_code("DEP001").is_empty(),
        "poetry.lock present — no DEP001");
}

#[test]
fn maven_no_lockfile_is_dep001() {                           // Slice 5
    // Maven has no first-class lockfile; this fixture has no BOM either.
    assert!(!scan_fixture("java-maven").with_code("DEP001").is_empty(),
        "maven project with no lockfile must raise DEP001");
}

#[test]
fn gradle_lock_present_no_dep001() {                         // Slice 5
    assert!(scan_fixture("java-gradle").with_code("DEP001").is_empty(),
        "gradle.lockfile present — no DEP001");
}
```

### 8.6 PyPI & Maven pinning / source — `pypi_tests.rs`, `maven_tests.rs` (Slices 4–5)

`pypi_tests.rs` (graph + findings section):

```rust
use super::common::scan_fixture;
use crate::deps::model::Scope;

#[test]
fn pypi_graph_classifies_pytest_as_development_scope() {
    assert_eq!(scan_fixture("python-poetry").node("pytest")
        .expect("pytest node missing").scope(), Scope::Development);
}

#[test]
fn pypi_graph_resolves_transitive_urllib3_version() {
    let inv = scan_fixture("python-poetry");
    let urllib3 = inv.node("urllib3").expect("urllib3 should be in the graph");
    assert!(!urllib3.is_direct(), "urllib3 is transitive (declared by requests)");
    assert_eq!(urllib3.version(), Some("2.0.7"));
}

#[test]
fn pypi_exact_pin_has_no_pinning_finding() {
    // flask==2.3.3 is the negative control.
    let inv = scan_fixture("python-pip-nolock");
    assert!(inv.findings_for("flask").iter()
            .all(|f| f.id != "DEP003" && f.id != "DEP004"),
        "flask==2.3.3 is exact — no pinning finding");
}

#[test]
fn pypi_bare_name_is_dep004() {
    assert!(scan_fixture("python-pip-nolock").findings_for("requests")
            .iter().any(|f| f.id == "DEP004"),
        "bare `requests` must raise DEP004");
}

#[test]
fn pypi_open_ended_range_is_dep004_high() {
    // §13 decision 2: unbounded `>=` / bare names are DEP004 High, like `*` / `latest`.
    use crate::deps::model::Severity;
    let inv = scan_fixture("python-pip-nolock");
    let f = inv.findings_for("urllib3").into_iter()
        .find(|f| f.id == "DEP004")
        .expect("open-ended `urllib3>=1.26` must raise DEP004");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn pypi_git_branch_dep_is_dep005() {
    assert!(scan_fixture("python-pip-nolock").findings_for("internal-lib")
            .iter().any(|f| f.id == "DEP005"),
        "internal-lib @ git+...@main is a mutable branch — expected DEP005");
}
```

`maven_tests.rs` (graph + findings section):

```rust
use super::common::scan_fixture;
use crate::deps::model::{PackageId, Severity};

#[test]
fn maven_graph_lists_all_direct_dependencies() {
    let inv = scan_fixture("java-maven");
    for name in ["guava", "commons-lang3", "slf4j-api", "internal-bom"] {
        let n = inv.node(name).unwrap_or_else(|| panic!("{name} node missing"));
        assert!(n.is_direct(), "{name} is declared directly in pom.xml");
    }
}

#[test]
fn maven_purl_identity_includes_group() {
    assert_eq!(*scan_fixture("java-gradle").node("guava").unwrap().id(),
        PackageId("pkg:maven/com.google.guava/guava@32.1.3-jre".into()));
}

#[test]
fn gradle_graph_resolves_dynamic_version_from_lockfile() {
    // build.gradle declares 3.+; gradle.lockfile pins 3.14.0.
    assert_eq!(scan_fixture("java-gradle").node("commons-lang3")
        .expect("commons-lang3 node missing").version(), Some("3.14.0"));
}

#[test]
fn maven_range_direct_dep_is_dep003() {
    assert!(scan_fixture("java-maven").findings_for("commons-lang3")
            .iter().any(|f| f.id == "DEP003"),
        "commons-lang3 `[3.0,4.0)` is a direct Maven range — expected DEP003");
}

#[test]
fn maven_exact_dep_has_no_pinning_finding() {
    // guava 32.1.3-jre is the negative control.
    assert!(scan_fixture("java-maven").findings_for("guava")
            .iter().all(|f| f.id != "DEP003" && f.id != "DEP004"),
        "guava is exactly pinned — no pinning finding");
}

#[test]
fn maven_latest_keyword_is_dep004() {
    let inv = scan_fixture("java-maven");
    let f = inv.findings_for("slf4j-api").into_iter()
        .find(|f| f.id == "DEP004").expect("slf4j-api `LATEST` must raise DEP004");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn maven_snapshot_is_dep021_high() {
    // §13 decision 1: Maven -SNAPSHOT is a mutable artifact version → DEP021 (High),
    // not DEP004 — the manifest names a coordinate, it is not an unbounded selector.
    let inv = scan_fixture("java-maven");
    let f = inv.findings_for("internal-bom").into_iter()
        .find(|f| f.id == "DEP021")
        .expect("2.0-SNAPSHOT must raise DEP021 (mutable artifact version)");
    assert_eq!(f.severity, Severity::High);
    assert!(f.recommendation.to_lowercase().contains("snapshot"),
        "recommendation should name the SNAPSHOT problem");
}
```

### 8.7 Policy — `policy_tests.rs` (Slice 5)

```rust
use super::common::{fixture, scan_fixture};
use crate::deps::{scan, policy::Policy};

#[test]
fn default_policy_fails_on_wildcard() {
    // The built-in default treats wildcard/latest as a hard finding (PRD §19).
    assert!(!scan_fixture("node-app").with_code("DEP004").is_empty(),
        "default policy must flag wildcard/latest dependencies");
}

#[test]
fn policy_from_yaml_parses_prd_example() {
    // The policy block from PRD_DEPS.md §6.6 must parse without error.
    let yaml = r#"
dependency_policy:
  require_lockfile: true
  fail_on_missing_lockfile: true
  fail_on_stale_lockfile: true
  direct_dependencies:
    fail_on_wildcard: true
    fail_on_latest: true
    warn_on_semver_range: true
    allow_exact_versions: true
  ci:
    fail_on_new_findings_only: true
    severity_threshold: high
"#;
    assert!(Policy::from_yaml(yaml).is_ok(), "the PRD example policy must parse");
}

#[test]
fn policy_disabling_rule_silences_finding() {
    // Negative control: with wildcard checks OFF, DEP004 must not fire.
    let yaml = r#"
dependency_policy:
  direct_dependencies:
    fail_on_wildcard: false
    fail_on_latest: false
"#;
    let policy = Policy::from_yaml(yaml).expect("policy parses");
    let inv = scan(&fixture("node-app"), &policy).expect("scan");
    assert!(inv.with_code("DEP004").is_empty(),
        "with wildcard checks disabled, DEP004 must not fire");
}
```

### 8.8 Explain — `explain_tests.rs` (Slice 6)

```rust
use super::common::scan_fixture;
use crate::deps::explain::explain;

#[test]
fn explain_transitive_shows_path() {
    let inv = scan_fixture("node-app");
    let e = explain(&inv.graph, "qs").expect("qs should be explainable");
    // Expected introduction path: root -> express@4.18.2 -> qs@6.11.0
    assert!(!e.direct, "qs is transitive");
    assert_eq!(e.depth, 2);
    let path = e.paths.first().expect("at least one dependency path");
    assert_eq!(path.first().map(|id| id.0.as_str()), Some("root"));
    assert!(path.iter().any(|id| id.name() == "express"),
        "the path must run through express");
    assert_eq!(path.last().map(|id| id.name()), Some("qs"));
}

#[test]
fn explain_unknown_package_is_none() {
    let inv = scan_fixture("node-app");
    assert!(explain(&inv.graph, "does-not-exist").is_none(),
        "explaining an absent package returns None");
}
```

Stub (`src/deps/explain.rs`):

```rust
use crate::deps::model::{DependencyGraph, PackageId};

#[derive(Debug)]
pub struct Explanation {
    pub package: PackageId,
    pub direct: bool,
    pub depth: u32,
    pub paths: Vec<Vec<PackageId>>,
}

pub fn explain(graph: &DependencyGraph, package: &str) -> Option<Explanation> {
    unimplemented!("deps::explain — PRD_DEPS_TESTING.md §8.8")
}
```

### 8.9 Diff — `diff_tests.rs` (Slice 6)

Graph-level diff, tested as a pure function on two in-memory graphs — no git, no fixtures. Nodes are built with the real `DependencyNode::new` constructor.

```rust
use crate::deps::diff::diff_graphs;
use crate::deps::model::{DependencyGraph, DependencyNode};

fn graph(nodes: Vec<DependencyNode>) -> DependencyGraph {
    DependencyGraph { nodes, edges: vec![] }
}

#[test]
fn diff_detects_added_removed_changed() {
    let base = graph(vec![
        DependencyNode::new_npm("lodash", "4.17.20"),
        DependencyNode::new_npm("request", "2.88.2"),
    ]);
    let head = graph(vec![
        DependencyNode::new_npm("lodash", "4.17.21"),
        DependencyNode::new_npm("axios", "1.8.2"),
    ]);
    let d = diff_graphs(&base, &head);
    assert!(d.added.iter().any(|n| n.name() == "axios"), "axios was added");
    assert!(d.removed.iter().any(|n| n.name() == "request"), "request was removed");
    assert!(
        d.changed.iter().any(|c| c.name == "lodash"
            && c.from == "4.17.20" && c.to == "4.17.21"),
        "lodash changed 4.17.20 -> 4.17.21"
    );
    assert!(d.added.iter().all(|n| n.name() != "lodash"),
        "a version bump is a change, not an add");
}
```

Stub (`src/deps/diff.rs`):

```rust
use crate::deps::model::{DependencyGraph, DependencyNode};

#[derive(Debug)]
pub struct VersionChange { pub name: String, pub from: String, pub to: String }

#[derive(Debug)]
pub struct GraphDiff {
    pub added: Vec<DependencyNode>,
    pub removed: Vec<DependencyNode>,
    pub changed: Vec<VersionChange>,
}

pub fn diff_graphs(base: &DependencyGraph, head: &DependencyGraph) -> GraphDiff {
    unimplemented!("deps::diff_graphs — PRD_DEPS_TESTING.md §8.9")
}
```

`DependencyNode::new_npm` is a real test-support constructor on the model — not a stub.

### 8.10 Output — `report_tests.rs` (Slices 3 & 6)

`report_json_*` lands in Slice 3 (npm vertical); SARIF and SBOM in Slice 6.

```rust
use super::common::scan_fixture;
use crate::deps::report::{to_json, to_sarif, to_cyclonedx};

#[test]
fn report_json_has_findings_and_graph() {                    // Slice 3
    let v = to_json(&scan_fixture("node-app"));
    assert!(v.get("nodes").and_then(|n| n.as_array()).is_some(),
        "JSON output carries the dependency graph nodes");
    assert!(v.get("findings").and_then(|f| f.as_array()).is_some(),
        "JSON output carries findings");
}

#[test]
fn report_sarif_has_rules_and_results() {                    // Slice 6
    let v = to_sarif(&scan_fixture("node-app"));
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "corgea-deps");
    let results = v["runs"][0]["results"].as_array().expect("results array");
    assert!(results.iter().any(|r| r["ruleId"] == "DEP004"),
        "SARIF results include the wildcard finding rule id");
}

#[test]
fn report_cyclonedx_has_components_and_deps() {              // Slice 6
    let v = to_cyclonedx(&scan_fixture("node-app").graph);
    assert_eq!(v["bomFormat"], "CycloneDX");
    let components = v["components"].as_array().expect("components array");
    assert!(components.iter().any(|c| c["purl"] == "pkg:npm/express@4.18.2"),
        "SBOM lists express as a component with its purl");
    assert!(v.get("dependencies").is_some(),
        "CycloneDX SBOM includes the dependency relationships");
}
```

Stub (`src/deps/report.rs`):

```rust
use serde_json::Value;
use crate::deps::{Inventory, model::DependencyGraph};

pub fn to_json(inv: &Inventory) -> Value {
    unimplemented!("deps::report::to_json — PRD_DEPS_TESTING.md §8.10")
}
pub fn to_sarif(inv: &Inventory) -> Value {
    unimplemented!("deps::report::to_sarif — PRD_DEPS_TESTING.md §8.10")
}
pub fn to_cyclonedx(graph: &DependencyGraph) -> Value {
    unimplemented!("deps::report::to_cyclonedx — PRD_DEPS_TESTING.md §8.10")
}
```

### 8.11 CLI integration — `tests/cli_deps.rs` (Slices 3–6)

These run the compiled binary. **Hermeticity is mandatory**: `Config::load()` (`src/config.rs:33`) creates `~/.corgea/` and writes `config.toml` on first run. Tests must redirect `HOME` to a throwaway directory so they never touch the developer's real config — and so they prove `corgea deps scan` works with no prior config and no token.

```rust
use std::process::Command;
use tempfile::TempDir;

/// A `corgea` invocation with HOME isolated to a fresh temp dir.
/// Returns the command and the TempDir guard (keep it alive for the call).
fn corgea_isolated() -> (Command, TempDir) {
    let home = TempDir::new().expect("temp HOME");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_corgea"));
    cmd.env("HOME", home.path())            // unix; dirs::home_dir() honors HOME
       .env("USERPROFILE", home.path())     // windows
       .env_remove("CORGEA_TOKEN")
       .env_remove("CORGEA_URL");
    (cmd, home)
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn cli_scan_runs_without_token_or_config() {
    // `deps scan` is local & offline — it must not require login.
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd.args(["deps", "scan", &fixture("python-poetry"),
                        "--out-format", "json"])
        .output().expect("failed to run corgea");
    assert!(out.status.success(),
        "clean local scan must succeed with no token; stderr: {}",
        String::from_utf8_lossy(&out.stderr));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(parsed.get("findings").is_some());
}

#[test]
fn cli_scan_does_not_write_outside_home() {
    // Hermeticity guard: a scan must not touch a real ~/.corgea.
    let (mut cmd, home) = corgea_isolated();
    cmd.args(["deps", "scan", &fixture("node-app")])
        .output().expect("failed to run corgea");
    // If anything was written, it lands under the temp HOME — never the real one.
    assert!(home.path().exists(), "temp HOME survives the run");
}

#[test]
fn cli_scan_fail_on_high_exits_one() {
    // node-app has High findings (DEP004, DEP005). --fail-on high must exit 1.
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd.args(["deps", "scan", &fixture("node-app"), "--fail-on", "high"])
        .output().expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(1),
        "High findings with --fail-on high must exit 1");
}

#[test]
fn cli_scan_clean_fixture_fail_on_high_exits_zero() {
    // Negative control: python-poetry has no High findings.
    let (mut cmd, _home) = corgea_isolated();
    let out = cmd.args(["deps", "scan", &fixture("python-poetry"),
                        "--fail-on", "high"])
        .output().expect("failed to run corgea");
    assert_eq!(out.status.code(), Some(0),
        "no High findings — --fail-on high must exit 0");
}

#[test]
fn cli_scan_out_file_writes_json() {
    let (mut cmd, home) = corgea_isolated();
    let out_file = home.path().join("deps.json");
    let out = cmd.args(["deps", "scan", &fixture("java-gradle"),
               "--out-format", "json", "--out-file", out_file.to_str().unwrap()])
        .output().expect("failed to run corgea");
    assert!(out.status.success(), "stderr: {}",
        String::from_utf8_lossy(&out.stderr));
    let written = std::fs::read_to_string(&out_file).expect("out-file should exist");
    let _: serde_json::Value =
        serde_json::from_str(&written).expect("out-file must contain valid JSON");
}
```

Before implementation these fail cleanly: clap rejects the unknown `deps` subcommand (exit 2) or `deps::run` panics (exit 101) — never the asserted 0/1.

### 8.12 Robustness & determinism — `robustness_tests.rs` (Slice 7)

`PRD_DEPS.md` §18 Risk 2 (ecosystem edge cases) and the determinism the JSON/SBOM contract depends on.

```rust
use super::common::{fixture, scan_fixture};
use crate::deps::{scan, policy::Policy};
use crate::deps::ecosystems::classify_constraint;
use crate::deps::model::Ecosystem;
use crate::deps::report::to_json;

// --- malformed input: error, never panic ------------------------------------

#[test]
fn robust_malformed_npm_lockfile_is_error_not_panic() {
    // bad-package-lock.json is invalid JSON. scan() must return Err, not panic
    // and not silently produce an empty graph.
    let dir = fixture("malformed");
    let result = scan(&dir, &Policy::default());
    assert!(result.is_err(), "a malformed lockfile must surface as an error");
}

#[test]
fn robust_truncated_poetry_lock_is_error_not_panic() {
    let result = std::panic::catch_unwind(|| {
        scan(&fixture("malformed"), &Policy::default())
    });
    assert!(result.is_ok(), "parsing a truncated lockfile must not panic");
}

#[test]
fn robust_classify_never_panics_on_adversarial_input() {
    // A bounded property check without a proptest dependency: classify must be
    // total over a corpus of hostile constraint strings.
    let corpus = [
        "", " ", "\t\n", "^", "~", ">=", "@", "git+", "#", "[", "[,]",
        "999999999999999999999999999999", "v1.2.3", "==", "*.*.*",
        "latest.latest", "-SNAPSHOT", "💥", "../../etc/passwd",
        &"a".repeat(10_000),
    ];
    for raw in corpus {
        for eco in [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Maven] {
            let _ = classify_constraint(eco, raw);   // must return, not panic
        }
    }
}

// --- determinism: the JSON/SBOM contract depends on it ----------------------

#[test]
fn robust_graph_order_deterministic() {
    let a = scan_fixture("node-app");
    let b = scan_fixture("node-app");
    let names = |inv: &crate::deps::Inventory| -> Vec<String> {
        inv.graph.nodes.iter().map(|n| n.id().0.clone()).collect()
    };
    assert_eq!(names(&a), names(&b),
        "graph node ordering must be deterministic across scans");
}

#[test]
fn robust_json_output_byte_stable() {
    let a = to_json(&scan_fixture("node-app")).to_string();
    let b = to_json(&scan_fixture("node-app")).to_string();
    assert_eq!(a, b, "JSON output must be byte-stable for identical input");
}

// --- monorepo / workspaces --------------------------------------------------

#[test]
fn robust_monorepo_detects_all_workspace_manifests() {
    let inv = scan_fixture("node-monorepo");
    use crate::deps::detect::DepFileKind::NpmManifest;
    let manifests = inv.detected_files.iter()
        .filter(|f| f.kind == NpmManifest).count();
    assert!(manifests >= 3, "root + 2 workspace manifests expected, got {manifests}");
}

// --- skip vendored directories (built at runtime — node_modules is gitignored)

#[test]
fn robust_scan_skips_node_modules() {
    use std::fs;
    let tmp = tempfile::TempDir::new().expect("temp dir");
    fs::write(tmp.path().join("package.json"),
        r#"{"name":"x","version":"1.0.0","dependencies":{}}"#).unwrap();
    let nested = tmp.path().join("node_modules/inner");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("package.json"),
        r#"{"name":"inner","version":"9.9.9"}"#).unwrap();

    let files = crate::deps::detect::detect_dependency_files(tmp.path());
    assert!(
        files.iter().all(|f| !f.path.components()
            .any(|c| c.as_os_str() == "node_modules")),
        "detection must not descend into node_modules"
    );
}
```

### 8.13 Vulnerability findings — `vuln_tests.rs` (Slice 8)

DEP010 stays in the MVP (§13 decision 7) behind a mocked source, so its tests are offline and deterministic. `scan()` itself stays vulnerability-free — enrichment is a separate, explicit step, which keeps the §8.12 determinism and offline guarantees intact.

Stub (`src/deps/vuln.rs`):

```rust
use std::path::Path;
use crate::deps::DepsError;
use crate::deps::findings::{Finding, FindingSource};
use crate::deps::model::DependencyGraph;

/// One advisory record from the offline fixture DB.
#[derive(Debug, Clone)]
pub struct Advisory {
    pub name: String,
    pub vulnerable_versions: Vec<String>,
    pub id: String,
    pub severity: String,
    pub summary: String,
}

/// A `FindingSource` backed by a static, offline advisory database.
pub struct VulnerabilitySource {
    advisories: Vec<Advisory>,
}

impl VulnerabilitySource {
    /// Load advisories from a `vuln-db.json` fixture. REAL — pure file + JSON read.
    pub fn from_json_file(path: &Path) -> Result<Self, DepsError> {
        unimplemented!("deps::vuln::VulnerabilitySource::from_json_file — §8.13")
    }
}

impl FindingSource for VulnerabilitySource {
    /// Emit a DEP010 finding for every graph node whose resolved version
    /// matches an advisory, carrying the introduction path.
    fn enrich(&self, graph: &DependencyGraph) -> Vec<Finding> {
        unimplemented!("deps::vuln::VulnerabilitySource::enrich — §8.13")
    }
}
```

Tests:

```rust
use super::common::{fixture, scan_fixture};
use crate::deps::findings::FindingSource;
use crate::deps::model::Severity;
use crate::deps::vuln::VulnerabilitySource;

fn vuln_source() -> VulnerabilitySource {
    VulnerabilitySource::from_json_file(&fixture("vuln-db.json"))
        .expect("vuln-db.json fixture must load")
}

#[test]
fn vuln_known_vulnerable_transitive_version_is_dep010() {
    // qs@6.11.0 is transitive in node-app and flagged by vuln-db.json.
    let inv = scan_fixture("node-app");
    let findings = vuln_source().enrich(&inv.graph);
    assert!(
        findings.iter().any(|f| f.id == "DEP010"
            && f.package.as_ref().is_some_and(|p| p.name() == "qs")),
        "a vulnerable transitive package must raise DEP010"
    );
}

#[test]
fn vuln_safe_version_is_not_dep010() {
    // express@4.18.2 and lodash@4.17.21 are absent from vuln-db.json — negative control.
    let inv = scan_fixture("node-app");
    let findings = vuln_source().enrich(&inv.graph);
    for safe in ["express", "lodash"] {
        assert!(
            findings.iter().all(|f|
                f.package.as_ref().map(|p| p.name()) != Some(safe)),
            "{safe} is not in the advisory DB — must not raise DEP010"
        );
    }
}

#[test]
fn vuln_dep010_severity_comes_from_advisory() {
    // DEP010 severity is the advisory's severity, not a fixed taxonomy default.
    let inv = scan_fixture("node-app");
    let f = vuln_source().enrich(&inv.graph).into_iter()
        .find(|f| f.id == "DEP010").expect("expected one DEP010");
    assert_eq!(f.severity, Severity::High, "vuln-db.json marks this advisory high");
}

#[test]
fn vuln_dep010_carries_dependency_path() {
    // The finding must show how the vulnerable package was introduced.
    let inv = scan_fixture("node-app");
    let f = vuln_source().enrich(&inv.graph).into_iter()
        .find(|f| f.id == "DEP010").expect("expected one DEP010");
    let path = f.paths.first().expect("DEP010 must carry an introduction path");
    assert_eq!(path.first().map(|id| id.0.as_str()), Some("root"));
    assert_eq!(path.last().map(|id| id.name()), Some("qs"));
}

#[test]
fn vuln_scan_without_source_yields_no_dep010() {
    // scan() is offline: with no source enrichment, DEP010 never appears.
    assert!(scan_fixture("node-app").with_code("DEP010").is_empty(),
        "scan() alone must not produce DEP010 — enrichment is explicit");
}

#[test]
fn vuln_clean_graph_yields_no_dep010() {
    // python-poetry has no package in vuln-db.json — whole-graph negative control.
    let inv = scan_fixture("python-poetry");
    assert!(vuln_source().enrich(&inv.graph).iter().all(|f| f.id != "DEP010"),
        "a graph with no advisory match must yield no DEP010");
}
```

---

## 9. Execution — vertical slices, not one red wall

### 9.1 Why slices

A single 52-test red batch is a legitimate *executable spec*, but it is not TDD and it loses the design feedback loop: you cannot tell whether the `findings` model is right until the `graph` model exists, so dozens of tests sit red for reasons unrelated to the code in front of you.

So the **document** is the full spec (§8), but the **work** ships as vertical slices. Each slice is one PR containing that slice's tests *and* the implementation that greens them. Within a slice you still write the test first, observe it red, then implement — classic red/green/refactor at slice granularity.

### 9.2 The slices

| Slice | Delivers | Tests (§) | Greens |
|---|---|---|---|
| **0** | Stub API (§5), all fixtures (§6), `common.rs`, CI job | — | compiles; nothing yet |
| **1** | `classify_constraint` for npm/PyPI/Maven | §8.2 (17) | constraint classification |
| **2** | `detect_dependency_files` | §8.1 (6) | file detection |
| **3** | **npm vertical** — manifest+lockfile parse, graph, findings (DEP002/003/004/005/006/008), `to_json`, CLI `scan` | §8.3, §8.4 (npm), §8.5 (none), §8.10 (json), §8.11 | npm end-to-end |
| **4** | **Python vertical** — pip/poetry parse, graph, DEP001, findings | §8.4 (pypi), §8.5 (pip/poetry), §8.6 (pypi) | Python end-to-end |
| **5** | **Java vertical** — pom/gradle parse, graph, DEP001, findings, `Policy` | §8.4 (gradle), §8.5 (maven/gradle), §8.6 (maven), §8.7 | Java end-to-end + policy |
| **6** | `explain`, `diff_graphs`, `to_sarif`, `to_cyclonedx`, CLI `graph`/`sbom` | §8.8, §8.9, §8.10 (sarif/sbom) | reporting & analysis |
| **7** | Robustness: malformed-input handling, determinism, monorepo, skip-vendored | §8.12 | hardening |
| **8** | **DEP010** — `VulnerabilitySource` (mocked) + `FindingSource` trait, graph enrichment, dependency-path attribution, `vuln-db.json` fixture | §8.13 (6) | vulnerability findings |

Slices 1–2 are pure functions (no I/O) — fastest wins, lowest risk, and they de-risk every later slice. Slice 3 is the deepest; once it is green the pipeline shape is proven and Slices 4–5 are largely "the same, another ecosystem".

### 9.3 CI handling

`.github/workflows/test.yml` runs `cargo test` on every push. All `deps` work lands on a `feat/deps` branch:

1. **`main` stays green.** It never sees a red `deps` test — `feat/deps` is not merged until every slice is green.
2. **`feat/deps` is green at every slice boundary.** A slice PR is merged into `feat/deps` only when its tests pass and no earlier slice regressed. Mid-slice, a developer's local `cargo test` is red — that is the point — but nothing red is merged, even to `feat/deps`.
3. **Optional visibility job.** A `deps-progress` CI job on `feat/deps` runs `cargo test deps` and reports the pass count as the public burndown.
4. **No `#[ignore]` ledger.** A test never carries `#[ignore]` to defer it; it simply lands in its slice's PR. This keeps the red signal honest.

### 9.4 Expected first run of a slice

When Slice 1's tests land (before its implementation), `cargo test deps` compiles and shows:

```text
test deps::tests::npm_tests::npm_classify_caret_is_bounded_range ... FAILED
  thread '...' panicked at src/deps/ecosystems/mod.rs:
  not implemented: deps::ecosystems::classify_constraint — PRD_DEPS_TESTING.md §8.2
```

The panic names `classify_constraint` — the function under test — not a constructor. That is the "fails for the right reason" check (§3.1).

---

## 10. Definition of done & PR checklist

A slice PR is mergeable into `feat/deps` only when:

- [ ] Each test it adds was committed **red first** — the PR description quotes the failing `cargo test` output, and the panic is in the *targeted* function, not a constructor.
- [ ] The slice's tests are now green.
- [ ] No earlier slice's test regressed (`cargo test` whole-crate).
- [ ] No test was weakened, deleted, or `#[ignore]`-d to pass.
- [ ] Every positive finding test has its paired negative test, both green.
- [ ] Any new decision-gated test (§3.4) asserts only the stable invariant until the policy question it depends on is resolved and recorded in §13.
- [ ] `cargo build --release` succeeds; `skills/corgea/SKILL.md` and `README.md` updated if the surface is user-visible (`cli/CLAUDE.md`).

`feat/deps` merges to `main` (GA per `PRD_DEPS.md` §17 Phase 3) when **all ~64 tests are green**. The §13 questions are resolved as of revision 3.

---

## 11. Coverage goals

- **Finding codes:** every MVP code (DEP001, DEP002, DEP003, DEP004, DEP005, DEP006, DEP008, DEP010, DEP021) has a green positive **and** negative test. DEP010 is exercised via a mocked `VulnerabilitySource` (§8.13); DEP016/DEP017 stay deferred behind the same trait seam (§5.3, §2.1).
- **Languages:** Python, Node.js, Java each exercise detection, classification, graph building, the manifest-vs-lockfile correctness rule, and ≥3 distinct finding codes.
- **Correctness rule:** `PRD_DEPS.md` §7.1 has a dedicated test per language (§8.4) — the regression guard for the §18 Risk 1 false-positive flood.
- **Robustness:** malformed input, determinism, monorepo, and vendored-dir skipping each have a test (§8.12).
- **Line/branch coverage** is a secondary signal: target ≥ 85% line coverage of `src/deps/` via `cargo llvm-cov`, but a green behavior test always outranks a coverage number.

---

## 12. Test-assertion strictness — what is pinned vs loose

Following the §14 review, assertions are tiered deliberately:

| Pinned exactly | Asserted loosely / not at all |
|---|---|
| Finding code presence & absence | Graph node / finding ordering — only its *determinism* is tested (§8.12), not a specific order |
| `direct` vs `transitive`, `scope` | Full JSON / SARIF / SBOM document shape — only required keys are checked |
| `reproducible` boolean | `recommendation` prose — only a keyword (e.g. "snapshot") where it carries meaning |
| Resolved version (from controlled fixtures) | — |
| `PackageId` / purl strings | — |
| Severity — every MVP code traces to an unambiguous `PRD_DEPS.md` §9 row (DEP001/002 High, DEP003 Medium, DEP004 High, DEP021 High); DEP010 severity comes from the advisory record | — |

Package matching uses the exact purl **name component** via `PackageId::name()` — never a substring `contains()`.

---

## 13. Resolved decisions

The seven open questions of revision 2 are resolved below. Each decision is binding on the slice it gates; the two formerly decision-gated tests (§3.4) are tightened to exact codes as of revision 3.

1. **SNAPSHOT taxonomy — RESOLVED: mint DEP021.** Maven `-SNAPSHOT` is not an unbounded *selector* (the manifest names a coordinate) — it is a mutable *artifact*, the DEP005 family, not DEP004. Filing it under DEP004 would make a SARIF rule titled "Wildcard or `latest` dependency" fire on `2.0-SNAPSHOT`. New taxonomy code **DEP021 "Mutable artifact version"** (High) is added to `PRD_DEPS.md` §9 and §10. `maven_snapshot_is_dep021_high` (§8.6) asserts `id == "DEP021"`. *Gates Slice 5.*
2. **Unbounded `>=` severity — RESOLVED: DEP004, High.** `PRD_DEPS.md` FR3 lists `>=`, `>`, "unbounded ranges" and "bare names" alongside `*` / `latest`; a lower bound blocks only downgrade, not the float-forward supply-chain risk. `ConstraintKind::Unbounded` already unifies `>=`, bare names, `*`, and `latest`, and §6.7 already rules `latest.release` is DEP004 High *even when locked* — treating `>=` differently would split one classification. `pypi_open_ended_range_is_dep004_high` (§8.6) asserts DEP004 + High. *Gates Slices 1 and 4.*
3. **DEP001 for a `==`-pinned `requirements.txt` — RESOLVED: stays High.** A `==`-pinned `requirements.txt` pins direct versions but not the transitive closure and carries no integrity hashes — it is not a lockfile. The pinning benefit is already credited elsewhere (no DEP003/DEP004 per `==` line). The real lockfile-equivalent is a `requirements.txt` with pip `--hash=` lines for every entry — that suppresses DEP001. No test change (the `python-pip-nolock` fixture is not fully pinned); the `--hash` substitute rule is specified now and gets its own fixture when Python coverage is extended. *Gates Slice 4.*
4. **Maven "no lockfile" stance — RESOLVED: a BOM is mitigating, not substituting.** A `dependencyManagement` / BOM pins only declared coordinates, not the full transitive closure, and carries no integrity hashes. DEP001 still fires for a BOM-only Maven project; a recognized BOM lowers it High→Medium with a recommendation that names the BOM. Exact BOM-severity wording is deferred until a BOM fixture lands; `java-maven` has no BOM, so `maven_no_lockfile_is_dep001` is unaffected. *Gates Slice 5.*
5. **`assert_cmd` dev-dependency — RESOLVED: no.** The ~5 CLI tests (§8.11) need hand-written `HOME` isolation regardless, and `CARGO_BIN_EXE_corgea` already supplies the binary path with zero deps. Plain `std::process::Command` stays. Revisit only if CLI tests exceed ~20. *Gates Slice 0.*
6. **YAML crate — RESOLVED: `serde_yaml_ng`, confirmed.** `serde_yaml` is archived; `serde_yaml_ng` is the conservative drop-in continuation. `serde_yml` is explicitly rejected (provenance / maintenance controversy). Verify its maintenance status is still current at adoption time (§4.3). *Gates Slice 0.*
7. **MVP scope — RESOLVED: keep DEP010, defer DEP016/DEP017 and the Go graph.** DEP010 ("vulnerable resolved package") is the center of gravity of an SCA tool; it stays in the MVP behind a **mocked vulnerability source** — new **Slice 8** (§8.13). DEP016 (license) and DEP017 (registry) remain deferred (config-heavy, secondary); Go keeps detection-only smoke coverage, with the full graph in Phase 2. §2.1 is updated accordingly. *Gates Slice 1 ordering and adds Slice 8.*

---

## 14. Design review record

Revision 2 incorporates a second-opinion review of revision 1. The substantive changes and why:

| Review finding | Change |
|---|---|
| `Policy::default()` was `unimplemented!()`, so `scan()` tests would panic in policy construction, not in the behavior under test | `Policy` has a **real** `Default` (§5.2). Stubs are now leaf-only (§3.1). |
| Revision 1 claimed "no new dependencies" but `Policy::from_yaml` needs YAML parsing, and the crate has no YAML parser | Added `serde_yaml_ng` as the one required new dependency (§4.3). |
| Package lookup by bare name is ambiguous across Maven groups and duplicate versions | Typed `PackageId` (purl) is the model identity; `node()` / `nodes_named()` / `node_by_id()` (§5.2). |
| §8 froze exact severities for cases §12 itself flagged as unresolved (SNAPSHOT, `>=`) | Decision-gated assertions (§3.4); those tests assert only the stable invariant. |
| One 52-test red batch loses the TDD design loop | Work re-sequenced into vertical slices (§9); the document stays the full spec. |
| CLI tests would touch the developer's real `~/.corgea/config.toml` | CLI tests isolate `HOME` to a temp dir and assert `deps scan` needs no token (§8.11). |
| No coverage for malformed input, determinism, monorepos, vendored-dir skipping | New robustness slice & tests (§6.8, §8.12, Slice 7). |
| `pub` froze the internal model | Model fields are `pub(crate)`; tests query via accessor methods (§5.2). |

---

## 15. Summary

This plan makes `PRD_DEPS.md` executable. It defines:

- a **narrow stub API** (§5) — real constructors, `unimplemented!()` only on the leaf behavior a test targets — so tests fail at the function under test;
- **typed `PackageId`** identity, so findings and graph queries are unambiguous;
- **eight fixture projects** across Python, Node.js, and Java (§6), each chosen so every MVP finding fires somewhere and stays silent somewhere else;
- **~64 tests** (§8) traceable to specific PRD requirements (§7), with positive/negative pairs across eight vertical slices, including DEP010 behind a mocked vulnerability source;
- a **vertical-slice sequence** (§9) that preserves the red→green→refactor loop, keeps `main` green, and de-risks the deepest work early.

The contract is unchanged: **the test is written first, observed failing, and the feature is "done" only when its test — and no test it should not have touched — is green.**
