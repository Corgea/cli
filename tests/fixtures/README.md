# Dependency scan fixtures (`tests/fixtures/`)

Offline fixture projects for `corgea deps` unit and CLI tests per `docs/PRD_DEPS_TESTING.md` §4.2.

- Pins are **intentional** — do not bump versions without updating advisory-backed tests.
- Used by `cargo test deps` and `tests/cli_deps.rs` (hermetic `HOME`, no network).
- Dogfood fixtures for freshness/CVE live under `fixtures/deps/` and use `corgea deps verify`.

| Directory | Role |
|-----------|------|
| `node-app` | npm graph + DEP003/004/005/008 |
| `node-stale` | DEP002 stale lockfile |
| `node-transitive` | npm generic transitive edges + scoped package names |
| `node-yarn` / `node-pnpm` | unsupported npm-family lockfiles |
| `node-monorepo` | workspace detection |
| `python-poetry` | Poetry lock + transitive urllib3 |
| `python-poetry-multi` | Poetry dependency tables for multiple parents |
| `python-pip-nolock` | DEP001 + requirements.txt |
| `python-uv-requirements` | `uv.lock` does not suppress requirements scanning |
| `java-maven` / `java-gradle` | Maven/Gradle parsers |
| `go-mod-smoke` | detection only |
| `malformed/` | graceful parse errors |
| `vuln-db.json` | mock DEP010 advisories |
