# PRD V0: `corgea deps` (npm)

**Status:** Build spec · **Scope:** npm only · **Parent:** PRD_DEPS_CONDENSED.md

## What V0 is

V0 is the smallest slice of `corgea deps` that proves the wedge: Corgea can tell a developer why a dependency exists, whether it can drift, and whether it matters. It ships inside the existing Corgea CLI.

V0 is not the product in PRD_DEPS_CONDENSED.md. It builds the load-bearing 10 percent, the dependency graph and the `explain` command. Everything else waits for evidence that this slice gets used.

## The one goal

Prove that developers trust the findings and come back to `explain`. If they do, build the rest. If they do not, fix trust before adding scope.

## Build scope

**1. npm only.** Parse `package.json` and `package-lock.json`. One ecosystem, one clean lockfile model. Confirm npm is right with the first design partners. If they run mostly Python, start there instead. Pick one.

**2. Dependency graph.** Build nodes (packages) and edges (relationships) from the manifest and lockfile. Model declared intent and resolved reality separately (see Correctness). Preserve full paths, not flat lists. Each node carries name, version, purl, direct or transitive, scope, and source type.

**3. `corgea deps scan`.** Detect npm files, build the graph, report the four findings below. Terminal table by default.

**4. `corgea deps explain <package>`.** The signature command. Show identity, direct or transitive, scope, the full path (`root > express@4.18.2 > qs@6.11.0`), declared constraint against resolved version, source file, and lockfile entry.

**5. Output and upload.** Terminal table, JSON (`--out-format json`, `--out-file`), and `--upload` to Corgea so org-level inventory has data.

## Findings

Four deterministic findings. No network, no vuln database, near-zero false positives.

| Code | Finding | Severity |
|---|---|---|
| DEP001 | Missing lockfile | High |
| DEP002 | Stale lockfile (manifest changed after lockfile) | High |
| DEP004 | Wildcard or `latest` direct dependency | High |
| DEP005 | Mutable Git branch dependency | High |

Every finding states the source file, the reason, and the exact fix.

## Correctness model

The load-bearing engineering. Model three layers:

- **Declared intent.** What the manifest allows (`"axios": "^1.8.0"`).
- **Resolved reality.** What the lockfile installed (`axios 1.8.2`).
- **Effective risk.** A range plus a committed lockfile is reproducible. Never report it as a missing lockfile.

A transitive package with a broad range that the lockfile resolves is not a finding. Flag a range only when no lockfile resolves it. Get this wrong and developers uninstall the tool.

## Out of scope for V0

Cut and deferred: `diff`, `sbom`, `policy init`, `fix`, exceptions, SARIF and HTML output, Go, Java, Python and other ecosystems, the vulnerable-package finding (Corgea SCA already covers it), license and registry findings, and the platform UI buildout.

## Success criteria

- Of developers who run `deps scan` once, the share who run it again within 7 days.
- Of developers who hit a finding, the share who fix it.
- `explain` invocations per active user.

Vanity counts (repos scanned, SBOMs generated) do not apply to V0.

## Open questions blocking V0

1. npm or Python first? Decide with the first three design partners.
2. Stale-lockfile detection: compare file mtimes, git history, or a manifest hash recorded in the lockfile?
3. Does `--upload` reuse the existing CLI scan-upload path, or need a new endpoint?
