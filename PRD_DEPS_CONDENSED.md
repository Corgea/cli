# PRD: Corgea Dependency Inventory & Supply-Chain Policy

**Area:** Corgea CLI · SCA / dependency scanning · **CLI namespace:** `corgea deps` · **Status:** Draft · **Users:** Developers, AppSec, platform, compliance

## 1. Summary

Corgea should do more than report vulnerable dependencies. It should explain what dependency exists, why it exists, whether it can drift, whether it violates policy, whether it is reachable, and what the smallest safe fix is.

Build a dependency-inventory and supply-chain-policy layer on the existing Corgea CLI. It scans manifests and lockfiles, builds a normalized dependency graph, classifies hygiene and reproducibility issues, flags vulnerable and policy-violating packages, and traces how each package entered the project. Inventory snapshots upload to Corgea for org-wide visibility.

The wedge is not "we find vulnerable dependencies." Many tools do that. The wedge is this: Corgea tells you why a dependency exists, whether it can drift, whether it matters, and how to fix it without drowning developers in noise.

## 2. Problem

Modern apps carry large dependency trees. Teams know a vulnerable package exists somewhere, but they cannot cheaply answer: where is it used, why is it present, direct or transitive, is the install reproducible, is the lockfile stale, is the code reachable, did this PR introduce it, what is the smallest fix.

Existing scanners over-index on CVEs and under-index on dependency governance. They miss missing lockfiles, unpinned direct deps, wildcard versions, mutable Git refs, unchecksummed URLs, stale lockfiles, drift, unknown registries, license violations, and dev deps leaking to production.

Precision makes or breaks this product. A transitive package may declare a broad range while the lockfile still resolves it to a concrete version. That install is reproducible, not non-deterministic. The product must distinguish *unpinned, broad, mutable, unresolved, resolved, locked, stale, vulnerable, reachable, non-reproducible,* and *policy-violating*. Conflating these destroys developer trust.

## 3. Goals & non-goals

**Goals.** Build an accurate inventory and direct/transitive graph per project. Detect missing, stale, and incomplete lockfiles. Flag unsafe direct deps (unpinned, broad, mutable). Explain dependency paths developers can act on. Detect new risk introduced by PRs. Support policy-as-code. Emit CI-friendly output (JSON, SARIF, SBOM). Upload snapshots. Reuse Corgea's existing SCA, reachability, dead-package, and remediation signals.

**Non-goals (v1).** Malware detection, runtime agent, container-image inventory, artifact reverse engineering, automated major-version upgrades, AI replacement recommendations, day-one org-wide multi-language enforcement, perfect reachability everywhere, rich terminal graph visualization. The MVP must be accurate, narrow, and trusted.

## 4. Solution

Five promises: **Inventory** (what we have), **Provenance** (where it came from), **Reproducibility** (can it drift), **Risk** (vulnerable, reachable, or policy-violating), **Remediation** (smallest safe fix).

Core commands:

```
corgea deps scan          inventory + policy scan
corgea deps explain <pkg> why a package exists (signature workflow)
corgea deps diff --base   dependency changes vs a git ref
corgea deps sbom          CycloneDX / SPDX export
corgea deps policy init   starter policy file
corgea deps fix           suggest / apply safe remediations
```

`explain` is the signature workflow. It shows identity, direct or transitive, scope, the full path (`root > express@4.18.2 > qs@6.11.0`), declared constraint against resolved version, source file, lockfile entry, policy and vuln and reachability status, and the fix. The best dependency tools answer one question: why is this here?

Output reuses Corgea's existing CLI model (`--out-format json|sarif|html|table`, `--out-file`). CI mode runs `corgea deps scan --changed --fail-on high`. It blocks on new risk, not inherited backlog.

## 5. Core correctness behavior

Model three layers separately:

- **Declared intent.** What the manifest allows (`"axios": "^1.8.0"`).
- **Resolved reality.** What the lockfile installed (`axios 1.8.2`).
- **Effective risk.** A range plus a committed lockfile is reproducible. Policy may warn, but it must never treat this as a missing lockfile.

Bad finding: *"axios is unpinned and vulnerable."* Good finding: *"axios uses a semver range in package.json; package-lock.json resolves 1.8.2. Policy warning only. The build stays reproducible."*

Each node carries ecosystem, version, purl, direct or transitive, scope (prod, dev, optional, peer), and source type (registry, private, git commit/tag/branch, local path, URL, workspace, vendored, unknown). The scanner preserves dependency paths instead of flattening them. Lockfile health detects missing, stale, uncommitted, manifest mismatch, missing integrity hashes, conflicting lockfiles, package-manager mismatch, and workspace gaps.

## 6. MVP scope

- **Commands:** `scan`, `explain`, `diff`, `policy init`, `sbom`
- **Ecosystems:** npm/yarn/pnpm, Python (requirements/Poetry/uv), Go modules, Maven/Gradle
- **Outputs:** terminal table, JSON, SARIF, CycloneDX SBOM, Corgea upload

**Findings to ship first:**

| Code | Finding | Severity |
|---|---|---|
| DEP001 | Missing lockfile | High |
| DEP002 | Stale lockfile | High |
| DEP003 | Direct dep uses broad range | Medium |
| DEP004 | Wildcard or `latest` dependency | High |
| DEP005 | Mutable Git branch dependency | High |
| DEP006 | URL/tarball dep without checksum | High |
| DEP008 | Lockfile integrity hash missing | Medium |
| DEP010 | Vulnerable resolved package | From vuln |
| DEP016 | License policy violation | High |
| DEP017 | Unapproved registry | High |
| DEP021 | Mutable artifact version (Maven SNAPSHOT) | High |

The full taxonomy (DEP001 to DEP021) also covers deprecated and abandoned packages, duplicate versions, dev-in-prod leakage, source-change detection, and expired exceptions.

**Default policy posture.** Require lockfiles. Fail on wildcard, `latest`, and mutable sources. Warn on semver ranges. Allow transitive ranges when the lockfile resolves them. Fail on new critical and high *reachable* vulnerabilities. Set `fail_on_new_findings_only: true`. This avoids the biggest product mistake: blocking builds for harmless, already-locked transitive declarations.

## 7. Risks & mitigations

**False positives.** Flagging every transitive range erodes trust. Mitigation: flag transitive ranges only when they are unresolved, unlocked, vulnerable, or mutable; gate CI on new findings only.

**Ecosystem edge cases.** Parsers break on real lockfiles and monorepos. Mitigation: start with fewer ecosystems, build strong test fixtures, use package-manager-native commands where needed, label unsupported files.

**Slow CI.** Builds get slower and teams disable scanning. Mitigation: hash and cache manifests and lockfiles, support changed-only mode, skip network calls unless opted in.

**Overlap with existing SCA.** Users cannot tell what this product is. Mitigation: position it as the graph, inventory, and policy layer. SCA vulnerabilities are one enrichment source, not the product.

## 8. Launch plan

**Alpha.** Internal users and design partners. npm and Python, local CLI, JSON output, basic findings plus `explain`. Exit: accurate graphs, low false-positive rate, output developers understand.

**Beta.** Selected customers, AppSec teams, CI users. SARIF, upload, policy-as-code, `diff`, SBOM, Go and Java. Exit: reliable CI integration, trusted diffs, useful platform inventory.

**GA.** All customers. Multi-ecosystem, dashboard, org-wide search, exceptions, reachability enrichment, remediation guidance. Exit: stable output schema, broad coverage, low support burden, clear ROI.

## 9. Open questions

1. Exact pinning for all direct deps, or only deployable apps? Different default policy for libraries and applications?
2. Invoke native package-manager commands, or parse lockfiles only?
3. How should the tool handle lockfiles that teams intentionally do not commit?
4. SBOM default: CycloneDX or SPDX?
5. Exception approval: repo-only, org-level, or both?
6. Is reachability required for CI gating, or used only for prioritization?

## 10. Success metrics

Adoption: repos scanned, active orgs, percent of scans uploaded, CI integrations. Quality: false-positive rate, percent of findings with a dependency path and a recommended fix, scan success rate by ecosystem. Security impact: missing and stale lockfiles reduced, reachable critical vulns reduced, mean time to remediate dependency findings. Developer experience: average scan time, percent of PRs blocked, percent of blocked PRs resolved without AppSec intervention.
