# PRD: Corgea Dependency Inventory & Supply Chain Policy

**Product area:** Corgea CLI / SCA / Dependency Scanning
**Working name:** Corgea Dependency Inventory
**Proposed CLI namespace:** `corgea deps`
**Status:** Draft PRD
**Primary users:** Developers, AppSec engineers, platform engineers, compliance/security teams
**Core thesis:** Corgea should not only report vulnerable dependencies. It should explain **what dependency exists, why it exists, whether it is reproducible, whether it violates policy, whether it is reachable, and what the smallest safe fix is**.

This PRD assumes Corgea already supports CLI scanning, exported scan results in `html`, `json`, and `SARIF`, and SCA/dependency-scanning capabilities with reachability and dead-package analysis. The CLI docs currently describe `--out-format` and `--out-file` support for scan reports, while Corgea’s dependency-scanning product page describes ecosystem coverage, reachability, dead-package analysis, and upgrade prioritization. ([Corgea Documentation][1])

---

## 1. Summary

We want to build a dependency inventory and supply-chain policy tool on top of the existing Corgea CLI.

The tool scans package manifests and lockfiles, builds a normalized dependency graph, identifies dependency hygiene issues, detects reproducibility gaps, flags vulnerable or policy-violating dependencies, and explains exactly how each package entered the project.

The initial user-facing product should live under:

```bash
corgea deps
```

The most important commands:

```bash
corgea deps scan
corgea deps graph
corgea deps explain <package>
corgea deps diff --base origin/main
corgea deps sbom --format cyclonedx
corgea deps policy init
corgea deps fix
```

The MVP should focus on:

1. Detecting manifests and lockfiles.
2. Building dependency graphs.
3. Separating declared intent from resolved reality.
4. Flagging non-reproducible installs.
5. Detecting direct unpinned/broad/mutable dependencies.
6. Identifying lockfile drift.
7. Explaining dependency paths.
8. Producing JSON/SARIF/SBOM output.
9. Uploading inventory snapshots to Corgea for organization-level visibility.

---

## 2. Problem

Modern applications depend on large dependency trees. Security teams often know that a vulnerable package exists somewhere, but they struggle to answer basic questions:

```text
Where is this dependency used?
Why is it present?
Is it direct or transitive?
Is the installed version reproducible?
Is the lockfile stale?
Is the vulnerable code reachable?
Which team owns it?
Did this PR introduce it?
What is the smallest safe fix?
```

Existing dependency scanners often over-focus on CVEs and under-focus on dependency governance. This creates alert fatigue and misses a broader category of supply-chain risk:

```text
missing lockfiles
unpinned direct dependencies
wildcard versions
mutable Git dependencies
URL/tarball dependencies without checksums
stale lockfiles
dependency drift
unknown registries
duplicate vulnerable packages
license violations
abandoned packages
dev dependencies leaking into production
```

The user’s original concern is valid: unpinned dependencies can create hidden risk. But the tool must be precise. A nested dependency may declare a broad range, while the project lockfile still resolves it to a concrete version. That is not the same as an actually non-deterministic install.

The product should distinguish:

```text
unpinned
broad
mutable
unresolved
resolved
locked
stale
vulnerable
reachable
non-reproducible
policy-violating
```

That distinction is critical for developer trust.

---

## 3. Goals

### Product goals

1. Create an accurate dependency inventory for every scanned project.
2. Build direct and transitive dependency graphs from manifests and lockfiles.
3. Detect missing, stale, or incomplete lockfiles.
4. Flag direct dependencies that are unpinned, overly broad, mutable, or unsafe.
5. Explain dependency paths in a way developers can act on.
6. Detect new dependency risk introduced by pull requests.
7. Support policy-as-code for dependency governance.
8. Export dependency findings in developer- and CI-friendly formats.
9. Upload dependency graph snapshots to Corgea for organization-wide visibility.
10. Integrate with Corgea’s existing SCA, reachability, dead-package, and remediation workflows.

### User goals

Developers should be able to answer:

```text
What changed in this PR?
What dependency introduced this vulnerable package?
Is this finding real or just a transitive declaration?
How do I fix it?
Will this block my build?
```

Security teams should be able to answer:

```text
Which repos have missing lockfiles?
Where do we use this package?
Which services are affected by this CVE?
Which dependency risks were introduced this week?
Which projects violate dependency policy?
Which teams own the riskiest graphs?
```

Compliance teams should be able to answer:

```text
Can we produce an SBOM for this release?
Which packages existed at this release commit?
Are there license violations?
Can we prove we reviewed/accepted exceptions?
```

---

## 4. Non-goals

For the MVP, this should **not** try to solve every supply-chain problem.

Out of scope for v1:

1. Full package malware detection.
2. Runtime production agent.
3. Container image dependency inventory.
4. Binary/package artifact reverse engineering.
5. Fully automated major-version upgrades.
6. AI-generated dependency replacement recommendations.
7. Enforcing org-wide policy across every language from day one.
8. Perfect reachability analysis for every ecosystem.
9. Dependency graph visualization in the terminal beyond simple tree/path output.
10. Complete support for every package manager edge case.

The MVP should be accurate, narrow, and trusted.

---

## 5. Personas

### 5.1 Developer

Wants fast feedback during local development and pull requests.

Primary needs:

```text
What did I introduce?
Will CI fail?
How do I fix it?
Is this really my dependency?
```

### 5.2 AppSec engineer

Owns dependency risk across many repositories.

Primary needs:

```text
Where is package X?
Which findings are reachable?
Which findings are new?
Which services are not reproducible?
Which teams need action?
```

### 5.3 Platform engineer

Maintains CI/CD, package manager conventions, and build reproducibility.

Primary needs:

```text
Do repos have lockfiles?
Are package manager versions pinned?
Are installs deterministic?
Are private registries enforced?
```

### 5.4 Compliance / audit user

Needs evidence for releases, audits, and customer security reviews.

Primary needs:

```text
Generate SBOM.
Show historical inventory.
Show license policy.
Show exceptions.
Show remediation status.
```

---

## 6. User experience

## 6.1 Local scan

Command:

```bash
corgea deps scan
```

Example output:

```text
Corgea dependency inventory

Detected:
  package.json              npm manifest
  package-lock.json         npm lockfile
  requirements.txt          pip requirements
  constraints.txt           pip constraints

Inventory:
  182 packages
  24 direct
  158 transitive
  129 production
  53 development

Policy findings:
  2 high
  5 medium
  11 low

High findings:
  DEP001  Missing lockfile for services/api/requirements.txt
          Install may resolve different transitive versions over time.
          Fix: generate a lockfile or compiled constraints file.

  DEP005  Mutable Git dependency
          internal-utils @ git+ssh://git.example.com/internal-utils.git@main
          Fix: pin to a commit SHA or immutable release tag.

Next:
  corgea deps explain internal-utils
  corgea deps diff --base origin/main
  corgea deps fix --interactive
```

Recommendation: keep local output concise. Developers should see the highest-impact issues first, then commands for deeper investigation.

---

## 6.2 Explain a dependency

Command:

```bash
corgea deps explain qs
```

Example output:

```text
qs@6.11.0

Ecosystem:
  npm

Scope:
  production

Type:
  transitive

Depth:
  2

Introduced by:
  root -> express@4.18.2 -> qs@6.11.0

Declared by parent:
  express@4.18.2 declares qs: "6.11.0"

Resolved by:
  package-lock.json

Status:
  locked
  reproducible
  no known reachable vulnerability
  no policy violation
```

This should become one of the signature workflows.

The best dependency tools answer: **“Why is this here?”**

---

## 6.3 Pull request diff

Command:

```bash
corgea deps diff --base origin/main
```

Example output:

```text
Dependency diff against origin/main

Added:
  + npm:axios@1.8.2 direct production
  + npm:form-data@4.0.1 transitive production via axios

Changed:
  ~ npm:lodash 4.17.20 -> 4.17.21

Removed:
  - npm:request@2.88.2

New policy findings:
  HIGH   DEP003  axios declared as "^1.8.0"
  MED    DEP014  3 versions of debug now present

New vulnerability findings:
  none
```

Recommendation: CI should primarily block on **new risk**, not inherited historical backlog.

---

## 6.4 CI mode

Command:

```bash
corgea deps scan --changed --fail-on high --out-format sarif --out-file deps.sarif
```

Expected behavior:

```text
pass if no new blocking findings
fail if new high/critical dependency policy violations are introduced
emit SARIF for code scanning integrations
emit JSON for Corgea ingestion and automation
```

Corgea’s existing CLI already supports scan export formats including JSON, HTML, and SARIF, so this feature should reuse that output model where possible. ([Corgea Documentation][1])

---

## 6.5 SBOM export

Command:

```bash
corgea deps sbom --format cyclonedx --out sbom.json
```

Expected behavior:

```text
generate a dependency inventory for the current repo/commit/release
include direct and transitive components
include dependency relationships
include package versions, package URLs, licenses, and vulnerability metadata where available
```

This is important for release workflows, customer security questionnaires, and audit readiness.

---

## 6.6 Policy initialization

Command:

```bash
corgea deps policy init
```

Example generated file:

```yaml
dependency_policy:
  require_lockfile: true
  fail_on_missing_lockfile: true
  fail_on_stale_lockfile: true

  direct_dependencies:
    fail_on_wildcard: true
    fail_on_latest: true
    warn_on_semver_range: true
    allow_exact_versions: true

  transitive_dependencies:
    allow_ranges_if_lockfile_resolves: true
    fail_if_unresolved: true

  sources:
    fail_on_mutable_git_refs: true
    fail_on_url_without_checksum: true
    allowed_registries:
      npm:
        - https://registry.npmjs.org/
      pypi:
        - https://pypi.org/simple/

  vulnerabilities:
    fail_on_critical_reachable: true
    fail_on_high_reachable: true
    warn_on_unreachable: true

  licenses:
    blocked:
      - AGPL-3.0
      - GPL-3.0

  ci:
    fail_on_new_findings_only: true
    severity_threshold: high
```

---

## 7. Core product behavior

## 7.1 Manifest vs lockfile distinction

The tool must separately model:

### Declared intent

What the manifest allows:

```json
"axios": "^1.8.0"
```

### Resolved reality

What the lockfile installed:

```json
"axios": "1.8.2"
```

### Effective risk

What this means:

```text
Manifest uses range.
Lockfile resolves exact version.
Install is reproducible as long as lockfile is committed and honored.
Policy may warn, but should not treat this as equivalent to missing lockfile.
```

This is the most important correctness requirement.

Bad finding:

```text
axios is unpinned and vulnerable.
```

Better finding:

```text
axios uses a semver range in package.json, but package-lock.json resolves it to 1.8.2.
Policy warning only. Build remains reproducible.
```

---

## 7.2 Direct vs transitive classification

Each dependency must be classified as:

```text
direct production
direct development
direct optional
direct peer
transitive production
transitive development
transitive optional
transitive peer
```

The scanner should preserve dependency paths, not just flat package lists.

Example:

```text
root -> express@4.18.2 -> body-parser@1.20.1 -> qs@6.11.0
```

This path should be available in CLI, JSON, SARIF metadata, and Corgea UI.

---

## 7.3 Package source classification

Every package node should have a source type:

```text
registry
private registry
git commit
git tag
git branch
git ref
local path
remote tarball
URL
workspace
vendored
unknown
```

High-risk source types:

```text
mutable git branch
remote URL without checksum
local path in release artifact
unapproved registry
unknown registry
package source mismatch
```

---

## 7.4 Lockfile health

The scanner should detect:

```text
missing lockfile
stale lockfile
lockfile not committed
manifest-lockfile mismatch
lockfile missing integrity hashes
multiple conflicting lockfiles
package manager mismatch
unsupported lockfile version
workspace lockfile not covering all manifests
```

Example finding:

```text
DEP002 Stale lockfile

package.json was modified after package-lock.json.
The manifest declares axios@^1.8.0, but package-lock.json does not contain axios.

Fix:
  npm install
  commit updated package-lock.json
```

---

## 7.5 Vulnerability and reachability enrichment

The dependency graph should be enriched with:

```text
known vulnerability IDs
affected version range
fixed version
severity
EPSS / exploitability signal if available
reachable / unreachable / unknown
dead package status
dependency path
recommended fix
```

Corgea already markets dependency scanning with AI reachability, dead-package analysis, function-level reachability, and upgrade prioritization; this feature should make those signals visible inside the inventory and policy workflows. ([Corgea][2])

---

## 8. Requirements

## 8.1 Functional requirements

### FR1: Detect dependency files

The CLI must recursively detect supported dependency files.

MVP file types:

```text
JavaScript / TypeScript:
  package.json
  package-lock.json
  yarn.lock
  pnpm-lock.yaml

Python:
  requirements.txt
  constraints.txt
  pyproject.toml
  poetry.lock
  uv.lock

Go:
  go.mod
  go.sum

Rust:
  Cargo.toml
  Cargo.lock

Ruby:
  Gemfile
  Gemfile.lock

Java:
  pom.xml
  build.gradle
  gradle.lockfile
```

Nice-to-have later:

```text
composer.json / composer.lock
packages.lock.json
Pipfile.lock
bun.lock
conda-lock.yml
mix.lock
rebar.lock
```

---

### FR2: Build dependency graph

The CLI must build a graph with:

```text
nodes = packages
edges = dependency relationships
root nodes = project manifests/workspaces
metadata = version, scope, source, file, line where possible
```

Each node should include:

```json
{
  "name": "axios",
  "ecosystem": "npm",
  "version": "1.8.2",
  "purl": "pkg:npm/axios@1.8.2",
  "direct": true,
  "scope": "production",
  "source_type": "registry",
  "manifest_file": "package.json",
  "lockfile": "package-lock.json"
}
```

---

### FR3: Identify direct unpinned dependencies

The scanner must flag direct dependencies using:

```text
*
latest
x
>=
>
unbounded ranges
bare names
mutable refs
branch refs
URL dependencies without checksum
```

Examples:

```text
npm:
  "lodash": "*"
  "axios": "latest"
  "react": ">=18"
  "express": "^4.18.0"

Python:
  requests
  requests>=2.31.0
  package @ git+https://example.com/repo.git@main
```

Important: severity depends on policy and lockfile context.

---

### FR4: Classify transitive ranges accurately

The scanner must not blindly flag every transitive package declaration as a blocking issue.

Classification:

```text
transitive range + resolved by lockfile = informational or no finding
transitive range + no lockfile = warning/high depending on deployability
transitive vulnerable resolved version = vulnerability finding
transitive package from mutable source = policy finding
```

---

### FR5: Detect lockfile drift

The scanner must detect when:

```text
manifest has changed but lockfile has not
manifest dependency is missing from lockfile
lockfile has package no longer declared or reachable
lockfile package manager version is incompatible
workspace manifest is not represented in root lockfile
```

---

### FR6: Explain dependency path

Users must be able to run:

```bash
corgea deps explain <package>
```

The output must show:

```text
package identity
direct/transitive
scope
dependency path
parent package
declared constraint
resolved version
source file
lockfile entry
policy status
vulnerability status
reachability status
fix recommendation
```

---

### FR7: Generate dependency diff

Users must be able to compare dependency graphs:

```bash
corgea deps diff --base origin/main
corgea deps diff --base v1.2.0 --head v1.3.0
corgea deps diff --previous-scan
```

The diff must show:

```text
added packages
removed packages
changed versions
new direct dependencies
new transitive dependencies
new vulnerabilities
resolved vulnerabilities
new policy violations
license changes
source/registry changes
```

---

### FR8: Support policy-as-code

The tool must read policy from:

```text
.corgea/deps.yml
.corgea.yml
organization default policy from Corgea platform
```

Precedence:

```text
CLI flags override repo policy
repo policy overrides org default
org default overrides built-in default
```

---

### FR9: Emit machine-readable output

The tool must support:

```bash
--out-format json
--out-format sarif
--out-format html
--out-format table
--out-file <path>
```

This aligns with Corgea’s existing CLI output model. ([Corgea Documentation][1])

---

### FR10: Upload inventory snapshot

The tool must support:

```bash
corgea deps scan --upload
```

Uploaded snapshot should include:

```text
repo
branch
commit SHA
scan timestamp
package files
manifest hashes
lockfile hashes
graph hash
dependency nodes
dependency edges
policy findings
vulnerability findings
license findings
SBOM artifact if generated
```

---

### FR11: Generate SBOM

The tool should support:

```bash
corgea deps sbom --format cyclonedx
corgea deps sbom --format spdx
```

MVP can start with one format. Recommended default: CycloneDX.

---

### FR12: Support suppressions and exceptions

Policy findings must support suppressions with:

```text
finding ID
package
reason
owner
expiration date
scope
approval metadata
```

Example:

```yaml
exceptions:
  - id: DEP003
    package: npm:axios
    reason: "Application uses lockfile; exact manifest pinning not required."
    owner: "platform-security"
    expires: "2026-08-01"
```

Exceptions without expiration should be discouraged.

---

## 9. Finding taxonomy

Recommended initial finding codes:

| Code   | Finding                                    |   Default severity |
| ------ | ------------------------------------------ | -----------------: |
| DEP001 | Missing lockfile                           |               High |
| DEP002 | Stale lockfile                             |               High |
| DEP003 | Direct dependency uses broad range         |             Medium |
| DEP004 | Wildcard or `latest` dependency            |               High |
| DEP005 | Mutable Git branch dependency              |               High |
| DEP006 | URL/tarball dependency without checksum    |               High |
| DEP007 | Transitive dependency unresolved           |             Medium |
| DEP008 | Lockfile integrity hash missing            |             Medium |
| DEP009 | Package manager version not pinned         |                Low |
| DEP010 | Vulnerable resolved package                | Severity from vuln |
| DEP011 | Declared range allows vulnerable versions  |             Medium |
| DEP012 | Deprecated package                         |             Medium |
| DEP013 | Abandoned package                          |             Medium |
| DEP014 | Duplicate versions of same package         |                Low |
| DEP015 | Dev dependency included in production path |             Medium |
| DEP016 | License policy violation                   |               High |
| DEP017 | Unapproved registry                        |               High |
| DEP018 | Suspicious package source change           |               High |
| DEP019 | Manifest-lockfile package manager mismatch |             Medium |
| DEP020 | Dependency exception expired               |               High |
| DEP021 | Mutable artifact version (Maven SNAPSHOT)  |               High |

---

## 10. MVP scope

### MVP command set

```bash
corgea deps scan
corgea deps explain <package>
corgea deps diff --base <ref>
corgea deps policy init
corgea deps sbom
```

### MVP ecosystems

Start with the ecosystems most likely to create immediate customer value:

```text
npm / yarn / pnpm
Python requirements / Poetry / uv
Go modules
Maven / Gradle
```

### MVP findings

Ship with these first:

```text
DEP001 missing lockfile
DEP002 stale lockfile
DEP003 direct dependency uses broad range
DEP004 wildcard/latest dependency
DEP005 mutable Git branch dependency
DEP006 URL dependency without checksum
DEP008 missing integrity hash
DEP010 vulnerable resolved package
DEP016 license violation
DEP017 unapproved registry
DEP021 mutable artifact version (Maven SNAPSHOT)
```

### MVP outputs

```text
terminal table
JSON
SARIF
CycloneDX SBOM
Corgea upload
```

### MVP platform views

```text
Dependency inventory by repo
Dependency search across repos
Lockfile coverage
Policy violations by severity
Vulnerable dependencies by reachability
Dependency diff per scan
SBOM download
```

---

## 11. Detailed use cases

1. **PR dependency review**
   A developer opens a PR that adds `axios`. Corgea shows the direct dependency and all new transitive packages.

2. **Missing lockfile detection**
   A Python service has `requirements.txt` but no compiled lockfile or constraints. Corgea flags the build as non-reproducible.

3. **Stale lockfile detection**
   A developer updates `package.json` but forgets to regenerate `package-lock.json`. Corgea blocks CI.

4. **Unpinned direct dependency detection**
   A direct dependency uses `latest`, `*`, `>=`, or a bare Python package name. Corgea flags it.

5. **Mutable Git dependency detection**
   A package points to `@main` instead of a commit SHA. Corgea flags it as mutable.

6. **Transitive dependency explanation**
   Security sees a vulnerable package and runs `corgea deps explain`. Corgea shows the parent dependency path.

7. **CVE incident response**
   A new vulnerability is disclosed. AppSec searches all inventories to find affected repos, teams, versions, and reachability.

8. **SBOM generation**
   A release manager generates an SBOM for a customer security review.

9. **License policy enforcement**
   A PR introduces an AGPL dependency. Corgea blocks the build and explains the license policy.

10. **Duplicate dependency reduction**
    Corgea detects five versions of the same npm package, helping reduce attack surface and bundle size.

11. **Dead dependency cleanup**
    Corgea identifies packages present in the lockfile but not used by application code.

12. **Private registry enforcement**
    Corgea flags a dependency resolved from a public registry when policy requires internal registry resolution.

13. **Dependency drift monitoring**
    Corgea compares branches, releases, or environments and detects inconsistent dependency resolutions.

14. **Monorepo inventory**
    Corgea maps every manifest and lockfile to its workspace/service owner.

15. **Audit readiness**
    Corgea stores historical dependency graphs per release commit.

16. **Exception governance**
    A team suppresses a finding with owner, reason, and expiration. Corgea reopens it after expiry.

17. **Upgrade planning**
    Corgea groups vulnerable dependencies by parent package and recommends the smallest upgrade path.

18. **Dev dependency production leakage**
    Corgea detects that a dev-only package is included in a production deployment path.

19. **Package source change detection**
    A package changes from official registry source to a Git URL or tarball. Corgea flags it.

20. **Organization policy enforcement**
    Security defines a central policy that all deployable apps must have lockfiles and approved registries.

---

## 12. Future features

### 12.1 Dependency graph diff visualization

A web UI that shows graph changes between commits, releases, or scans.

Useful views:

```text
new direct dependencies
new transitive dependencies
new vulnerable paths
removed packages
changed package sources
license changes
registry changes
```

---

### 12.2 Automated remediation PRs

Corgea could generate PRs that:

```text
regenerate lockfiles
pin exact versions
add constraints
upgrade vulnerable packages
remove unused packages
replace deprecated packages
switch mutable Git refs to commit SHAs
```

---

### 12.3 Package health scoring

Score each dependency using:

```text
release recency
maintenance activity
deprecated status
known vulnerabilities
license risk
package age
download/popularity signal
maintainer changes
registry/source changes
typosquatting risk
malware history
```

---

### 12.4 Organization-wide dependency search

Search examples:

```text
show all repos using lodash
show all services using urllib3 < 2.0
show all packages from unapproved registries
show all projects without lockfiles
show all AGPL dependencies
show all reachable critical vulnerabilities
```

---

### 12.5 Runtime correlation

Compare source dependency inventory with what is actually deployed.

Questions answered:

```text
Is this lockfile dependency present in the container?
Is this vulnerable package actually shipped?
Are dev dependencies leaking into production?
Does production contain packages not represented in source?
```

---

### 12.6 VEX support

Allow teams to record exploitability status:

```text
affected
not affected
fixed
under investigation
```

This would reduce noise for vulnerabilities that are present but not exploitable in context.

---

### 12.7 Dependency ownership mapping

Automatically assign dependencies and findings to service owners.

Inputs:

```text
CODEOWNERS
repo ownership metadata
monorepo workspace ownership
Corgea project ownership
team mappings
```

---

### 12.8 Risk budget

Allow teams to define a dependency risk budget.

Example:

```text
maximum 0 critical reachable vulns
maximum 3 high reachable vulns
maximum 10 medium policy warnings
no missing lockfiles
no unapproved registries
```

---

### 12.9 Package manager version governance

Flag projects that do not pin package manager versions.

Examples:

```text
npm version not pinned
pnpm version not pinned
Poetry version not pinned
uv version not pinned
Maven wrapper missing
Gradle wrapper missing
```

This matters because different package manager versions can resolve or install dependencies differently.

---

### 12.10 Suspicious dependency behavior

Future supply-chain checks:

```text
dependency newly added with install scripts
package maintainer changed recently
package name similar to popular package
package source changed registries
package has very low age or low adoption
package publishes many versions rapidly
package contains obfuscated code
```

---

## 13. Data model

### Dependency node

```json
{
  "id": "pkg:npm/axios@1.8.2",
  "name": "axios",
  "ecosystem": "npm",
  "version": "1.8.2",
  "purl": "pkg:npm/axios@1.8.2",
  "scope": "production",
  "direct": true,
  "depth": 1,
  "source_type": "registry",
  "registry_url": "https://registry.npmjs.org/",
  "license": "MIT",
  "deprecated": false,
  "reachable": "unknown",
  "dead_package": false
}
```

### Dependency edge

```json
{
  "from": "root",
  "to": "pkg:npm/axios@1.8.2",
  "declared_constraint": "^1.8.0",
  "resolved_version": "1.8.2",
  "relationship": "direct",
  "scope": "production",
  "source_file": "package.json",
  "lockfile": "package-lock.json"
}
```

### Finding

```json
{
  "id": "DEP003",
  "severity": "medium",
  "title": "Direct dependency uses broad range",
  "package": "pkg:npm/axios@1.8.2",
  "source_file": "package.json",
  "declared_constraint": "^1.8.0",
  "resolved_version": "1.8.2",
  "status": "open",
  "recommendation": "Pin axios to 1.8.2 or allow this range by policy because the lockfile resolves it.",
  "introduced_in": "current_scan",
  "paths": [
    ["root", "pkg:npm/axios@1.8.2"]
  ]
}
```

### Inventory snapshot

```json
{
  "repo": "api-service",
  "branch": "main",
  "commit": "abc123",
  "scan_timestamp": "2026-05-20T10:00:00Z",
  "manifest_hashes": {
    "package.json": "..."
  },
  "lockfile_hashes": {
    "package-lock.json": "..."
  },
  "graph_hash": "...",
  "nodes": [],
  "edges": [],
  "findings": []
}
```

---

## 14. CLI design

### Primary commands

```bash
corgea deps scan
```

Runs dependency inventory and policy scan.

```bash
corgea deps explain <package>
```

Explains why a package exists.

```bash
corgea deps graph
```

Prints dependency tree or exports graph.

```bash
corgea deps diff --base <git-ref>
```

Compares dependency graph against another ref.

```bash
corgea deps sbom --format cyclonedx
```

Generates SBOM.

```bash
corgea deps policy init
```

Creates starter policy file.

```bash
corgea deps fix
```

Suggests or applies safe remediations.

---

### Useful flags

```bash
--ecosystem npm
--ecosystem pypi
--prod-only
--include-dev
--changed
--fail-on high
--policy .corgea/deps.yml
--out-format json
--out-format sarif
--out-format html
--out-file deps-report.json
--upload
--explain-findings
--show-paths
--sbom
```

---

## 15. Platform UI recommendations

The Corgea web experience should include:

### 15.1 Dependency inventory page

Columns:

```text
package
ecosystem
version
direct/transitive
scope
repos affected
vulnerabilities
reachability
license
source
last seen
owner
```

### 15.2 Repo dependency posture page

Cards:

```text
total dependencies
direct dependencies
transitive dependencies
missing lockfiles
stale lockfiles
reachable critical vulns
license violations
unapproved registries
dead packages
```

### 15.3 Dependency detail page

Show:

```text
all repos using package
all versions in use
dependency paths
known vulnerabilities
fixed versions
licenses
source registries
reachability status
historical trend
```

### 15.4 PR view

Show:

```text
new packages
removed packages
version changes
new policy findings
new reachable vulnerabilities
new license issues
recommended action
```

### 15.5 Policy page

Allow org admins to configure:

```text
lockfile requirements
pinning requirements
allowed registries
blocked licenses
vulnerability thresholds
exception rules
CI failure behavior
```

---

## 16. Success metrics

### Adoption metrics

```text
number of repos scanned
number of active orgs using deps scan
percentage of scans uploaded
number of CI integrations
number of SBOMs generated
```

### Quality metrics

```text
false positive rate
percentage of findings with dependency path
percentage of findings with recommended fix
percentage of findings with reachability status
scan success rate by ecosystem
```

### Security impact metrics

```text
missing lockfiles reduced
stale lockfiles reduced
reachable critical vulnerabilities reduced
unapproved registry usage reduced
license violations prevented
mean time to remediate dependency findings
```

### Developer experience metrics

```text
average scan time
average CI runtime overhead
percentage of PRs blocked
percentage of blocked PRs resolved without AppSec intervention
number of explain command uses
```

---

## 17. Launch plan

### Phase 1: Alpha

Audience:

```text
internal users
design partners
small number of repos
```

Scope:

```text
npm and Python
local CLI only
JSON output
basic policy findings
dependency explain
```

Exit criteria:

```text
accurate dependency graph on representative repos
low false positive rate for lockfile and pinning findings
developer output is understandable
```

---

### Phase 2: Beta

Audience:

```text
selected customers
AppSec teams
CI users
```

Scope:

```text
SARIF output
Corgea upload
policy-as-code
dependency diff
SBOM export
Go and Java support
```

Exit criteria:

```text
CI integration works reliably
dependency diffs are trusted
platform inventory is useful
policy configuration is understandable
```

---

### Phase 3: GA

Audience:

```text
all Corgea customers
```

Scope:

```text
multi-ecosystem support
dashboard
org-wide search
exceptions
reachability enrichment
license policy
remediation guidance
```

Exit criteria:

```text
documented CLI
stable output schema
strong ecosystem coverage
low support burden
clear ROI for AppSec and developers
```

---

## 18. Risks and mitigations

### Risk 1: Too many false positives

Bad outcome:

```text
Developers see every transitive semver range as a violation.
They ignore or disable the tool.
```

Mitigation:

```text
Treat transitive ranges as risky only when unresolved, unlocked, vulnerable, mutable, or policy-relevant.
Default CI gating to new high-risk findings only.
```

---

### Risk 2: Ecosystem edge cases

Bad outcome:

```text
Parser fails on real-world lockfiles, monorepos, or workspaces.
```

Mitigation:

```text
Start with fewer ecosystems.
Build strong test fixtures.
Use package-manager-native commands where needed.
Clearly label unsupported files.
```

---

### Risk 3: Slow CI scans

Bad outcome:

```text
Teams disable scanning because it slows builds.
```

Mitigation:

```text
Cache parsed lockfiles.
Hash manifests and lockfiles.
Support changed-only mode.
Avoid network calls unless explicitly enabled.
```

---

### Risk 4: Confusing policy semantics

Bad outcome:

```text
Users do not understand why something failed.
```

Mitigation:

```text
Every finding includes source file, reason, dependency path, policy rule, and exact remediation.
```

---

### Risk 5: Overlapping with existing SCA scanner

Bad outcome:

```text
Users cannot tell whether this is SCA, SBOM, policy, or vulnerability scanning.
```

Mitigation:

```text
Position this as the graph/inventory/policy layer.
SCA vulnerabilities are one enrichment source, not the whole product.
```

---

## 19. Recommendation: default policy

Default policy should be strict enough to create value but not so strict that every repo fails.

Recommended default:

```yaml
dependency_policy:
  require_lockfile: true
  fail_on_missing_lockfile: true
  fail_on_stale_lockfile: true

  direct_dependencies:
    fail_on_wildcard: true
    fail_on_latest: true
    fail_on_mutable_sources: true
    warn_on_semver_range: true

  transitive_dependencies:
    allow_ranges_if_resolved_by_lockfile: true
    fail_if_unresolved: true

  vulnerabilities:
    fail_on_new_critical_reachable: true
    fail_on_new_high_reachable: true
    warn_on_unreachable: true

  licenses:
    fail_on_blocked_license: true

  ci:
    fail_on_new_findings_only: true
```

This avoids the biggest product mistake: blocking builds for harmless transitive declarations that are already locked.

---

## 20. Open questions

1. Should exact version pinning be recommended for all direct dependencies, or only for deployable applications?
2. Should libraries get a different default policy from applications?
3. Which package managers should be MVP versus beta?
4. Should Corgea invoke native package-manager commands, or parse lockfiles only?
5. How should the tool handle generated lockfiles that are intentionally not committed?
6. Should dependency health scoring be included in v1 or left for v2?
7. Should remediation PRs be part of beta or GA?
8. Which SBOM format should be default: CycloneDX or SPDX?
9. How should exceptions be approved: repo-only, org-level, or both?
10. Should policy support different thresholds for production, staging, development, and test dependencies?
11. Should reachability be required for CI gating, or used only as prioritization?
12. How should monorepo service ownership be inferred?

---

## 21. Final recommendation

Build this as **Corgea’s dependency graph and supply-chain policy layer**, not just a pinning checker.

The MVP should be:

```text
corgea deps scan
corgea deps explain
corgea deps diff
corgea deps policy
corgea deps sbom
```

The product should center on five promises:

```text
Inventory: what dependencies do we have?
Provenance: where did they come from?
Reproducibility: can this install drift?
Risk: is this vulnerable, reachable, or policy-violating?
Remediation: what is the smallest safe fix?
```

The strongest wedge is not “we find vulnerable dependencies.” Many tools do that.

The stronger wedge is:

```text
Corgea tells you exactly why a dependency exists, whether it can drift, whether it matters, and how to fix it without drowning developers in noise.
```

[1]: https://docs.corgea.app/cli?utm_source=chatgpt.com "CLI - Corgea Documentation"
[2]: https://corgea.com/products/dependency-scanning?utm_source=chatgpt.com "Dependency Scanning with AI Reachability Analysis"

