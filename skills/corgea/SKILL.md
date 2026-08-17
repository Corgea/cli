---
name: corgea
description: Scans code for security vulnerabilities using Corgea's AI-powered BLAST scanner and third-party tools, gates `pip` and `npm` package installs against vulnerable and malicious dependencies (including transitive), manages findings, and displays AI-generated fixes. Use when the user needs to install pip/npm packages safely, scan for security issues, upload scan reports, list or inspect vulnerabilities, view fixes, or integrate security scanning into CI/CD.
allowed-tools: Shell, Read, Grep, Glob, StrReplace
---

# Corgea CLI

Find and fix security vulnerabilities using AI-powered scanning (BLAST), third-party scanners, and AI-generated fixes.

## Check the installed version first

This file describes a CLI version, not the one on the machine. Run `corgea --version` before relying on anything below.

```bash
corgea --version
```

`corgea --help` and `corgea <command> --help` come from the installed binary, so they are authoritative about which commands and flags exist. **Where this file and `--help` disagree, `--help` is right.** Confirm any command from here that you have not seen in `--help` before running it.

If a command or flag is missing, the CLI is likely older than this reference. Report that to the user with the upgrade for how it was installed, rather than upgrading unprompted — CI runners and self-hosted installs are often pinned deliberately.

```bash
pip install --upgrade corgea-cli      # installed with pip
npm install -g @corgea/cli            # installed with npm
```

A missing flag is the visible case. A flag whose default or output shape changed will not error, so treat a surprising result on an older CLI as a version difference before treating it as a bug.

## Commands

### Scan — `corgea scan [scanner]`

Default scanner is `blast` (AI-powered, server-side). Also supports `semgrep` and `snyk` (must be installed separately), blast should be used by default unless the user asked not to.

```bash
corgea scan                                    # BLAST scan, full project
corgea scan semgrep                            # Semgrep scan, upload results
corgea scan snyk                               # Snyk Code scan, upload results
```

#### BLAST Options

```bash
corgea scan --only-uncommitted                 # Staged/modified/untracked files only
corgea scan --target src/,pyproject.toml       # Specific paths (comma-separated)
corgea scan --target "src/**/*.py"             # Glob patterns
corgea scan --target git:diff=origin/main...HEAD  # Git diff range
corgea scan --target git:staged,git:modified   # Git selectors
corgea scan --target -                         # File list from stdin
corgea scan --scan-type secrets                # Single scan type
corgea scan --scan-type blast,policy,secrets,pii  # Multiple scan types
corgea scan --scan-type policy --policy 1      # Specific policy ID
corgea scan --fail-on CR                       # Exit 1 on critical issues (CR, HI, ME, LO)
corgea scan --fail-on malicious                # Exit 1 if any dependency is classified malicious
corgea scan --fail-on HI,malicious             # Comma-separated conditions combine
corgea scan --block-on criticals               # Exit 1 if the scan violates the named CI blocking rules
corgea scan --block-on criticals,malicious-deps  # Comma-separated rule slugs
corgea scan --fail                             # Deprecated: exit 1 based on every active blocking rule
corgea scan --out-format json --out-file r.json   # Export (json, html, sarif, markdown)
corgea scan --sbom                             # Also write a CycloneDX SBOM to bom.json
corgea scan --sbom sbom.cdx.json               # SBOM to a custom file
corgea scan --include-image myapp:1.2.3        # Also scan a fully built container image
corgea scan --include-image myapp:1.2.3 --include-image ghcr.io/acme/api:latest  # Repeatable
corgea scan --project-name my-service          # Override project name
corgea scan --skip-if-commit-scanned-recently  # Reuse a recent scan of this commit instead of scanning again
corgea scan --skip-if-commit-scanned-recently --scanned-within 4h  # Window for "recently" (default 24h)
corgea scan --skip-if-commit-scanned-recently --ignore-dirty-worktree  # Reuse even if this tree or the prior scan is dirty
```

Scan types: `blast` (base AI), `policy` (PolicyIQ), `malicious`, `secrets`, `pii`.

`--fail-on` takes comma-separated conditions: severity thresholds `CR`, `HI`, `ME`, `LO` (trip at or above the level) and/or `malicious` (trips when any dependency in the scan is classified malicious). Use `malicious` to block supply-chain findings in CI across every ecosystem the scan covers, including those the `corgea npm`/`corgea pip` install gate does not.

`--block-on` takes comma-separated blocking-rule slugs. Blocking rules are configured in the web app and each one applies either to pull requests or to CI. Only CI rules can be named by `--block-on`; a slug that is unknown, inactive, or scoped to pull requests is a hard error (exit 1) rather than a silently skipped gate. The slug is shown next to each rule in the web app and is derived from the rule name, so renaming a rule changes its slug. Name rules for the condition that trips them — `criticals`, not `no-criticals` — so that `--block-on` reads as a direct assertion rather than a double negative.

`--fail` is deprecated. It evaluates every active blocking rule regardless of what it applies to; use `--block-on` to name the CI rules a pipeline should enforce.

`--include-image` scans the image you actually ship. Without it, container scanning discovers the base images referenced by Dockerfiles and Compose files in the repo and scans those. With it, each image is exported to a tar archive with `docker save` (or `podman save`), bundled with the project, and scanned as a whole — base-image discovery is skipped for that scan. Images that aren't available locally are pulled first, so build (or pull) the image before the scan and stay logged in to its registry. Set `CORGEA_CONTAINER_ENGINE` to choose a specific container CLI. Container scanning must be enabled for your account.

An included image is enough on its own: when it is combined with `--only-uncommitted` or `--target` and no source files match (a clean working tree, for example), the scan warns and covers just the image rather than failing. An archive named `corgea-image-scanning-*.tar` that is committed to the repository is ignored — only images passed on the command line are scanned.

`--only-uncommitted` and `--target` are mutually exclusive. `--fail-on`, `--fail`, and `--block-on` are mutually exclusive.

`--out-format`/`--out-file` and `--sbom` are honored regardless of the gate: the report and the SBOM are written before `--fail`/`--block-on` are evaluated, so a scan that exits 1 on a blocking rule still leaves the report file behind for the pipeline to ingest.

`--skip-if-commit-scanned-recently` reuses the project's most recent reusable scan of the current commit instead of starting a duplicate, when one ran inside the `--scanned-within` window (default `24h`; accepts `90s`, `30m`, `4h`, `7d`, and a bare number as hours). The reused scan takes the new scan's place for the rest of the command — results table, `--block-on` gate and its exit code, `--out-file` report — so the pipeline behaves the same either way. It prints `CORGEA_SCAN_SKIPPED=true` plus `CORGEA_SCAN_ID=<id>` on a reuse and `CORGEA_SCAN_SKIPPED=false` when a scan runs, so a later step can branch on it.

Reuse requires a candidate that answers the same question: a completed `corgea-blast` scan of that commit, on a branch rather than a pull request, from an explicitly clean worktree, reporting no scanner problems. Anything else runs a real scan (nothing in the window, a failed or still-running scan, a worktree that does not match the commit including files hidden from `git status`, or a failed lookup). `--ignore-dirty-worktree` (requires `--skip-if-commit-scanned-recently`) overrides the dirty-worktree half of that test: reuse proceeds even if this worktree is dirty or the prior scan recorded `worktree_dirty`. A new scan still reports the real dirty status. An unresolvable commit is a hard error (exit 1). Because the API exposes neither a scan's configured scan types and target policies nor whether it bundled a container image, a run that changes what gets scanned cannot be matched against a candidate, so the flag cannot be combined with `--scan-type`, `--policy`, `--include-image`, `--only-uncommitted`, or `--target`. `--exclude` is allowed but warns on a skip: what gets reused is a scan of the whole commit, so the results and the gate can cover files the run would have skipped (over-reporting, never under-reporting).

### Upload — `corgea upload [report]`

Upload an existing scan report to Corgea.

```bash
corgea upload path/to/report.json              # JSON, SARIF, Coverity XML
corgea upload path/to/report.fpr               # Fortify FPR
corgea upload report.sarif --project-name svc  # Custom project name
cat report.json | corgea upload                # From stdin
corgea upload report.json --wait               # Wait for scan to complete and print results
```

Supported: Semgrep JSON, SARIF, Checkmarx (CLI/Web/XML), Coverity, Fortify FPR.

By default `upload` prints the scan page URL so you can track the results. Pass `--wait` to block until the scan completes and print the results (like `corgea scan`).

### Wait — `corgea wait [scan_id]`

```bash
corgea wait                                    # Wait for latest scan
corgea wait SCAN_ID                            # Wait for a specific scan
```

Waiting (`corgea scan`, `corgea wait`, `corgea upload --wait`) exits 1 if the
scan fails, printing why. A scan missing one scanner's results exits 0 with a
warning. Polling gives up after 10 hours; override with
`CORGEA_SCAN_TIMEOUT_SECONDS`. `--fail`/`--block-on` then wait up to 15 minutes
for blocking rules to be evaluated, and exit 1 if that runs out; override with
`CORGEA_BLOCKING_RULES_TIMEOUT_SECONDS`.

### List — `corgea list` (alias: `corgea ls`)

```bash
corgea ls                                      # List scans
corgea ls --issues --scan-id SCAN_ID           # Issues for a scan
corgea ls --sca-issues                         # SCA (dependency) issues
corgea ls --code-quality                       # Code quality issues
corgea ls --issues --page 2 --page-size 10     # Pagination
corgea ls --issues --scan-id SCAN_ID --json    # JSON output
```

| Flag | Short | Description |
|------|-------|-------------|
| `--issues` | `-i` | List code/SAST issues |
| `--sca-issues` | `-c` | List SCA issues |
| `--code-quality` | `-q` | List code quality issues (alias `--quality`) |
| `--scan-id` | `-s` | Filter to a scan |
| `--page` | `-p` | Page number |
| `--page-size` | | Items per page |
| `--json` | | JSON output |

### Inspect — `corgea inspect <id>`

```bash
corgea inspect SCAN_ID                         # Scan overview with issue counts
corgea inspect --issue ISSUE_ID                # Full issue details + fix
corgea inspect --issue --summary ISSUE_ID      # Summary only
corgea inspect --issue --fix ISSUE_ID          # Fix explanation only
corgea inspect --issue --diff ISSUE_ID         # Diff only
corgea inspect --issue --json ISSUE_ID         # JSON output
```

| Flag | Short | Description |
|------|-------|-------------|
| `--issue` | `-i` | Treat ID as issue (default: scan) |
| `--summary` | `-s` | Summary only |
| `--fix` | `-f` | Fix explanation only |
| `--diff` | `-d` | Diff only |
| `--json` | | JSON output |

### Setup Hooks — `corgea setup-hooks`

```bash
corgea setup-hooks                             # Interactive configuration
corgea setup-hooks --default-config            # Default: secrets + PII, fail on LO
```

Installs a pre-commit hook running `corgea scan blast --only-uncommitted`. Bypass with `git commit --no-verify`.

<!-- BEGIN GENERATED CORGEA DEPS SKILL -->
### Deps — `corgea deps <command>`

Offline dependency inventory and policy checks. No Corgea token or network required.
Agent environments default to compact TSV; force output with `--format human|agent|json|quiet`.

- `corgea deps scan [PATH]` — Scan manifests and lockfiles, build inventory, evaluate policy. Flags: `--fail-on`, `--out-format`, `--out-file`, `--format`
  Examples: `corgea deps scan --format agent`; `corgea deps scan --format quiet --fail-on high`
- `corgea deps graph [PATH]` — Print the dependency graph. Flags: `--format`
  Examples: `corgea deps graph --format agent`; `corgea deps graph tests/fixtures/node-app --format json`
- `corgea deps explain <PACKAGE> [PATH]` — Explain why a package is present. Flags: `--format`
  Examples: `corgea deps explain lodash --format agent`; `corgea deps explain left-pad tests/fixtures/node-app --format json`
- `corgea deps diff --base <BASE> [PATH]` — Compare dependency graph against a git ref. Flags: `--base`, `--fail-on-new`, `--format`
  Examples: `corgea deps diff --base origin/main --format json`; `corgea deps diff --base HEAD . --fail-on-new high`
- `corgea deps sbom [PATH]` — Generate an SBOM. Flags: `--format`, `--out`
  Examples: `corgea deps sbom --format cyclonedx`; `corgea deps sbom --format cyclonedx --out bom.json`
- `corgea deps policy init [PATH]` — Write a starter `.corgea/deps.yml` policy file. Flags: `--exist-ok`, `--format`
  Examples: `corgea deps policy init`; `corgea deps policy init --exist-ok --format quiet`

Notes: `deps scan --out-format table|json|sarif` is the report/export selector; do not combine it with `deps scan --format`.

### Dependency finding catalog

| ID | Status | Severity | Title | Description | Remediation |
| --- | --- | --- | --- | --- | --- |
| `DEP001` | emitted | High | Missing lockfile | The dependency manifest has no expected lockfile, so resolution is not reproducible. | Generate and commit the ecosystem lockfile. |
| `DEP002` | emitted | High | Stale lockfile | A manifest dependency is missing from its lockfile. | Regenerate and commit the lockfile. |
| `DEP003` | emitted | Medium | Direct dependency uses broad range | A direct dependency uses a bounded version range. | Pin an exact version or explicitly allow the range by policy. |
| `DEP004` | emitted | High | Wildcard or latest dependency | A direct dependency uses wildcard, latest, or another unbounded range. | Pin an exact version. |
| `DEP005` | emitted | High | Mutable Git branch dependency | A direct dependency is sourced from a mutable Git branch reference. | Pin a commit SHA or immutable release tag. |
| `DEP006` | emitted | High | URL/tarball dependency without checksum | A direct URL or tarball dependency has no integrity checksum. | Add an integrity checksum or pin a registry package. |
| `DEP008` | emitted | Medium | Lockfile integrity hash missing | A lockfile entry lacks its integrity hash. | Add the integrity hash to the lockfile entry. |
| `DEP010` | reserved | Medium | Vulnerable package advisory | Reserved for vulnerable-package/advisory findings; `corgea deps` does not emit it. | Handle this code in an advisory or install-wrapper flow, never in `corgea deps`. |
| `DEP014` | emitted | Low | Duplicate versions of same package | More than one resolved version of a package is present. | Align or deduplicate the resolved dependency versions. |
| `DEP019` | emitted | Medium | Unsupported lockfile | A detected lockfile format is not supported by the parser. | Use a supported lockfile or wait for parser support. |
| `DEP021` | emitted | High | Mutable artifact version | A direct artifact version is mutable, such as a Maven SNAPSHOT. | Pin an immutable release version. |
<!-- END GENERATED CORGEA DEPS SKILL -->

### Advisories — `corgea advisories check`

Query Corgea's vulnerability database for a package **before** choosing or
installing it. Read-only: it reports, never blocks. Network access to the
vuln-api is required. The package-level form needs no token; the versioned
form uses the same auth story as the install gate (a Corgea token is
attached automatically when logged in on the default vuln-api, and the
production version-check route may require one — a tokenless 401 exits 2
with a clear message).

**Before adding or choosing a dependency version, run
`corgea advisories check <ecosystem> <package>` to see its advisory history,
then `corgea advisories check <ecosystem> <package>@<version>` once you have
a candidate version. Pick the safe version the output steers to. The install
gate (`corgea npm|pip|...`) remains the backstop.**

```bash
corgea advisories check npm axios            # axios's advisory history (up to 100 most recent)
corgea advisories check npm axios@1.0.0      # verdict for one exact version
corgea advisories check pypi requests@2.31.0 # pypi (pip is accepted as an alias)
corgea advisories check pypi requests==2.31.0  # pip-style separator also accepted; extras ([security]) are ignored
corgea advisories check npm axios@1.0.0 --json  # stable machine-readable document
```

| Exit code | Meaning |
|-----------|---------|
| 0 | Clean: no advisories for the version, no advisories for the package, or package unknown to the database |
| 1 | Advisories found (versioned: vulnerable; unversioned: at least one advisory linked) |
| 2 | Error: network, auth, parse, or bad arguments |

Versions must be exact (`1.2.3`, not `^1.2`). The versioned form gives the
same verdict the install gate enforces — advisory IDs, severities,
`fixed in <version>` notes, and a `→ safe version:` steer when every
advisory has a fix. The unversioned form lists the package's advisory
history (id, severity, cvss, tier, kev/malware markers) so you can pick a
version with a clean record; it has no fix data, so follow up with the
versioned form. `--json` emits one `schema_version: 1` document on stdout
(`verdict` object for the versioned form — same vocabulary as the install
gate's `--json`; `found` + `advisories[]` + `possibly_truncated` for the
unversioned form — the listing caps at 100 advisories and
`possibly_truncated: true` means more may exist). Errors after arguments
parse (network, auth, unknown package spec, bad version) emit
`{"schema_version":1,"error":...}` on stdout and exit 2; malformed
command-line usage (missing arguments, unknown flags) gets the CLI's
standard usage text on stderr instead, also exit 2.

### Install Wrappers — `corgea pip|npm|yarn|pnpm|uv <args...>`

Run a package manager through Corgea's install gate. Install commands with
named targets are resolved against the public registry first, then each
resolved version is checked against Corgea's vuln-api. Every resolved
package's publish time is shown for provenance (`published <age> ago at
<UTC timestamp>`), but it never blocks.
Baseline public CVE checks need no token: known-vulnerable or malicious
versions block, but vuln-api lookup outages warn and continue because public
mode is fail-open. A Corgea token on the default vuln-api enables
authenticated enforcement; in that mode, verdict lookup failures, resolution
errors, and unverifiable git/URL/path specs (including `pip install .`, PEP
508 `name @ url` direct references, and npm GitHub shorthand `user/repo`) all
block (fail-closed) unless `--force`. In public mode those same specs are
noted, never blocked, and everything else passes through with the package
manager's own exit code. The install verb
is found behind global flags (`npm --loglevel silent install x` is still
gated). Bare `npm install` (zero specs, project `package.json` found like npm
finds it — nearest ancestor) is gated too: the full lockfile-resolved tree is
verdicted, so a vulnerable lockfile blocks. `npm ci` (and aliases) is gated
from the project lockfile directly.

The vuln check covers the **full would-install set** where the manager has a
safe resolver, not just the named targets: `pip` and `npm` resolve the
complete tree (named + transitive) via a safe dry-run
(`pip install --dry-run …`; an isolated `npm install --package-lock-only` in
a temp dir, never touching your lockfile), and `uv pip install` / `uv add` /
`uv pip sync` resolve theirs via `uv pip compile`; every resolved package is
verdicted, so a flagged **transitive** dependency blocks the install too,
labeled by provenance (`(transitive)`, `(from requirements)`,
`(already in package.json)`, `(locked)`). `uv sync` is gated from `uv.lock`
(found like uv finds it — nearest ancestor). `yarn` and `pnpm` have no safe
dry-run, so they verify the named targets only; bare `yarn`/`pnpm` installs
run unchecked after a stderr note
(`note: bare '<pm> <sub>' is not gated …`). Whenever a dry-run fails or an
npm flag redirects the project root (`--prefix`, `-g`), the gate falls back
to named-only and prints
`warning: transitive dependencies not checked (…); only named packages were verified.`
— for pip/uv, entries of `-r requirements.txt` files are still parsed and
verified in that fallback. Verdict requests run in a bounded pool
(8 parallel). Running the wrong manager for a project (npm in a pnpm
project, pip in a uv project, …) is refused with a
`Did you mean `corgea …`?` suggestion; `--force` bypasses that guard too.

Wrapper flags (`--force`, `--json`) are read between the manager name and the
install verb (`corgea npm --force install x`); flags after the verb belong to
the package manager and are forwarded untouched.

Blocked findings steer to the fix: each advisory line shows
`fixed in <version>` (or `no fixed version known`). When every advisory on a
package has a fix, the gate prints `→ safe version: <name>@<version>` — the
highest fix covering every advisory. Install that version instead.

The gate also blocks **freshly published** named targets: a package whose
resolved version was published within the recency window (default 14 days)
is refused, naming each package and its publish age. This catches just-shipped
typosquat/hijack releases before the advisory feeds catch up. It is **on by
default**; turn it off with `recency_gate = false` in `~/.corgea/config.toml`
(or `CORGEA_RECENCY_GATE=0`), tune the window with `recency_threshold_days`
(or `CORGEA_RECENCY_THRESHOLD_DAYS`), or pass `--force` for a single install.
Packages whose publish date is unknown (pip backtracking to an unresolved
version) never trip it, and a vulnerable/malicious verdict takes precedence —
such a package blocks on that verdict, not as fresh.

```bash
corgea pip install requests==2.31.0   # resolves, checks the vuln verdict, then runs pip
corgea npm install axios@^1.0.0       # same gate for npm ranges
corgea pip --force install badpkg     # print findings but install anyway (overrides every block)
corgea pip --json install newpkg      # machine-readable per-target report incl. verdicts
corgea pip list                       # non-install subcommands pass straight through
```

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | | Proceed despite all findings (vulnerable, malicious, unverifiable). Findings still print. Also bypasses the wrong-package-manager and PEP 668 refusals, and unparsable-lockfile refusals on `uv sync`/`npm ci`. |
| `--json` | | JSON report instead of text. Per-result `verdict` object + `verdict_mode` + `tree`. Stdout carries only the report; the package manager's output moves to stderr. |

`--json` adds `verdict_mode` (`"public"` or `"authenticated"` from the CLI;
`"none"` can only appear for library callers that disable verdicts)
and a `tree` object: `null` when no tree pass ran; otherwise `mode` is
`"full"` (transitive checked) or `"named-only"` (with a `reason`), plus
`resolved_count` and a `transitive[]` array of `{name, version, origin,
verdict}` for packages beyond the named targets. Vulnerable `verdict`
objects carry a `remediation` field: the safe version covering every
advisory, or `null` when any advisory has no known fix. Known-malicious
packages report a distinct verdict `status` of `malicious` (matches carry a
`malware` boolean; each summary object carries a separate `malicious` count)
and refuse with a distinct `known MALICIOUS package(s) detected` message;
their `remediation` field is always `null` because malware must be removed,
not upgraded. A top-level
`recency_threshold_days` reports the active recency window (or `null` when
the recency gate is off); pair it with each result's `age_seconds`.

Baseline CVE checks need no token. The default vuln-api
uses `CORGEA_TOKEN` (or the `corgea login` token) when present. A custom
`CORGEA_VULN_API_URL` is public by default, even when a token exists; set
`CORGEA_VULN_API_SEND_TOKEN_TO_CUSTOM_URL=1` to send the token to that
custom URL and make lookup failures fail closed. Recency gate:
`recency_gate` / `recency_threshold_days` in `~/.corgea/config.toml`, overridden
by `CORGEA_RECENCY_GATE` and `CORGEA_RECENCY_THRESHOLD_DAYS`. Overrides for
testing: `CORGEA_PYPI_REGISTRY`, `CORGEA_NPM_REGISTRY`, `CORGEA_VULN_API_URL`.

#### Limitations

The gate is a wrapper, not an enforcement boundary. By design it cannot catch:

- **Direct invocation** — running the package manager itself (`pip`, `npm`,
  `python -m pip`) skips the gate entirely.
- **Custom indexes/registries** — `--index-url`, `--registry`, and `.npmrc`/
  `pip.conf` overrides change where packages resolve from. The gate still
  verdicts each `name@version`, but it cannot vouch that a substituted
  registry serves the same artifact those advisories describe.
- **Named-only fallback** — when a dry-run fails (old pip, broken resolution)
  or `--prefix`/`-g` redirects npm's root, transitive dependencies install
  unchecked behind the printed warning.
- **Ungated managers** — bare `yarn`/`pnpm` installs run unchecked (see the
  bare-install note above); only their named targets are verified.
- **Ungated uv/yarn subcommands** — `uv run` (project sync on first run,
  `--with` packages), `uv tool install`/`uv tool run`, and
  `yarn global add` install packages without a gate; each prints an
  ungated note instead of passing silently.

## Common Workflows

### Scan full project

```bash
corgea scan
```

### Scan uncommitted changes

```bash
corgea scan --only-uncommitted --fail-on HI
```

### Scan the container image a build produced

```bash
docker build -t myapp:1.2.3 .
corgea scan --include-image myapp:1.2.3
```

### Scan a PR diff

```bash
corgea scan --target git:diff=origin/main...HEAD --fail-on CR
```

### Review and apply a fix

```bash
corgea ls --issues --scan-id SCAN_ID
corgea inspect --issue --diff ISSUE_ID
```

### CI/CD pipeline

```bash
corgea scan --fail-on CR --out-format sarif --out-file results.sarif
corgea scan --fail-on CR,malicious --out-format sarif --out-file results.sarif  # also block malicious dependencies
corgea scan --block-on criticals --out-format sarif --out-file results.sarif  # gate on a CI blocking rule from the web app
corgea scan --block-on criticals --skip-if-commit-scanned-recently  # re-runs of an already-scanned commit gate on that scan instead of rescanning
```

The report is written whether or not the gate trips, so a pipeline can both fail
on policy and ingest the results file.

### Upload third-party reports

```bash
corgea upload report.json --project-name my-app
```

### Export results

```bash
corgea scan --out-format html --out-file report.html
corgea scan --out-format sarif --out-file report.sarif
corgea scan --out-format sarif --out-file report.sarif --sbom bom.json  # SARIF + CycloneDX SBOM
```

## Severity Levels

`CR` (Critical), `HI` (High), `ME` (Medium), `LO` (Low)



## Troubleshooting

- **"token invalid" or authentication errors**: The user needs to authenticate with Corgea. Ask them to run `corgea login` (browser OAuth) or `corgea login <API_TOKEN>` to set up credentials. For single-tenant instances, use `corgea login --url https://<instance>.corgea.app <TOKEN>`. Tokens can also be set via the `CORGEA_API_TOKEN` environment variable.
- **Third-party scanner not found**: `semgrep` or `snyk` must be installed and on `PATH`.
- **Upload failures**: The CLI retries 3 times per file. Check file paths and permissions.
