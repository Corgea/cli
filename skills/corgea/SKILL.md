---
name: corgea
description: Scans code for security vulnerabilities using Corgea's AI-powered BLAST scanner and third-party tools, gates `pip` and `npm` package installs against vulnerable and malicious dependencies (including transitive), manages findings, and displays AI-generated fixes. Use when the user needs to install pip/npm packages safely, scan for security issues, upload scan reports, list or inspect vulnerabilities, view fixes, or integrate security scanning into CI/CD.
allowed-tools: Shell, Read, Grep, Glob, StrReplace
---

# Corgea CLI

Find and fix security vulnerabilities using AI-powered scanning (BLAST), third-party scanners, and AI-generated fixes.

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
corgea scan --fail                             # Exit 1 based on project blocking rules
corgea scan --out-format json --out-file r.json   # Export (json, html, sarif, markdown)
corgea scan --project-name my-service          # Override project name
```

Scan types: `blast` (base AI), `policy` (PolicyIQ), `malicious`, `secrets`, `pii`.

`--only-uncommitted` and `--target` are mutually exclusive. `--fail-on` and `--fail` are mutually exclusive.

### Upload — `corgea upload [report]`

Upload an existing scan report to Corgea.

```bash
corgea upload path/to/report.json              # JSON, SARIF, Coverity XML
corgea upload path/to/report.fpr               # Fortify FPR
corgea upload report.sarif --project-name svc  # Custom project name
cat report.json | corgea upload                # From stdin
```

Supported: Semgrep JSON, SARIF, Checkmarx (CLI/Web/XML), Coverity, Fortify FPR.

### Wait — `corgea wait [scan_id]`

```bash
corgea wait                                    # Wait for latest scan
corgea wait --scan-id SCAN_ID                  # Wait for specific scan
```

### List — `corgea list` (alias: `corgea ls`)

```bash
corgea ls                                      # List scans
corgea ls --issues --scan-id SCAN_ID           # Issues for a scan
corgea ls --sca-issues                         # SCA (dependency) issues
corgea ls --issues --page 2 --page-size 10     # Pagination
corgea ls --issues --scan-id SCAN_ID --json    # JSON output
```

| Flag | Short | Description |
|------|-------|-------------|
| `--issues` | `-i` | List code/SAST issues |
| `--sca-issues` | `-c` | List SCA issues |
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
<!-- END GENERATED CORGEA DEPS SKILL -->

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
such a package blocks as vulnerable, not as fresh.

```bash
corgea pip install requests==2.31.0   # resolves, checks the vuln verdict, then runs pip
corgea npm install axios@^1.0.0       # same gate for npm ranges
corgea pip --force install badpkg     # print findings but install anyway (overrides every block)
corgea pip --json install newpkg      # machine-readable per-target report incl. verdicts
corgea pip list                       # non-install subcommands pass straight through
```

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | | Proceed despite all findings (vulnerable, unverifiable). Findings still print. Also bypasses the wrong-package-manager and PEP 668 refusals, and unparsable-lockfile refusals on `uv sync`/`npm ci`. |
| `--json` | | JSON report instead of text. Per-result `verdict` object + `verdict_mode` + `tree`. Stdout carries only the report; the package manager's output moves to stderr. |

`--json` adds `verdict_mode` (`"public"` or `"authenticated"` from the CLI;
`"none"` can only appear for library callers that disable verdicts)
and a `tree` object: `null` when no tree pass ran; otherwise `mode` is
`"full"` (transitive checked) or `"named-only"` (with a `reason`), plus
`resolved_count` and a `transitive[]` array of `{name, version, origin,
verdict}` for packages beyond the named targets. Vulnerable `verdict`
objects carry a `remediation` field: the safe version covering every
advisory, or `null` when any advisory has no known fix. A top-level
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
```

### Upload third-party reports

```bash
corgea upload report.json --project-name my-app
```

### Export results

```bash
corgea scan --out-format html --out-file report.html
corgea scan --out-format sarif --out-file report.sarif
```

## Severity Levels

`CR` (Critical), `HI` (High), `ME` (Medium), `LO` (Low)



## Troubleshooting

- **"token invalid" or authentication errors**: The user needs to authenticate with Corgea. Ask them to run `corgea login` (browser OAuth) or `corgea login <API_TOKEN>` to set up credentials. For single-tenant instances, use `corgea login --url https://<instance>.corgea.app <TOKEN>`. Tokens can also be set via the `CORGEA_API_TOKEN` environment variable.
- **Third-party scanner not found**: `semgrep` or `snyk` must be installed and on `PATH`.
- **Upload failures**: The CLI retries 3 times per file. Check file paths and permissions.
