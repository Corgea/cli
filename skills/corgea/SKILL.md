---
name: corgea
description: Scans code for security vulnerabilities using Corgea's AI-powered BLAST scanner and third-party tools, manages findings, and displays AI-generated fixes. Use when the user needs to scan for security issues, upload scan reports, list or inspect vulnerabilities, view fixes, or integrate security scanning into CI/CD.
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

### Install Wrappers — `corgea pip|npm <args...>`

Run a package manager through Corgea's install gate. Install commands with
named targets are resolved against the public registry first, then gated
twice: a version published within `--threshold` (default `2d`) blocks
(exit 1), and each resolved version is checked against Corgea's vuln-api —
known-vulnerable or malicious versions block. CVE checks are public and need
no token; vuln-api lookup outages warn and continue (fail-open). Everything
else passes through with the package manager's own exit code. Git/URL/path
specs (including `pip install .`, PEP 508 `name @ url` direct references, and
npm GitHub shorthand `user/repo`) are noted, never blocked. The install verb
is found behind global flags (`npm --loglevel silent install x` is still
gated). Bare installs (no named targets) and `-r requirements.txt` files are
noted, not gated. `npm ci` passes through ungated.

Wrapper flags (`--force`, `--no-fail`, `-t`) are read between the manager
name and the install verb (`corgea npm --force install x`); flags after the
verb belong to the package manager and are forwarded untouched.

Blocked findings steer to the fix: each advisory line shows
`fixed in <version>` (or `no fixed version known`). When every advisory on a
package has a fix, the gate prints `→ safe version: <name>@<version>` — the
highest fix covering every advisory. Install that version instead.

```bash
corgea pip install requests==2.31.0   # resolves, checks recency + vuln verdict, then runs pip
corgea npm install axios@^1.0.0       # same gate for npm ranges
corgea pip --no-fail install newpkg   # demote a recency block to a warning (vuln blocks still apply)
corgea pip --force install badpkg     # print findings but install anyway (overrides every block)
corgea pip list                       # non-install subcommands pass straight through
```

| Flag | Short | Description |
|------|-------|-------------|
| `--threshold` | `-t` | Recency threshold (`2d`, `12h`). Younger resolved versions block. |
| `--no-fail` | | Demote a recency block to a warning. Does NOT bypass vulnerable blocks. |
| `--force` | | Proceed despite all findings (vulnerable, recent). Findings still print. |

Overrides for testing: `CORGEA_PYPI_REGISTRY`, `CORGEA_NPM_REGISTRY`,
`CORGEA_VULN_API_URL`.

#### Limitations

The gate is a wrapper, not an enforcement boundary. By design it cannot catch:

- **Direct invocation** — running the package manager itself (`pip`, `npm`,
  `python -m pip`) skips the gate entirely.
- **Custom indexes/registries** — `--index-url`, `--registry`, and `.npmrc`/
  `pip.conf` overrides change where packages resolve from. The gate still
  verdicts each `name@version`, but it cannot vouch that a substituted
  registry serves the same artifact those advisories describe.
- **Transitive dependencies** — only the named install targets are verified;
  the rest of the resolved tree installs unchecked.
- **Bare installs and lockfiles** — `npm install` with no targets, `npm ci`,
  and `-r requirements.txt` files run unchecked after a note.

Hard enforcement needs org-level controls — lockfile review, registry
allow-listing — alongside the wrapper.

#### Testing the gate

The staging vuln-api (`https://cve-worker-staging.corgea.workers.dev`) is the
current default endpoint and serves deterministic verdicts for dogfooding.
Known-vulnerable targets:

| Ecosystem | Target | Verdict |
|-----------|--------|---------|
| npm | `axios@0.21.0` | vulnerable — fixed in 0.21.2 |
| npm | `minimist@0.0.8` | vulnerable — fixed in 1.2.2 |
| npm | `node-fetch@2.6.0` | vulnerable — fixed in 2.6.7 |
| PyPI | `mezzanine==6.0.0` | vulnerable — no fixed version known |

Verify the gate end-to-end:

```bash
corgea npm install axios@0.21.0      # exit 1, names CVE-2021-3749, steers to 0.21.2
corgea pip install mezzanine==6.0.0  # exit 1, no fixed version known
```

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
