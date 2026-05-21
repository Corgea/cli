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

### Verify Deps — `corgea verify-deps`

Supply-chain tripwire: looks up every pinned dependency in the project against the public registry (npm or PyPI) and flags anything whose installed version was published within a configurable recency window. Useful for catching very-recent malicious version pushes before they get baked into a build.

```bash
corgea verify-deps                                  # 2-day window, prod deps, both ecosystems
corgea verify-deps --threshold 7d                   # widen the window to 7 days
corgea verify-deps --threshold 48h --fail           # exit 1 if any recent dep is found (CI gate)
corgea verify-deps --ecosystem npm                  # only check npm deps
corgea verify-deps --ecosystem python --include-dev # python only, include dev deps
corgea verify-deps --path ./services/api            # check a different project
corgea verify-deps --json                           # machine-readable output
```

| Flag | Short | Description |
|------|-------|-------------|
| `--ecosystem` | `-e` | `npm`, `python`, or `all` (default) |
| `--threshold` | `-t` | Recency window: `2d`, `48h`, `30m`, `1w`, etc. (default `2d`) |
| `--include-dev` | | Include development dependencies |
| `--fail` | `-f` | Exit non-zero if any recent dep is detected |
| `--json` | | JSON output instead of human text |
| `--path` | `-p` | Project directory (default: `.`) |

Supported lockfiles (preferred → fallback): npm: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5/v6/v9), `yarn.lock`. Python: `poetry.lock`, `Pipfile.lock`, `uv.lock`, `requirements.txt` (only `==`-pinned lines).

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

### Block builds that pull in a freshly-published dependency

```bash
corgea verify-deps --threshold 2d --fail
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
