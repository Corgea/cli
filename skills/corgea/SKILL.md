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

### Deps — `corgea deps`

Supply-chain tripwire: looks up every pinned dependency in the project against the public registry (npm or PyPI) and flags anything whose installed version was published within a configurable recency window. Useful for catching very-recent malicious version pushes before they get baked into a build.

```bash
corgea deps                                  # 2-day window, prod deps, both ecosystems
corgea deps --threshold 7d                   # widen the window to 7 days
corgea deps --threshold 48h --fail           # exit 1 if any recent dep is found (CI gate)
corgea deps --fail-unpinned                  # exit 1 if any dep can't be verified because it isn't pinned
corgea deps --ecosystem npm                  # only check npm deps
corgea deps --ecosystem python --include-dev # python only, include dev deps
corgea deps --path ./services/api            # check a different project
corgea deps --json                           # machine-readable output
```

| Flag | Short | Description |
|------|-------|-------------|
| `--ecosystem` | `-e` | `npm`, `python`, or `all` (default) |
| `--threshold` | `-t` | Recency window: `2d`, `48h`, `30m`, `1w`, etc. (default `2d`) |
| `--include-dev` | | Include development dependencies |
| `--fail` | `-f` | Exit non-zero if any recent dep is detected |
| `--fail-unpinned` | | Exit non-zero if any dep is unpinned (manifest with no lockfile, or unpinned `requirements.txt` line) |
| `--json` | | JSON output instead of human text |
| `--path` | `-p` | Project directory (default: `.`) |
| `--check-cve` | | Query Corgea vulnerability database for known CVEs/advisories (requires login) |
| `--fail-cve` | | Exit non-zero if any known CVE is found (requires `--check-cve`) |

### CVE detection

Pass `--check-cve` to query the Corgea vulnerability database for known CVEs and advisories on every pinned dependency. Requires `corgea login` first (or `CORGEA_TOKEN` set). Without a token, the command refuses to start and exits **2** with no report printed.

```bash
# Local: see what would fail
corgea deps --check-cve

# CI: fail the build on any known CVE
corgea deps --check-cve --fail-cve
```

Example finding:

```text
✗ npm lodash@4.17.20: GHSA-xxxx-yyyy-zzzz [TOP-FIX] (severity: high)
  → upgrade to 4.17.21
  https://corgea.app/advisories/GHSA-xxxx-yyyy-zzzz
```

With `--json`, each dependency in `results[]` includes a `cves[]` array and `cve_status` label. Top-level `cve_summary` reports counts (`checked`, `vulnerable`, `clean`, `errors`, `unpinned_not_checked`). CVE fields are omitted when `--check-cve` is not passed.

| Override | Where | Default |
|----------|-------|---------|
| Token | `corgea login` or `CORGEA_TOKEN` env | (required) |
| Vuln-api URL | `CORGEA_VULN_API_URL` env, or `vuln_api_url` in `~/.corgea/config.toml` | `https://vuln-api.corgea.app` |

**Exit codes — CVE CI gating:**

| Exit | Condition |
|------|-----------|
| 0 | No vulnerable deps found, or `--check-cve` not passed, or findings present but no `--fail-cve` |
| 1 | Known CVE found **and** `--fail-cve` passed |
| 2 | `--check-cve` without token; `--fail-cve` without `--check-cve`; parse/validation errors |

**All deps gates (independent flags):**

| Flag | Exit 1 when |
|------|-------------|
| `--fail` | Recent publish, registry error, CVE finding, **or CVE lookup error** |
| `--fail-unpinned` | Unpinned dep detected |
| `--fail-cve` | CVE finding only (lookup errors do **not** trigger) |

Full reference: https://docs.corgea.app/cli/deps

Supported lockfiles (preferred → fallback): npm: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5/v6/v9), `yarn.lock`. Python: `poetry.lock`, `Pipfile.lock`, `uv.lock`, `requirements.txt` (only `==`-pinned lines).

### Install wrappers — `corgea npm` / `yarn` / `pnpm` / `pip` / `uv`

Wraps install commands (`npm install`, `yarn add`, `pnpm add`, `pip install`), resolves what the package manager *would* install against the public registry, and refuses to run the install when a resolved version was published within `--threshold`. Use as a thin replacement for the bare command in CI scripts or interactive shells.

```bash
corgea npm install axios@^1.0.0 --save-dev
corgea pnpm add @types/node@latest
corgea yarn add lodash
corgea pip install requests==2.31.0
corgea pip install -r requirements.txt
corgea uv add django
corgea uv pip install requests==2.31.0
corgea uv sync                             # verifies uv.lock / other Python lockfiles
corgea npm install                       # bare install — verifies the lockfile
```

| Flag | Description |
|------|-------------|
| `--threshold <T>` (`-t`) | Recency window (`2d`, `48h`, `30m`, `1w`). Default `2d`. |
| `--no-fail` | Demote a recent finding from a hard block to a warning (install runs anyway). |
| `--check-only` | Run the verification but never exec the install. |
| `--fail-unpinned` | Also fail on unverifiable specs (URL/git/file/editable) and unpinned `requirements.txt` lines pulled in by `-r`. |
| `--json` | Machine-readable output. |

Spec resolution:

* **npm / yarn / pnpm** — `pkg`, `pkg@latest`, `pkg@1.2.3`, `pkg@^1.0.0`, `pkg@>=1.0.0 <2.0.0`, `pkg@next` (any dist-tag), and scoped names (`@types/node@...`). Ranges are resolved against the registry's full version list using `semver` semantics.
* **pip / `uv pip install` / `uv add`** — `pkg`, `pkg==1.2.3`, `pkg>=1,<2`, `pkg~=1.4`, `pkg[extras]==X`. Exact `==` pins are honoured precisely; other PEP 440 specifiers are resolved against PyPI's release list with a best-effort comparison. `uv sync` with no package args verifies the project lockfile (`uv.lock`, etc.) then runs sync.
* **Skipped (warning, not blocked)** — `git+...`, `file:...`, `./local`, `http(s)://...`, `npm:alias@...`, `workspace:*`, `pip -e`. These are explicit out-of-band sources we can't verify against a registry.

Subcommands other than `install` / `add` / `i` are forwarded straight through to the package manager unchanged, so `corgea npm view ...` and similar just work.

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
corgea deps --threshold 2d --fail
```

### Require pinned, lockfile-resolved dependencies

```bash
corgea deps --fail-unpinned
```

Use this together with `--fail` to gate both freshness and pinning in one CI step:

```bash
corgea deps --threshold 2d --fail --fail-unpinned
```

### Block CI on known CVEs

```yaml
- name: Check dependencies for known CVEs
  env:
    CORGEA_TOKEN: ${{ secrets.CORGEA_TOKEN }}
  run: corgea deps --check-cve --fail-cve
```

Local dry-run first: `corgea deps --check-cve` (no `--fail-cve`) to inspect findings without failing.

### Pre-check an install before letting it run

```bash
corgea npm install axios@^1.0.0
corgea pip install -r requirements.txt --fail-unpinned
```

Ecosystem commands resolve the actual version a package manager would install, block if it was published within the threshold, and otherwise transparently run the install (preserving the package manager's exit code).

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
