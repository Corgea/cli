# Corgea CLI
Corgea CLI is a powerful developer tool that helps you find and fix security vulnerabilities in your code. Using our AI-powered scanner (blast) and our platform, Corgea identifies complex security issues like business logic flaws, authentication vulnerabilities, and other hard-to-find bugs. The CLI provides commands to scan your codebase, inspect findings, interact with fixes, and much more - all designed with a great developer experience in mind.


For full documentation, visit https://docs.corgea.app/cli

## Installation

### Using npm
```
npm install -g @corgea/cli
```
The npm package bundles native binaries for all supported platforms. The correct binary for your OS and architecture is selected automatically at runtime.

### Using pip
```
pip install corgea-cli
```

### Manual Installation
You can get the latest binaries for your OS from https://github.com/Corgea/cli/releases.

### Setup
Once the binary is installed, login with your token from the Corgea app.
```
corgea login <token>
```

## Dependency Inventory (offline)

`corgea deps` builds a dependency inventory from npm, Python, and Java manifests
and lockfiles, then evaluates a pinning policy (DEP rules). Runs fully offline —
no token or network required.

```bash
corgea deps scan                       # table report for the current directory
corgea deps scan --format agent        # compact TSV for coding agents
corgea deps scan --format json         # JSON inventory on stdout
corgea deps scan --format quiet        # no stdout; exit code still applies
corgea deps scan --fail-on high        # exit 1 if any finding is >= high
corgea deps scan --out-format json     # machine-readable (json or sarif)
corgea deps graph --format json        # print the resolved dependency graph
corgea deps explain <package> --format agent  # show why a package is present
corgea deps diff --base origin/main --format json
corgea deps sbom --format cyclonedx    # emit a CycloneDX SBOM
corgea deps policy init --exist-ok     # write starter policy, or keep existing file
```

`corgea deps` defaults to `--format agent` when an agent environment is detected (`AI_AGENT`, `CODEX_SANDBOX`, `CLAUDECODE`, and related agent variables). Use `--format human` to force the normal terminal output.

See [Dependency Scanning (CLI)](https://docs.corgea.app/cli/deps) for the full flag and exit-code reference.

## Install Gate

Prefix a package-manager install with `corgea` to vet every package it would
install — named **and transitive** — against Corgea's vulnerability API *before*
anything lands on disk. Known-vulnerable or malicious versions block the install;
a clean set runs the underlying command untouched. Works with `pip`, `npm`,
`yarn`, `pnpm`, and `uv`.

No token required — baseline public CVE checks run out of the box. Try it:

```bash
corgea npm install lodash@4.17.20      # blocks: known-vulnerable (CVE-2025-13465), exits 1
corgea pip install requests            # resolves, checks the verdict, then runs pip
corgea npm install axios@^1.0.0        # ranges resolve to a concrete version first
corgea pip --force install <pkg>       # print findings but install anyway
corgea pip list                        # non-install subcommands pass straight through
```

`corgea pip install` and `corgea npm install` resolve the **full would-install
set** (named + transitive) via a safe dry-run, so a vulnerable *transitive*
dependency blocks too. Blocked findings steer to the fix: each advisory shows
`fixed in <version>`, and the gate prints the safe version to install instead.

The gate also blocks **freshly published** packages — anything published within
the recency window (default 14 days) — to catch just-shipped typosquats and
hijacks before advisory feeds catch up. It is on by default; turn it off with
`recency_gate = false` in `~/.corgea/config.toml`, retune the window with
`recency_threshold_days`, or pass `--force` for a one-off install.

Logging in (`corgea login`) upgrades the gate to authenticated enforcement —
unverifiable packages, resolution errors, and lookup failures then fail closed
(public mode warns and continues). Wrapper flags (`--force`, `--json`) go between
the manager and its command: `corgea npm --force install <pkg>`.

See [the CLI docs](https://docs.corgea.app/cli) for the full flag and exit-code reference.

## Development Setup

### Prerequisites
- Python 3.8 or higher
- Rust toolchain (for maturin)

### Using venv (Python Virtual Environment)
1. Create and activate a virtual environment:
   ``` 
   python -m venv .venv
   source .venv/bin/activate  # On Unix/macOS
   .venv\Scripts\activate     # On Windows
   ```

2. Install dependencies:
   ```
   pip install maturin
   ```

3. Build and install the package in development mode:
   ```
   maturin develop
   ```

### Using Conda
1. Create and activate a conda environment:
   ```
   conda create -n corgea-cli python=3.8
   conda activate corgea-cli
   ```

2. Install dependencies:
   ```
   pip install maturin
   ```

3. Build and install the package in development mode:
   ```
   maturin develop
   ```

Note: After making changes to Rust code, you'll need to run `maturin develop` again to rebuild the package.
