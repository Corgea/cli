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

### Beta / pre-release builds
Opt-in builds that ship ahead of stable. Actively developed — expect breaking changes.
```
npm install -g @corgea/cli@beta
pip install --pre corgea-cli
```
Stable installs (`@corgea/cli`, `corgea-cli`) always resolve to the latest non-beta release.

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
