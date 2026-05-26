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

## Dependency Security

`corgea deps` is a supply-chain tripwire for pinned npm and Python dependencies. It supports two independent modes: **freshness** (flag recently published versions) and **CVE detection** (query known advisories).

Freshness gate — block builds that pull in a recently published dependency:

```bash
corgea deps --threshold 2d --fail
```

CVE gate — requires `corgea login` (or `CORGEA_TOKEN`):

```bash
corgea deps --check-cve --fail-cve
```

See [Dependency Scanning (CLI)](https://docs.corgea.app/cli/deps) for flags, exit codes, CI integration, and self-hosted vuln-api setup.

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
