# Security Policy

The Corgea CLI is a security tool, and we take the security of the CLI itself seriously. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Report privately through one of these channels:

1. **GitHub private vulnerability reporting** (preferred) — go to the [Security tab](https://github.com/Corgea/cli/security) and click **Report a vulnerability**. This keeps the report private and tracked.
2. **Email** — send details to `adam@corgea.com`.
   <!-- Maintainers: if Corgea has a dedicated security alias (e.g. security@corgea.com), swap it in here. -->

Please include as much of the following as you can:

- The type of issue (e.g. credential leakage, path traversal, insecure TLS handling, dependency vulnerability).
- Affected version(s) — the output of `corgea --version`.
- Affected source files and a description of the impact.
- Step-by-step instructions to reproduce, including any proof-of-concept.
- Whether the issue is exploitable in a default configuration.

## What to expect

- **Acknowledgement** — we aim to confirm receipt within 3 business days.
- **Assessment** — we will investigate and tell you whether the report is accepted, along with our severity assessment.
- **Updates** — we will keep you informed as we work on a fix.
- **Disclosure** — we ask that you keep the report confidential until a fix is released. We are happy to credit you in the release notes unless you prefer to remain anonymous.

## Supported versions

Security fixes are released against the latest published version of the CLI. Please upgrade to the newest release (via npm, pip, or the GitHub Releases page) before reporting an issue, and verify it still reproduces.

## Scope

In scope:

- The CLI source in this repository and its release artifacts (native binaries, the npm package `@corgea/cli`, the pip package `corgea-cli`).
- Handling of credentials and tokens (`~/.corgea/config.toml`, the `CORGEA_TOKEN` environment variable).
- TLS and proxy handling, and the local OAuth callback server used by `corgea login`.

Out of scope:

- The Corgea platform / backend API — report those through the channels above as well, noting the distinction; they are handled by a separate team.
- Findings produced by a scan (those are product output, not CLI vulnerabilities).
- Vulnerabilities requiring a compromised local machine or physical access.

Thank you for practicing responsible disclosure.
