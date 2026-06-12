---
date: 2026-06-12
researcher: claude
git_commit: dfac68e
branch: install-vuln-gate
repository: cli
status: draft
tags: [jtbd, spec, install-gate, supply-chain, agents]
last_updated: 2026-06-12
last_updated_by: claude
---

# Gate Package Installs

**Date**: 2026-06-12
**Researcher**: claude
**Git Commit**: dfac68e
**Branch**: install-vuln-gate

## Job Statement

**Full JTBD**: When a coding agent or developer is about to install a package,
I want the install to pass through a gate that blocks vulnerable, malicious,
or suspiciously new versions and steers to a safe one, so I can trust that
development — especially autonomous, agent-driven development — never
introduces a supply-chain compromise.

**Trigger Context**: Agents install packages autonomously with nobody
watching. Developers add dependencies with no check at the decision moment.
Malware campaigns spread through registries in hours, faster than any CI
scan. Security teams have no control point at install time.

**Success Indicators**:
- An agent hits a block, reads the refusal, and installs the safe version —
  no human in the loop.
- Gated installs catch real vulnerable/malicious packages; `--force` stays rare.
- Teams and agent sessions gate installs weekly — adoption, not a demo.
- End state: with a token, nothing unverifiable gets through (fail-closed).

## Why restart

The previous attempt (branch `install-vuln-gate`, 60+ commits, ~10.7k lines)
built the right thing but is unreviewable as one PR. Three things ate it:

1. **Scope creep to the full tree.** Named-target gating grew into resolving
   the entire would-install set per manager — dry-runs, lockfiles, bare
   installs — each with its own quirks.
2. **Edge-case hardening.** Fail-open/fail-closed modes, retries, yanked
   releases, PEP 668, constraint files, JSON stdout purity — correctness
   tails with no phase boundary to stop at.
3. **Test infra weight.** The vuln-api stub, integration harness, and
   fixtures became a project inside the project, built incidentally.

The restart keeps the learnings and the proven modules, and lands the work as
one PR per phase, each with explicit exit criteria.

**Process rule**: one phase = one PR. A phase that can't land as a reviewable
PR is two phases.

## Phases

### Phase 0: Foundation — vuln-api contract + test harness

**Scope**: The vuln-api client and its versioned contract (clean / vulnerable
/ malware / unknown verdicts, remediation data). In-process test stub, gated
out of release builds. Shared integration-test scaffold. Deterministic
staging targets documented (`axios@0.21.0`, `minimist@0.0.8`,
`node-fetch@2.6.0`, `mezzanine==6.0.0`).

**Not Included**: Any user-facing command. Auth/token handling. Retries.

**Entry Criteria**: Staging worker (`cve-worker-staging`) serving
deterministic verdicts.

**Exit Criteria**: Contract tests green against both the stub and staging.
Another phase can write an integration test in under 20 lines of setup.

**Harvest**: `src/vuln_api/mod.rs`, `src/vuln_api_stub/mod.rs`,
`tests/common/mod.rs`, `tests/fixtures/vuln_api/`.

### Phase 1: Core gate (SHIP) — `corgea pip|npm install <named targets>`

**Scope**: Install-verb detection behind global flags. Named-spec parsing
(exact pins and ranges). Registry resolution (PyPI, npm). Two independent
blocks: recency (`-t`, default `2d`) and vuln verdict. Refusal output built
for agent self-correction: per-advisory `fixed in <version>` lines and a
`→ safe version: <name>@<version>` steer. `--force` (override everything),
`--no-fail` (demote recency only). Git/URL/path specs pass through with a
note, never blocked. Non-install subcommands pass straight through. Public
mode only: no token, lookup outages warn and continue (fail-open).
`skills/corgea/SKILL.md` section, including the limitations doc (wrapper, not
an enforcement boundary).

**Not Included**: Transitive/tree resolution. Bare installs, lockfiles,
`npm ci`. `-r requirements.txt` parsing (noted, not gated). `--json`. Token
auth and fail-closed mode. yarn/pnpm/uv. Retry logic.

**Entry Criteria**: Phase 0 merged.

**Exit Criteria**: Dogfood pass — a real agent session with the skill
installed hits a staging-target block and self-corrects to the safe version
unprompted. All deterministic staging targets block with exit 1.

**Harvest**: `src/precheck/parse.rs`, `detect.rs`, `verdict.rs`, `render.rs`
(trimmed to named-target paths), `src/verify_deps/registry.rs`.

### Phase 2: Depth (SHIP) — the full would-install set

**Scope**: pip tree via `pip install --dry-run`; npm tree via isolated
`npm install --package-lock-only` in a temp dir. Bare `npm install` gated
from the nearest `package.json`; `npm ci` gated from the lockfile.
Transitive findings labeled by provenance. Honest named-only fallback with a
printed warning when a dry-run fails or `--prefix`/`-g` redirects the root.
`-r requirements.txt` fallback parsing. Bounded verdict pool (fixed at 8).

**Not Included**: uv/yarn/pnpm. `--json`. Auth.

**Entry Criteria**: Phase 1 shipped and dogfooding.

**Exit Criteria**: A vulnerable transitive dep blocks the install. A
vulnerable lockfile blocks `npm ci`. Fallback warnings fire when and only
when the tree pass didn't run.

**Harvest**: `src/precheck/tree.rs`, `tests/cli_tree.rs`,
`tests/cli_bare_install.rs`, `tests/cli_npm_ci.rs`.

### Phase 3: Breadth + guarantee

**Scope**: Three independent lanes, each its own PR:
1. **uv** — `uv pip install`/`uv add`/`uv pip sync` via `uv pip compile`;
   `uv sync` from `uv.lock`. yarn/pnpm named-only with honest ungated notes.
2. **Machine output** — `--json` (stdout purity, `verdict_mode`, `tree`
   object, `remediation` field).
3. **Org guarantee** — authenticated fail-closed mode, custom-URL token
   opt-in, transient-failure retries, PEP 668 refusal, yanked-release
   handling.

**Not Included**: Org policy config, telemetry, registry allow-listing —
future work, separate PRD.

**Entry Criteria**: Phase 2 shipped.

**Exit Criteria**: Per lane. Lane 3's bar: with a token, an unverifiable
package or a vuln-api outage blocks the install.

**Harvest**: `src/precheck/uv.rs`, `tests/cli_uv_sync.rs`,
`tests/cli_verdict.rs` (auth modes), JSON paths in `render.rs`.

## Known dead ends — do not rebuild

Built and deliberately removed in the previous attempt:
- npm audit warn-only second opinion (`ccceb7a`)
- Steer re-verification pass (`e62399c`)
- `--concurrency` flag — fixed pool of 8 instead (`bfc8cf1`)
- Persisted `vuln_api_url` config — env var only (`204fb47`)
- Standalone vuln-api-stub binary — in-process stub instead (`b6c2e83`)

## Open Questions

- Recency default: `2d` carried over from the spike — validate against real
  release cadence data before P1 ships.
- Does `--json` pull forward into P1 if agent dogfooding wants structured
  output over refusal text?
- Staging worker is the current default vuln-api endpoint — when does the
  production worker take over, and who owns its seed data?
- Telemetry (catch rates, `--force` usage) — needed to measure success
  indicators, but where does it report? Separate PRD.

## References

- Previous attempt: branch `install-vuln-gate` (head `dfac68e`) — harvest
  source and design reference.
- Agent contract: `skills/corgea/SKILL.md` (limitations section at
  `dfac68e`).
- Staging verdicts: `https://cve-worker-staging.corgea.workers.dev`
  (source: `/Users/juan/Code/corgea/vuln-api`).
- Flag validation pattern to mirror: `src/main.rs` (blast-only flag
  rejection).
