---
name: rpi
description: Run the RPI research-to-implementation workflow in a Cursor Cloud checkout. Use only when the user explicitly asks for RPI.
disable-model-invocation: true
---

# RPI for Cursor Cloud

Run this sequence in the current Cursor Cloud checkout:

```text
questions -> research -> design -> outline -> visual baseline -> implementation -> simplification -> verification + visual final -> local commit -> PR artifacts
```

You are the root orchestrator. Keep artifact selection, state validation, user contact, path ownership, final verification, and stage acceptance in this context. Use `Task` only for the stages listed below, one stage at a time in the foreground.

## Resolve the installation and repository

Resolve the absolute path of this loaded `SKILL.md`, then set `<skills-root>` to the parent of its containing `rpi` directory. Resolve every downstream instruction as `<skills-root>/<skill-name>/SKILL.md`. Do not search personal configuration directories or fall back to another installation. Stop if a required sibling skill is absent.

With `Shell`, resolve and retain:

- canonical repository root from `git rev-parse --show-toplevel`;
- branch from `git symbolic-ref --short HEAD`;
- default branch from `refs/remotes/origin/HEAD`, or the repository's documented default when that ref is absent;
- baseline `HEAD`;
- full `git status --porcelain=v1 --untracked-files=all`.

Before creating or resuming artifacts, require all of the following:

- `HEAD` is attached to a named branch;
- the branch is not the default branch;
- `git ls-files '.humanlayer/**'` returns no paths.

A new run additionally requires a clean source working tree. A resumed run must instead match the exact saved `expected_source_status`, `expected_head`, and source-snapshot requirements below; do not reject or accept a resume from cleanliness alone.

Resolve the repository-local exclude file with `git rev-parse --git-path info/exclude`. Using `Shell`, append an exact `/.humanlayer/` line only when `grep -Fqx '/.humanlayer/' <exclude-file>` does not find it. Recheck that a probe beneath `.humanlayer/` is ignored. Never edit a shared or global ignore file.

## Artifact and resume contract

Resolve `.humanlayer/tasks/<task-slug>/` beneath the repository. The slug is the normalized ticket identifier plus a short kebab-case description when a ticket exists, otherwise a short kebab-case task name. Canonicalize the tasks parent and the proposed task path without following a final symlink, and require the proposed path to remain a direct child of that parent.

Before writing any task artifact, inspect the proposed task path with `lstat` semantics:

- If it is absent, require the clean new-run anchor, create the directory, write `ticket.md` with `Write`, and initialize state. If the input is a Linear URL, use the team Linear connector when available; otherwise use `AskQuestion` to request the ticket text. Include the source URL when known.
- If it exists, do not write or truncate anything. Reject a symlink, non-directory, missing ticket/state pair, extra workflow state, malformed state, unsupported schema, or mismatched task identity. For a valid RPI run, verify the canonical repository, branch, baseline and expected `HEAD`, exact ticket path/hash and task-identity hash, every artifact path/hash and hash-history transition, current stage, expected source status, allowlist, visual-manifest current/history hashes, and any authorized source snapshot. Resume at the first incomplete saved stage without rewriting completed artifacts or history.

The task identity is the SHA-256 of canonical JSON containing the exact resolved ticket text and source URL (or `null`), with sorted keys, UTF-8 encoding, and no insignificant whitespace. A same-slug directory that cannot prove that exact identity is a collision and blocks. Never turn a collision into a new run and never overwrite `ticket.md` or `rpi-state.json` to recover it.

Maintain `.humanlayer/tasks/<task-slug>/rpi-state.json` with `Write` or `StrReplace`. It contains:

```json
{
  "schema_version": 1,
  "workflow": "rpi",
  "repository": "<canonical repository root>",
  "branch": "<branch>",
  "default_branch": "<default branch>",
  "baseline_head": "<baseline HEAD>",
  "baseline_status": [],
  "expected_head": "<expected HEAD>",
  "expected_source_status": [],
  "current_stage": "research-questions",
  "task_identity_sha256": "<hex digest>",
  "implementation_allowlist": [],
  "authorized_source_snapshot": null,
  "stages": {
    "ticket": {"path": "<absolute path>", "hash": "<git hash-object result>"}
  },
  "visual_validation": {
    "applicable": null,
    "reason": null,
    "manifest": null,
    "baseline_images": [],
    "final_images": [],
    "report": null
  }
}
```

After each artifact stage, add its canonical absolute path and `git hash-object --no-filters -- <path>` result. Persist the next `current_stage`, `expected_head`, and exact porcelain-v2 source status after each accepted transition. Before launching or resuming any stage, recompute every recorded current hash, confirm the repository, branch, default branch, baseline and expected `HEAD`, baseline status, and exact current source status, and reject missing, duplicated, reordered, or conflicting artifacts. When a stage intentionally revises an existing artifact, first verify its recorded hash, update that exact file, retain the prior hash as history, and replace its current hash in state. Never infer progress from filenames alone. After implementation begins, `HEAD` must remain at the baseline until the commit stage succeeds.

### Canonical source snapshot

Read the [canonical source-snapshot schema](../ci-commit/references/source_snapshot.md) completely and use its exact byte encoding, ordering, and framing. Block on any conflicting snapshot instruction.

Bind the commit authorization to exact repository bytes, not only changed path names or porcelain status. After the final verification and finalized visual report, derive a canonical source snapshot from the repository root, write its exact canonical bytes once to the immutable regular file `<task-dir>/source-snapshots/verification-1.json`, and persist its canonical path and SHA-256 digest in `authorized_source_snapshot`. The ignored snapshot file is not source and cannot include itself.

Build it independently with `git status --porcelain=v2 -z --untracked-files=all`, `git ls-files --stage -z`, and raw filesystem reads. Include the baseline and current `HEAD`. For every staged, unstaged, deleted, renamed, copied, type-changed, or untracked source path, record base64 of its raw repository-relative path bytes; base64 of the complete raw porcelain-v2 record; base64 old and new endpoints for rename/copy records; `HEAD` and index modes/object IDs when present; filesystem kind and full `lstat` mode; SHA-256 of current regular-file bytes or symlink-target bytes; and the prospective Git index mode/object ID for the exact worktree state after repository attributes. Use an explicit absent marker for deletions. Do not follow symlinks. Include both endpoints of renames and copies in the implementation allowlist. Reject quoting ambiguities, duplicate raw paths, submodules, paths outside the allowlist, any `.humanlayer/**` path, or an index that differs from `HEAD` before validation or Luna; still record the empty staged state so an unexpected staged edit changes the digest.

Serialize the snapshot with the shared fixed schema version, sorted object keys, entries sorted by decoded raw path bytes, compact JSON separators, UTF-8 encoding, and exactly one trailing LF byte. No other whitespace is allowed. Its authorization digest is SHA-256 over those exact bytes. Recompute the complete snapshot immediately before dispatching Luna and require byte-for-byte canonical JSON equality and digest equality. Any edit, mode change, stage operation, path transition, or new/untracked/deleted path invalidates authorization and blocks; rerun verification rather than updating the saved snapshot in place.

Visual-validation files use the same path-and-hash rule. Record the canonical manifest, every problem/before/after/design image, and the final HTML report. The manifest is intentionally updated between baseline and final modes: verify the baseline hash immediately before final mode, retain it in `previous_hashes`, then record the new current hash. Images and reports are immutable once recorded. All visual evidence must stay beneath the ignored task directory and is permanently excluded from source ownership, staging, and commits.

An accepted `Task` result has exactly these fields:

```text
STATUS: complete|blocked|needs_root
ARTIFACTS:
- <absolute path or none>
DECISIONS:
- <decision tagged recommended or assumed, or none>
QUESTIONS:
- <question for root or none>
VERIFICATION:
- <exact command with numeric exit code, or none>
CHANGED_PATHS:
- <absolute path or none>
BLOCKER: <exact blocker or none>
```

Reject malformed results. Canonicalize every path. For artifact stages, require exactly the expected artifact beneath the task directory and no source changes. For source-changing stages, derive changed paths independently with Git and require an exact match. A `blocked` result stops. For `needs_root`, ask only the returned consequential question with `AskQuestion`, then relaunch the same stage with the answer and prior artifact path.

## Stage routing

| Stage | Task `subagent_type` | Instruction |
|---|---|---|
| Research questions | `brain-terra` | `create-research-questions` |
| Research | `brain-terra` | `create-research` |
| Design discussion | `brain-opus` | `create-design-discussion` |
| Structure outline | `brain-sol` | `create-structure-outline` |
| Implementation | `brain-grok` | `implement-outline` |
| Simplification | `brain-sol` | `simplify` |
| Commit | `brain-luna` | `ci-commit` |
| PR artifacts | `brain-sol` | `describe-pr` |

For each `Task`, use the table's exact `subagent_type`, `model: inherit`, foreground execution, and a self-contained prompt containing the absolute instruction path, canonical repository and task paths, baseline, exact input paths and hashes, applicable decisions, and required output envelope. Never use a generic task type when the named brain exists.

## Run the pipeline

### 1. Research questions

Launch `brain-terra` with the absolute ticket path and `<skills-root>/create-research-questions/SKILL.md`. Require one `research-questions` artifact. Ask it to identify current control surfaces and the smallest viable scope using current-state evidence only.

### 2. Research

Launch a fresh `brain-terra` with only the absolute research-questions path and `<skills-root>/create-research/SKILL.md`. Do not pass the ticket. Require one objective research artifact with file-and-line evidence.

### 3. Design discussion

Launch `brain-opus` with the task directory and `<skills-root>/create-design-discussion/SKILL.md`. Require a Smallest Viable Control decision that compares existing control surfaces, selects the least complex sufficient scope, and justifies any new persisted state, feature flag, dependency, infrastructure, or cross-service control. Resolve consequential open questions through the root `AskQuestion` flow before proceeding. On relaunch, pass the exact existing design-artifact path, its recorded current hash, and the user's answer; require the stage to revise that file in place and return its replacement hash rather than create another design artifact.

### 4. Structure outline

Launch `brain-sol` with the task directory and `<skills-root>/create-structure-outline/SKILL.md`. Require thin vertical phases, explicit non-overlapping path ownership, exact runnable automated commands with working directories, honest manual checks, and a complete **Visual Validation Contract**. That contract must declare the boolean `applicable: true` or `applicable: false`, give the reason, and define no more than six reproducible scenarios when true. Reject string or missing discriminators. Do not create or suggest another checkout.

### 5. Visual baseline

Resolve `<skills-root>/visual-validation/SKILL.md`, read it completely with `Read`, and execute its `baseline` mode against the canonical task directory before any source edit. Validate its documented return contract.

- When the outline contract has `applicable: false`, require the same boolean, a concrete matching reason, no manifest, and no evidence directory.
- When the outline contract is applicable, require `applicable: true`, `blocked: false`, a canonical manifest with `baseline-captured` status, and a before image for every declared scenario. A missing capture mechanism, missing scenario image, capture failure, scenario mismatch, or blocked manifest stops RPI before implementation.

Hash and record the manifest and every baseline, problem, or selected-design image in state. Recheck that all paths remain beneath the ignored task directory and that Git reports none as tracked or staged.

### 6. Implementation

Capture status again and require no unexplained source changes. For applicable visual work, revalidate every baseline evidence hash. Launch `brain-grok` with the absolute outline path and `<skills-root>/implement-outline/SKILL.md`. Instruct it to run all phases sequentially through fresh `outline-implementer-agent` tasks, never edit artifacts, and never stage or commit. Validate its result and independently derive the exact implementation allowlist from baseline-to-working-tree changes. Visual evidence and every `.humanlayer/**` path are excluded from that allowlist.

### 7. Simplification

Launch `brain-sol` with `<skills-root>/simplify/SKILL.md` and the exact implementation allowlist. It may change only those paths, must preserve behavior and public interfaces, must rerun affected checks, and must not stage or commit. Treat a no-op as success. Recompute the allowlist and reject any path outside it.

### 8. Verification and visual final

Using root `Shell`, rerun every exact automated command from every outline phase in its recorded working directory, followed by documented repository-wide test, lint, typecheck, and build commands. Record each command verbatim and its numeric exit code. Do not substitute an equivalent command. Stop on any failure, unexplained diff, artifact change, ownership violation, or changed `HEAD`. Manual checks remain explicitly outstanding unless direct evidence proves them.

Then read `<skills-root>/visual-validation/SKILL.md` again and execute its `final` mode against the task directory with the completed root verification results, `validationAttemptId: validation-1`, and `validationAttempt: 1`. For `applicable: false`, require the same non-applicability result as baseline. For `applicable: true`, require all of the following before commit:

- the baseline manifest and images matched their recorded hashes before final mode;
- every declared scenario has a distinct final image produced with the same setup, actions, viewport, ready state, and capture point;
- every expected visual outcome is recorded as present;
- the preliminary self-contained HTML report was rendered successfully with a zero exit code.

Treat missing evidence, scenario drift, an unmet outcome, sensitive content, a blocked result, or renderer failure as a verification failure. After successful captures, the RPI root merges its complete verification result into the manifest: set the final validation date and verdict, preserve current scenario observations, record every exact check, and replace pending blockers with the complete deduplicated list. Rerun the installed visual renderer against the same `YYYY-MM-DD-visual-validation-attempt-1.html` path and require exit code zero. Require a passing final verdict and no blocking findings. Record the finalized manifest's new current hash, all final-image hashes, and the final report hash in state. Reconfirm that no visual-evidence path is tracked, staged, or included in the implementation allowlist.

With those exact verified bytes still present, create the immutable canonical source-snapshot file defined above. Persist its path and SHA-256 digest as the sole commit authorization. Recompute the live snapshot in memory after the file and state writes and require exact canonical-byte and digest matches; ignored task-artifact writes must not affect the source snapshot.

### 9. Local commit

Launch `brain-luna` only after automated and applicable visual verification pass and an exact recomputation of the authorized source snapshot succeeds. Provide `<skills-root>/ci-commit/SKILL.md`, the verified implementation allowlist, baseline, outline, command evidence, visual-verification verdict, canonical source-snapshot path, and its SHA-256 digest. Require Luna to verify that immutable file and independently reconstruct and compare the live snapshot before touching the index, stage explicit paths only, prove every staged blob and mode equals the snapshot's prospective index state, never use `git add -A`, create one local commit, never push, and exclude every artifact, visual-evidence, or unrelated path. Verify the commit's path set and tree entries against the authorization, verify excluded changes remain unstaged, and record the commit hash in state.

### 10. PR artifacts

Launch `brain-sol` with `<skills-root>/describe-pr/SKILL.md`, the ticket, outline, verified diff, simplification summary, command evidence, commit hash, and task directory. It may write only the requested PR-description and walkthrough artifacts beneath the task directory. It must not commit, push, or create or update a pull request.

Cursor owns branch push and pull-request creation after the Cloud run. Never claim a PR exists without a URL supplied by Cursor.

## Final report

Return:

- canonical paths and hashes for ticket, questions, research, design, outline, visual manifest, every evidence image, final visual report, PR description, and optional walkthrough;
- branch, baseline, local commit hash, and committed path set;
- authorized source-snapshot digest and proof that the committed tree entries matched it;
- implementation and simplification summaries;
- every verification command with numeric exit code;
- visual applicability, scenarios, capture results, and final verdict;
- outstanding manual checks;
- explicit confirmation that Cursor owns push and PR creation.

Never claim an artifact, check, commit, or PR exists without direct evidence.
