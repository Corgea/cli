---
name: validate-implementation
description: "Explicit-only: validate completed work against an approved plan or structure outline, execute its exact checks, and produce a binary evidence-backed verdict."
disable-model-invocation: true
---

# Validate Implementation

Validate the current implementation against its approved plan and current repository state. This is a read-only source-code review: only task-local validation and visual-evidence artifacts may be written.

## Input

Require an absolute plan or approved structure-outline path and these execution inputs:

- an absolute task directory;
- `validationAttemptId` in the exact form `validation-N` and a positive integer `validationAttempt: N` assigned by the caller;
- `changedPathAllowlist`, an explicit list of repository-relative files owned by the implementation;
- the implementation-start SHA when the invoking workflow recorded one.

Also accept:

- an ExecPlan path for additional context;
- ticket or review-feedback files;
- an existing visual-evidence manifest.
- `visualFinalEvidenceMode: capture-in-validator` (default) or `pre-captured`.

If the plan path cannot be derived from the task directory, use **AskQuestion** for that path. In an unattended RPI or Shipwright stage, return `blocked` to the orchestrator instead of contacting the user.

Shipwright and any other retry-capable workflow must supply both attempt fields for every run, starting with `validationAttemptId: validation-1` and `validationAttempt: 1`, then incrementing both once per validation after a repair. Require the numeric suffix and integer to match. A standalone or single-pass RPI validation may default both fields to `validation-1` and `1` only when its output path does not already exist. Missing, malformed, mismatched, or reused attempt identity is blocking.

## Changed-path ownership

Validate ownership before writing any validation or visual artifact. Normalize `changedPathAllowlist` to unique repository-relative file paths. Reject an empty list, absolute paths, directories, globs, paths outside the repository, and `.humanlayer/**` entries.

Use **Shell** to derive the Git-changed path set as the union of:

1. committed changes from the caller's implementation-start SHA through `HEAD`; when that SHA is unavailable in a standalone run, use the merge base with the resolved default branch and record that fallback;
2. staged and unstaged changes relative to `HEAD`;
3. untracked, non-ignored files from `git ls-files --others --exclude-standard`.

Use name-status output with rename/copy detection and include both old and new paths for a rename or copy. Record which Git source contributed each path. Tracked `.humanlayer/**` is always an ownership violation; ignored task artifacts are not implementation paths.

Compute:

- allowlisted and changed paths;
- allowlisted but unchanged paths;
- changed paths outside the allowlist.

Every changed path outside the allowlist is a blocking finding and forces `FAIL`, even when tests pass. Continue safe read-only checks so the validation document contains complete evidence. Recompute the set after delegated review and visual capture; any newly introduced source path receives the same treatment.

## Establish evidence

1. Use **Read** to read every provided document fully. When given a task directory, use **Shell** to inventory it and select its approved plan or structure outline; do not require a `-plan.md` suffix.
2. Read all source and test files named by the plan, plus every changed file relevant to its promised behavior.
3. Record repository root, branch, `HEAD`, `git status --short --untracked-files=all`, staged paths, and the current committed and working-tree diffs.
4. Record the changed-path ownership evidence derived above.
5. Extract every required behavior, automated command, manual check, and the plan's Visual Validation Contract. Claims in tickets or comments are context, not proof.
6. Use this precedence when documents conflict: implementation plus executed checks → plan → structure outline → design discussion → research → ticket.

Do not edit source, tests, the plan, an ExecPlan, or historical artifacts.

## Execute exact checks

Run every automated verification command required by the approved plan with **Shell**, exactly as written and from its specified working directory. Normalize whitespace only when matching a reported command back to the plan; a substituted, expanded, or similar command does not satisfy the requirement.

For each command, record:

- exact command text;
- working directory;
- numeric exit code;
- concise relevant output;
- pass, fail, or blocked status.

If the plan omits a command but names a concrete repository check, use the repository's documented command and label it `additional`. Never invent a command. A missing, altered, nonzero, or unavailable required command is a validation failure unless the plan explicitly marks it manual-only.

## Visual validation

Require the Visual Validation Contract to contain exactly one boolean discriminator, `applicable: true` or `applicable: false`; reject string values and unknown/missing values. When it is `applicable: true`, resolve the sibling `../visual-validation/SKILL.md` relative to this skill and read it fully.

With `visualFinalEvidenceMode: capture-in-validator`, perform its `final` mode with the absolute task directory, baseline manifest, current automated-check results, `validationAttemptId`, and `validationAttempt`.

With `visualFinalEvidenceMode: pre-captured`, require the caller to supply the canonical manifest path and current SHA-256 plus immutable baseline/final screenshot and preliminary-report paths/hashes for this exact attempt. Verify that the manifest has `final-captured` or `blocked` status, its attempt pair and scenario set exactly match, every supplied file is a regular canonical file beneath the task directory with the saved hash, and no expected attempt path is missing or extra. Do not invoke `visual-validation` final mode again or overwrite any attempt-specific screenshot. The verdict-finalization step below may rerender the verified preliminary report at that same path exactly once. Treat malformed, stale, cross-attempt, or missing evidence as blocking.

Require each planned scenario to repeat the same setup, actions, ready state, viewport, and capture point. Require an after screenshot, evidence-based observation, expected-outcome result, updated manifest, and preliminary rendered HTML report. At this stage the visual skill records capture outcomes and current checks but leaves the overall verdict pending. Missing baseline evidence, capture capability, expected outcome, or renderer success is blocking.

When the contract has `applicable: false`, record its concrete reason and create no image artifact.

## Independent review

Always obtain one independent review after the exact checks finish. Snapshot repository status, then launch one foreground **Task** with `subagent_type: qa` and `model: inherit`. Give it:

- absolute repository, plan, task-directory, and optional ExecPlan paths;
- the current diff summary;
- changed-path allowlist and derived ownership evidence, including every outside path;
- every required behavior and manual criterion;
- every exact command, exit code, and relevant result;
- visual-validation result or the `applicable: false` reason;
- the question: should the implementation receive `GO` or `NO-GO` against the plan, and what blocking findings remain?

Require this result:

- `GO` or `NO-GO`;
- blocking findings or `None`;
- missing or weak evidence or `None`;
- confidence and key assumptions.

Prove the reviewer did not change the filesystem. A missing, malformed, ungrounded, or writing reviewer result counts as missing independent evidence and forces a failure. Use `codebase-analyzer` instead only when the plan requires an implementation-path trace that the QA contract cannot supply; apply the same read-only snapshot and evidence rules.

## Verdict and artifacts

Compare every planned phase and success criterion against code, executed commands, visual evidence, and the independent review. The local validator owns the verdict:

- `PASS`: every required behavior is present and every required automated check passed; required visual and manual evidence is complete.
- `FAIL`: any required behavior is absent, contradicted, unproven, blocked, failing, unrun, still awaiting mandatory manual validation, or changed outside the caller-supplied path allowlist.

When visual validation applies, merge the complete validation result into the task-local manifest: set the final validation date and verdict, preserve scenario observations, record all exact checks, and replace the pending blocking findings with the complete deduplicated list. Then rerun the visual renderer against the same `YYYY-MM-DD-visual-validation-attempt-<validationAttempt>.html` path and require exit code zero so the HTML reflects the final Markdown verdict. The validator, not `visual-validation`, owns this finalization step.

Read [references/validation_template.md](references/validation_template.md). Set the output to `<task-dir>/YYYY-MM-DD-validation-attempt-<validationAttempt>.md`. This path is immutable: use **Write** only when it does not exist, never use **StrReplace** on it, and block rather than overwrite or reuse a prior attempt document.

After writing, use **Shell** to compute its SHA-256 digest and verify the file still has that digest before returning. Read [references/validation_final_answer.md](references/validation_final_answer.md) before returning.

Return:

- verdict and blocking findings;
- `validationAttemptId`;
- `validationAttempt`;
- absolute validation-document path;
- `validationDocumentSha256`;
- normalized `changedPathAllowlist`, derived changed paths with their Git sources, allowlisted-but-unchanged paths, and unowned changed paths;
- every exact command and numeric exit code;
- plan coverage and unresolved manual checks;
- independent reviewer result;
- `visualApplicable`;
- absolute `visualManifestPath` and `visualReportPath`, or `null` when `applicable: false`;
- final repository status proving source files were not changed by validation.
