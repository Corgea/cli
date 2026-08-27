---
name: deslop
description: "Explicit-only: remove AI-generated clutter from changed code while preserving behavior, project conventions, and unrelated work."
disable-model-invocation: true
---

# Deslop

Remove unnecessary comments, abnormal defensive checks, type-system escapes, and other style inconsistencies introduced by the current change. Preserve observable behavior and public interfaces; this is not a correctness review, broad refactor, or commit step.

## Resolve the change scope

Use **Shell** to record the repository root, current branch, `HEAD`, and `git status --short --untracked-files=all`. Read applicable `AGENTS.md` files and nearby code with **Read** before editing.

If the caller supplies a path or revision range, use it. Otherwise resolve the repository's default branch from local Git metadata and compare its merge base with `HEAD`; use the current branch's tracking ref only when it is proven to be that default branch. Never use a same-named feature-branch tracking ref as the baseline. If no default branch can be resolved, use `HEAD~1` when available and report that limited fallback scope. Add tracked working-tree changes from `git diff HEAD` and untracked, non-ignored files. Never assume the default branch is named `main`.

Turn this scope into an explicit file allowlist. Preserve all pre-existing changes outside it and stop with a no-op result when it is empty.

## Remove only introduced slop

Inspect the diff and surrounding code. Use **StrReplace** or **Write** only within the allowlist to remove:

- comments that restate the code or conflict with local commenting style;
- redundant guards or `try`/`catch` blocks that are abnormal for already validated code paths;
- unsafe casts or type escapes added to bypass errors when a local, type-safe expression suffices;
- needless wrappers, temporary variables, nesting, or formatting inconsistent with the edited file.

Do not remove comments that explain intent, invariants, safety, or non-obvious constraints. Do not change behavior, expand scope to pre-existing issues, introduce speculative abstractions, overwrite unrelated edits, stage files, commit, push, or create a pull request. If an edit's safety is uncertain, leave it unchanged.

## Verify and report

Use **Shell** to confirm every changed path remains allowlisted and the index and unrelated work are unchanged. Run the narrowest existing formatter, static check, or tests proportional to the edits; do not invent project commands. If no safe cleanup exists, leave the worktree unchanged.

Finish with only a one-to-three-sentence summary of what changed and the verification result.
