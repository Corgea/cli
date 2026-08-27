---
name: simplify
description: "Explicit-only: audit changed code for reuse, efficiency, abstraction depth, and unnecessary complexity, then apply safe behavior-preserving fixes within that change scope."
disable-model-invocation: true
---

# Simplify

Improve changed code without changing observable behavior or public interfaces. This is a bounded quality pass, not a correctness review, broad refactor, or commit step.

## Input and scope

Accept an optional repository-relative path, checked-out git ref, or revision range. An explicit target wins.

Without a target, resolve the union of:

1. The current branch against its upstream; otherwise the repository's default branch against `HEAD`; otherwise `HEAD~1` when it exists.
2. Tracked working-tree changes from `git diff HEAD`.
3. Untracked, non-ignored files reported by git.

Use **Shell** to record the repository root, branch, `HEAD`, resolved comparison, and `git status --short --untracked-files=all`. Read every applicable `AGENTS.md` and the project configuration needed to learn conventions and focused verification commands.

Turn the resolved scope into an explicit file allowlist. Exclude generated code, vendored dependencies, migrations, fixtures, snapshots, and ignored files unless the caller named them. If the requested ref is not checked out, do not edit another checkout. Stop with a no-op result when the allowlist is empty.

## Four independent audits

Launch exactly three read-only **Task** calls in one bounded parallel batch. Use `subagent_type: code-reviewer` and `model: inherit` for each. Do not use background tasks. Give every reviewer the repository root, comparison range, explicit file allowlist, applicable project instructions, and exactly one lens:

- **Reuse:** find code in the allowlist that duplicates an existing helper or local pattern. Require the exact existing symbol and location.
- **Efficiency:** find redundant computation or I/O, needless serialization, hot-path blocking, or long-lived closures retaining an unnecessarily large environment. Require a cheaper behavior-equivalent replacement.
- **Abstraction altitude:** find scoped changes implemented as brittle special cases when an existing in-scope mechanism can express the behavior directly. Require the precise in-scope replacement.

Each reviewer must return only candidates containing a file and line, one-line summary, concrete cost, and behavior-preserving replacement. Findings outside the allowlist are invalid. A reviewer must write `None` when it has no candidate.

While those three tasks run, perform the fourth audit locally: find redundant or derivable state, repeated branches, needless nesting, dead code introduced by the change, premature abstractions, and dense expressions that obscure intent. Do not report correctness defects; record them as skipped and recommend a correctness review.

Wait for all three reviewers. A missing, malformed, or writing reviewer result blocks the simplification pass. Compare `git status` with the pre-task snapshot and block if any reviewer changed the filesystem.

## Select and apply safe fixes

Deduplicate candidates by line and mechanism. Accept one only when all of these are true:

- Observable behavior and public interfaces stay unchanged.
- The edit remains inside the explicit allowlist.
- Repository conventions support it.
- The benefit is concrete rather than stylistic.
- Focused verification covers the affected behavior.

Reject behavior changes, speculative abstractions, broad cleanup, pre-existing issues, and uncertain findings.

Launch one foreground **Task** with `subagent_type: codebase-simplifier` and `model: inherit`. This is the only writer. Give it the accepted candidates, exact writable file allowlist, pre-task status, and focused verification commands. Require it to revalidate each candidate before using **Read**, **StrReplace**, or **Write**, and to return changed paths plus every command and numeric exit code. It must not stage, commit, contact remotes, or edit task artifacts.

After it returns, use **Shell** to prove that every changed path is allowlisted, the index is unchanged, and no commit was created. Do not discard unrelated work if this check fails; stop and report the unexpected state.

## Verify and return

Run the narrowest existing formatter check, static check, and tests that cover the applied edits. Do not invent commands. If a check fails, correct only the simplification edits through the same single-writer contract or report the failure; never erase pre-existing work.

Return:

- resolved comparison and file allowlist;
- the three reviewer outcomes and local audit outcome;
- fixes applied, with files and reasons;
- candidates skipped, with reasons;
- exact verification commands, numeric exit codes, and relevant output;
- final changed paths and confirmation that no staging or commit occurred.

If no safe cleanup exists, leave the worktree unchanged and say so.
