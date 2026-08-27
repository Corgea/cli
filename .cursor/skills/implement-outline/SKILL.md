---
name: implement-outline
description: Implement a structure outline one verified phase at a time without staging or committing. Use only when explicitly invoked.
disable-model-invocation: true
---

# Implement a Structure Outline

Implement every requested phase through a fresh `outline-implementer-agent`. This skill owns phase parsing, path ownership, result validation, and verification. It never edits task artifacts, stages files, commits, pushes, or opens a pull request.

## Resolve inputs and baseline

Require one absolute structure-outline path or one canonical task directory. If a directory is supplied, list it with `ls -La` through `Shell` and require exactly one active structure outline. Canonicalize every artifact path. Read the outline and relevant ticket, research, PRD, TDD, and resolved design artifacts completely with `Read`; exclude research-questions documents.

Apply this precedence:

```text
structure outline > TDD > PRD > resolved design discussion > research > ticket
```

With `Shell`, record the canonical repository root, named branch, baseline `HEAD`, and full status. Reject tracked `.humanlayer/**`. Record all pre-existing tracked and untracked changes. When the invoking prompt supplies a baseline or artifact hashes, require an exact match before editing.

Parse phases in order. For each phase, retain the exact identifier and full text, canonical owned source and test paths, exact automated commands and their working directories, and manual checks. Reject missing or ambiguous ownership, paths outside the repository, unexplained overlap, vague commands, unresolved artifact conflicts, or pre-existing unrelated edits that overlap an owned path.

## Run one phase at a time

For each phase, call foreground `Task` with:

- `subagent_type: outline-implementer-agent`;
- `model: inherit`;
- a fresh descriptive task label;
- no later phase content except context needed to preserve interfaces.

The prompt must include:

- canonical repository and artifact paths;
- baseline `HEAD` and complete pre-phase status;
- artifact precedence;
- exact phase identifier and full phase text;
- canonical ownership allowlist;
- prior phases' changed paths;
- every exact automated command and working directory;
- every manual check marked outstanding;
- instructions to preserve existing work, edit only owned source or test paths, never edit `.humanlayer/**`, never stage or commit, avoid further delegation and user contact, and return the required envelope.

Require exactly:

```text
STATUS: complete|blocked|needs_root
PHASE: <exact phase identifier>
CHANGED_PATHS:
- <absolute canonical path or none>
VERIFICATION:
- <exact command> | EXIT: <numeric code>
MANUAL_CHECKS:
- <outstanding check or none>
BLOCKER: <exact blocker or none>
```

Reject a missing field, extra status value, phase mismatch, relative path, or malformed command evidence. `blocked` and `needs_root` stop the workflow and return the blocker to the invoking root; this skill does not contact the user.

## Verify each phase independently

Capture status and diff immediately before and after each `Task`. Derive its changed paths independently rather than trusting the report. Every newly changed path must equal an owned file or be beneath an owned directory after canonicalization. Reject changes to task artifacts, `.humanlayer/**`, secrets, credentials, setup files, unrelated configuration, prior user work, prior phase paths without sequential ownership, or any unowned path.

Require the reported and derived path sets to match exactly. Confirm `HEAD` still equals the baseline and no index entries or commits were created. Run every phase command verbatim, in order, from its documented working directory with `Shell`. Record the exact command, relevant output, and numeric exit code. Do not accept a broader, narrower, substituted, partial, or unrun command. Stop on a nonzero exit.

Do not change outline checkboxes or phase markers. Artifact progress belongs to the root workflow state, not the implementation diff. Manual checks remain outstanding unless direct evidence from the invoking root proves them; they do not authorize this skill to contact the user.

## Final verification

After all phases pass, rerun every exact phase command in order. Then run documented repository-wide test, lint, typecheck, and build commands when repository instructions or configuration define them. Do not download replacement tools or silently substitute checks.

Review the complete baseline-to-working-tree diff against the outline and artifact precedence. Require every source change to map to one phase and the union of phase ownership. Confirm:

- `HEAD` still equals the baseline;
- the index is unchanged from its recorded initial state;
- no task artifact changed;
- no commit, push, or pull-request operation occurred;
- all automated checks have zero exit codes;
- manual checks are reported honestly.

## Resume and report

On resume, compare current `HEAD`, status, hashes, and diff with the recorded baseline. Never trust outline markers as proof. An existing commit after the baseline is a conflict unless the invoking root explicitly establishes a new baseline. Preserve the working tree on failure.

Resolve this loaded `SKILL.md` to an absolute path and read `references/implement_outline_final_answer.md` beside it. Return that exact envelope with completed phases, independently derived changed paths, every command and exit code, outstanding manual checks, and the blocker or `none`. Never report a commit because this skill cannot create one.
