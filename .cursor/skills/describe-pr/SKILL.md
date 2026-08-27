---
name: describe-pr
description: "Explicit-only: generate a review-ready pr-description.md and, for a large committed diff, an optional self-contained walkthrough without publishing or requiring an existing pull request."
disable-model-invocation: true
---

# Describe PR

Generate review artifacts from the committed `base...HEAD` diff. Do not commit, contact remotes, publish, or require a pull request to exist. Cursor Cloud owns branch publication and pull-request creation after this stage.

## Required context

Require the absolute repository root and, when available, the absolute task directory. Accept an explicit base ref and plan path.

Resolve the absolute path through which this `SKILL.md` was loaded, canonicalize its parent directory with **Shell**, and record it as `<describe-pr-skill-dir>`. Block if the loaded path cannot be resolved to an absolute directory or if its required references and helper script are absent. All bundled resources must be read or executed from this installed skill directory, never from the target repository's `scripts/` or `references/` directories.

Use **Shell** to record the current branch, `HEAD`, repository root, and `git status --short --untracked-files=all`. Resolve the base in this order:

1. explicit base ref;
2. the local remote-default-branch ref;
3. local `main`;
4. local `master`.

Block when no base resolves, the branch is the default branch, `base...HEAD` is empty, or implementation changes remain uncommitted. Untracked ignored task artifacts may remain. Tracked `.humanlayer/**` content or tracked task-artifact changes are blocking.

Read the ticket, research, design, plan, validation, and implementation summaries present in the task directory. Treat them as context; the committed diff is the source of truth.

## Inspect the committed change

Use **Shell** to collect from the resolved `base...HEAD` range:

- merge base and head SHA;
- commit subjects;
- name status, file count, and additions/deletions;
- the complete unified diff.

Read every changed source and test file needed to explain intent and verification. If command output truncates the unified diff, read it in bounded per-file segments until every changed file is covered. Do not write a diff file into the repository.

## Independent plan comparison

When a plan exists, snapshot repository status and launch one foreground **Task** with `subagent_type: implementation-reviewer` and `model: inherit`. Give it the absolute repository root, absolute plan path, base SHA, head SHA, and exact comparison range. Require these sections, using `None` when empty:

- Implemented as planned
- Deviations/surprises
- Additions not in plan
- Items planned but not implemented

After the task returns, prove the read-only reviewer did not change the filesystem. A malformed result or filesystem mutation blocks artifact generation. If there is no plan, record `No plan file found`.

## Optional walkthrough

Generate `pr-walkthrough.html` only when the committed diff has at least 300 changed lines **and** at least 5 changed files. Otherwise omit it.

For a walkthrough:

1. Use **Read** on `<describe-pr-skill-dir>/references/pr_walkthrough_example.html`.
2. Use **Write** to create a self-contained walkthrough in the task directory. Replace every placeholder with facts from the committed diff.
3. Order nodes as context → operating principles → implementation phases → deliberately not changed → verification and ship readiness.
4. Give each node a badge, title, one-line summary, and useful expanded body. Use real before/after snippets for the most important changes.
5. Set `diffFile` on every changed-file node and leave the `#diffs` stash empty.
6. Use **Shell** to run `<absolute describe-pr-skill-dir>/scripts/inject-walkthrough-diffs.sh <walkthrough-path> <repository-root> --range <base>...HEAD`. The executable path must be absolute. Read the resulting file and verify every requested file was injected as a `data-encoding="base64"` payload rather than raw diff text.

The walkthrough embeds local diff evidence. It must not contain placeholder URLs, credentials, externally fetched code, or claims unsupported by the diff.

## Write the PR description

Use **Read** on `<describe-pr-skill-dir>/references/pr_description_template.md`. Fill every section from repository evidence:

- task or ticket context when available;
- problems addressed;
- user-facing and internal changes, naming repository-relative paths;
- implementation journey;
- independent plan comparison;
- exact verification commands and known results;
- migrations, compatibility concerns, or breaking changes;
- a one-line changelog entry.

Write `pr-description.md` in the task directory with **Write** or **StrReplace**. When no task directory was supplied, create `.humanlayer/tasks/<branch-slug>/` and use it as the task directory. Do not modify source files.

Use **Read** on `<describe-pr-skill-dir>/references/describe_pr_final_answer.md` and return:

- absolute description path;
- absolute walkthrough path or `null`;
- base and head SHAs;
- changed-file and line totals;
- plan-comparison summary;
- confirmation that no commit, publication, or pull-request mutation occurred.
