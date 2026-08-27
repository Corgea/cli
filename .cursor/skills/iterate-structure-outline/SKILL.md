---
name: iterate-structure-outline
description: Revise an existing structure outline in place from exact feedback while preserving vertical slices, path ownership, and verifiable commands.
disable-model-invocation: true
---

# Iterate Structure Outline

Revise one existing structure outline in place. Keep it concise, ordered, implementation-ready, and sliced by independently testable behavior rather than architectural layer.

Use Cursor's `Shell`, `Read`, `StrReplace`, `Write`, `Task`, and `AskQuestion` tools. Resolve the files under `references/` relative to this file's installed directory. Do not depend on a user-specific path.

## Interaction contract

Interactive mode is the default. If feedback or the outline path is missing, use `AskQuestion` to request it and stop.

When a parent supplies exact feedback and the exact flag `NO_USER_AVAILABLE: true`, do not contact the user. Apply only the supplied feedback and evidence-required follow-ups. Return `needs_root` when ambiguity would materially change behavior, design, ownership, or verification.

Never infer no-user mode from a `Task` call.

## 1. Establish the canonical outline

Use `Shell` with `ls -La` to inventory the supplied task directory. Read the structure outline and every relevant upstream artifact completely with `Read`: TDD, PRD, design discussion, research, and ticket. Read any repository files cited by those artifacts or the feedback.

Identify exactly one canonical structure outline and record its content hash. Reject multiple candidates unless the parent explicitly selects one. Update the canonical document at the same path; do not create a replacement outline.

Document precedence is:

```text
structure outline > TDD > PRD > design discussion > research > ticket
```

When facts are missing, run a foreground `Task` with `model: inherit` and one bounded read-only agent:

- `codebase-locator` to find relevant paths;
- `codebase-analyzer` to trace current implementation and integration points;
- `codebase-pattern-finder` to find representative implementation and test patterns;
- `web-search-researcher` only for external primary-source facts.

Require file-and-line evidence and no edits. Skip delegated research when existing artifacts already establish the facts.

## 2. Verify and classify feedback

Do not accept feedback blindly. Verify factual claims against the repository and upstream artifacts, then route changes:

- Phase boundaries, ordering, path ownership, commands, manual checks, or completion criteria belong in this outline.
- Visual applicability, capture capability, reproducible scenarios, or visual pass/fail criteria belong in the outline's `Visual Validation Contract`.
- Product behavior conflicts return to PRD revision.
- Architecture or program-design conflicts return to TDD revision.
- New product choices, permissions, destructive operations, credentials, or authority return `needs_root`.

If feedback answers an open question, incorporate the answer into the relevant phase and remove the resolved question. If it adds or removes scope, update both phase content and `What We're Not Doing`.

## 3. Preserve vertical slices

Every phase should deliver the smallest meaningful behavior across as many required layers or module boundaries as needed. Prefer slices such as “a user can complete the simplest flow end to end” over horizontal phases such as “add types,” “add endpoints,” then “add tests.”

Each phase must be independently verifiable without requiring a later phase and must include:

- observable behavior delivered;
- exact owned source paths, with no overlap between concurrent owners;
- important interfaces or signatures changed;
- dependencies on earlier completed phases only;
- exact automated verification commands copied in runnable form;
- manual verification only for behavior that cannot be automated;
- explicit completion criteria.

Do not invent manual checks to make a phase appear vertical. Automated verification takes precedence. Reject vague commands such as “run tests” when the repository exposes an exact command. Do not weaken or omit an existing check merely to make a phase pass.

Preserve and revalidate the top-level `Visual Validation Contract`. It must contain the boolean `applicable: true` with one to six complete reproducible scenarios for rendered or design-backed work, or `applicable: false` with a concrete non-visual reason and no scenarios. Reject string discriminators such as `applicable`, `APPLICABLE`, or `N/A`. When feedback changes affected behavior, update applicability and every affected scenario's route, deterministic setup, actions, viewport, ready state, capture point, expected outcome, and selected design reference. Never drop the contract or switch applicable work to `false` to avoid capture.

## 4. Apply the revision

Use `StrReplace` to rework the affected phases and summary sections in place. Reorder phases when dependencies require it. Remove stale or contradicted text instead of appending corrections.

When feedback changes slicing or verification, return the complete current phase list, ownership list, automated command list, manual-check list, Visual Validation Contract, and open-question list—not only the changed excerpt. This lets the parent replace its tracked execution contract atomically.

Do not launch or recommend another implementation orchestrator. The parent workflow owns implementation in the current Cursor Cloud checkout.

## 5. Verify the revised outline

Before returning, prove:

- the canonical outline changed in place and no duplicate outline was created;
- every supplied feedback item was incorporated or explicitly returned unresolved;
- every phase is a thin vertical slice or documents why the task cannot be sliced further;
- phase ownership is explicit and non-overlapping;
- every automated command is exact, runnable from a stated working directory, and maps to completion criteria;
- manual steps are clearly distinguished and cannot reasonably be automated;
- the Visual Validation Contract remains complete and consistent with the revised behavior and approved upstream artifacts;
- resolved questions were removed and remaining questions are explicit;
- no source-code path changed.

Report the resulting outline hash and every changed artifact path.

Use `Shell` to inspect `git rev-parse --git-dir`. Read the matching final-answer reference for the current checkout shape. In parent no-user mode, use the reference only as a completeness checklist and return the parent's required envelope without contacting the user.
