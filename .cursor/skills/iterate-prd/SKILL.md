---
name: iterate-prd
description: Refine an existing PRD in place from exact product feedback, preserving a coherent specification and its decision ledger.
disable-model-invocation: true
---

# Iterate PRD

Refine one existing Product Requirements Document (PRD) in place. Preserve its role as the source of product behavior and scope. Re-paint affected sections; never append a Q&A transcript or changelog.

Use Cursor's `Shell`, `Read`, `StrReplace`, `Write`, `Task`, and `AskQuestion` tools. Resolve `references/prd_final_answer_resolved.md` relative to this file's installed directory. Do not depend on a user-specific path.

## Choose the interaction mode

Interactive mode is the default. Apply one resolved change at a time, then ask what to address next.

Use delegated no-user mode only when the parent prompt contains:

```text
NO_USER_AVAILABLE: true
```

Do not infer no-user mode from a `Task` call. The parent must also supply the exact feedback. In no-user mode:

- do not use `AskQuestion` or contact the user;
- resolve only follow-up choices necessary to apply the supplied feedback;
- choose the best evidence-supported option and tag it `recommended`, or tag a gap-filling choice `assumed`;
- preserve and update the PRD's embedded `Decision Ledger`;
- return `needs_root` when feedback is ambiguous in a way that materially changes behavior or scope;
- return the absolute PRD path, changed mockup paths, revised ledger entries, and verification in the parent's required envelope.

## Conversation rules

In interactive mode:

- Ask exactly one question per turn.
- Offer two or three credible options and a recommendation when a decision is needed.
- Treat clarification and pushback as discussion, not a resolved decision.
- Modify the document only when the current decision is settled.
- After one incorporated change, stop and ask what the user wants to address next.

If invoked without a PRD path or feedback, use `AskQuestion` to request the missing input. Do not guess the target document.

## 1. Establish the edit target

Use `Shell` with `ls -La` to inventory the supplied task directory. Read the target PRD and every relevant upstream artifact completely with `Read`. Identify the canonical PRD path and reject multiple candidates unless the parent explicitly identifies one.

Record the PRD content hash before editing. Read mentioned source files and artifacts before accepting factual feedback. Do not accept a correction blindly.

When repository evidence is missing, run a foreground `Task` with `model: inherit` and one bounded read-only agent:

- `codebase-locator` for locations;
- `codebase-analyzer` for current behavior or design-system details;
- `codebase-pattern-finder` for comparable product behavior;
- `web-search-researcher` for external primary-source facts.

Require file-and-line evidence and no edits. Skip delegated research when the supplied feedback and existing artifacts already establish the facts.

## 2. Process feedback at the product layer

For each resolved change:

1. Verify the claim against available evidence.
2. Identify every affected PRD section and mockup.
3. Rework those sections so the result reads as one current specification.
4. Update the problem, success lever, proposed solution, alternatives, solution details, out-of-scope list, or deferred-to-TDD notes when the feedback changes them.
5. Update the embedded decision ledger with the decision, tag, alternatives, evidence, and rationale. Replace superseded entries instead of accumulating contradictions.

Stay in product space. If feedback is technical design rather than product behavior, record it under `Deferred to TDD` and return it to the parent for TDD handling.

### Continue-grilling mode

When asked to continue exploring the solution, find the next unresolved or sparse product decision yourself. Do not expect a stored question list. Present one decision, resolve it through the active interaction mode, and then rework the document. Continue only when interactive user input or the explicit no-user contract authorizes the next choice.

## 3. Keep mockups synchronized

For visual feedback, edit the affected HTML mockup in place with `StrReplace`. Create a new mockup with `Write` only when the feedback introduces a genuinely new view or decision. Match the repository's design system and use realistic labels.

Keep the winning mockups embedded next to their prose with `task-artifact` blocks. Do not leave stale options presented as the selected design. In interactive mode, show the revised mockup before moving on. In no-user mode, verify the mockup against the selected behavior and record it in the ledger.

## 4. Verify the revision

Before returning:

- prove the canonical PRD changed in place and no duplicate PRD was created;
- confirm all supplied feedback was incorporated or explicitly returned as unresolved;
- confirm problem, success, behavior, scope, mockups, and ledger agree;
- confirm every new or changed choice is tagged `recommended` or `assumed` in no-user mode;
- report every changed artifact path and the resulting PRD content hash;
- report no source-code path as changed.

Read `references/prd_final_answer_resolved.md` and follow the branch for the active interaction mode. In interactive mode, stop after each revision and ask one question. In no-user mode, return to the parent without prompting the user.

Document precedence is:

```text
PRD > design discussion > research > ticket
```
