---
name: iterate-tdd
description: Refine an existing TDD in place from exact technical feedback while preserving system/program boundaries and its decision ledger.
disable-model-invocation: true
---

# Iterate TDD

Refine one existing Technical Design Document (TDD) in place. Preserve the distinction between cross-component System Design and in-code Program Design. Re-paint affected sections; never append a Q&A transcript or changelog.

Use Cursor's `Shell`, `Read`, `StrReplace`, `Write`, `Task`, and `AskQuestion` tools. Resolve `references/artifact_template.html` and `references/tdd_final_answer_resolved.md` relative to this file's installed directory. Do not depend on a user-specific path.

## Choose the interaction mode

Interactive mode is the default. Apply one resolved decision at a time, then ask what to address next.

Use delegated no-user mode only when the parent prompt contains:

```text
NO_USER_AVAILABLE: true
```

Do not infer no-user mode from a `Task` call. The parent must also supply exact feedback. In no-user mode:

- do not use `AskQuestion` or contact the user;
- resolve only follow-up choices necessary to apply the supplied feedback;
- select the best codebase-supported option and tag it `recommended`, or tag a gap-filling option `assumed`;
- preserve and update the TDD's embedded `Decision Ledger`;
- return `needs_root` when feedback is ambiguous, conflicts with the PRD, or materially changes product behavior;
- return the absolute TDD path, changed diagram paths, ledger changes, and verification in the parent's required envelope.

## Conversation and design rules

In interactive mode:

- Ask exactly one question per turn.
- Present two or three credible options, concrete design shapes, tradeoffs, and a recommendation.
- Treat clarification and pushback as discussion, not a resolved decision.
- Modify the document only after the current decision settles.
- Stop after one incorporated change and ask what to address next.

Use diagrams, signatures, and code-shape sketches instead of walls of prose. Give each subsection a takeaway-style heading. Keep exhaustive file lists in the downstream structure outline.

If invoked without a TDD path or feedback, use `AskQuestion` to request the missing input. Do not guess the target document.

## 1. Establish the edit target

Use `Shell` with `ls -La` to inventory the supplied task directory. Read the target TDD, PRD, research, ticket, and every relevant diagram or design artifact completely with `Read`. Identify one canonical TDD and reject multiple candidates unless the parent selects one.

Record the TDD content hash before editing. Read every mentioned source file before accepting factual feedback.

When repository evidence is missing, run a foreground `Task` with `model: inherit` and one bounded read-only agent:

- `codebase-locator` for locations;
- `codebase-analyzer` for implementation and data flow;
- `codebase-pattern-finder` for representative patterns and tests;
- `web-search-researcher` for external primary-source facts.

Require file-and-line evidence and no edits. Skip delegated research when the feedback and existing artifacts already establish the facts.

## 2. Classify the feedback

Route each change to the correct layer:

- **System Design:** cross-component architecture, data/control flow, service boundaries, external interfaces, public contracts, endpoints, messages, schemas, stores, queues, and failure behavior.
- **Program Design:** call stacks, frontend component trees, high-level file responsibility, dependency-injection seams, internal signatures, algorithms, and repository patterns.
- **Product behavior:** return to the parent as `needs_root`; do not redefine the PRD from a technical revision.
- **Phase slicing or exact implementation steps:** return to the parent for structure-outline revision.

When feedback affects both system and program design, update System Design first, verify the new cross-component contract, then rework Program Design to implement it.

## 3. Apply resolved changes

For each resolved decision:

1. Verify the claim against repository and upstream-artifact evidence.
2. Identify every affected TDD section and diagram.
3. Present or evaluate credible alternatives and select one through the active interaction mode.
4. Use `StrReplace` to rework affected sections so the document remains one coherent design.
5. Update `Patterns to Follow` with concise repository-relative evidence when patterns change.
6. Replace superseded ledger entries with the current decision, tag, alternatives, evidence, and rationale.

Do not accumulate contradictory or stale design alternatives in the selected design. Keep ruled-out choices concise when their rationale remains useful.

### Continue-grilling mode

When asked to continue exploring the design, identify the next unresolved or sparse decision yourself. Do not expect a stored question list. For system questions, show diagrams or public-contract shapes. For program questions, show call trees, component trees, file-tree diffs, dependency maps, signatures, or pseudocode. Continue only when interactive user input or the explicit no-user contract authorizes the next choice.

## 4. Keep diagrams synchronized

Use Mermaid directly in the TDD for focused architecture and data-flow views. When a decision needs a richer HTML diagram, edit the canonical file in place or create one focused new artifact at:

```text
<task-dir>/diagram-<description>.html
```

Read `references/artifact_template.html`, preserve its stylesheet, and use its prose and utility classes. Keep embedded `task-artifact` paths aligned with the current winning design. Remove stale embeddings from the selected design.

## 5. Verify the revision

Before returning:

- prove the canonical TDD changed in place and no duplicate TDD was created;
- confirm all supplied feedback was incorporated or explicitly returned as unresolved;
- confirm System Design, Program Design, patterns, diagrams, and the approved PRD agree;
- confirm every new or changed choice is tagged `recommended` or `assumed` in no-user mode;
- report every changed artifact path and the resulting TDD content hash;
- report no source-code path as changed.

Read `references/tdd_final_answer_resolved.md` and follow the branch for the active interaction mode. In interactive mode, stop after each revision and ask one question. In no-user mode, return to the parent without prompting the user.

Document precedence is:

```text
TDD > PRD > design discussion > research > ticket
```
