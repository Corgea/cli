---
name: create-tdd
description: Create a technical design document through ordered system-design and program-design interviews, or self-resolve it only when an orchestrating parent explicitly declares that no user is available.
disable-model-invocation: true
---

# Create TDD

Create the Technical Design Document (TDD) that explains how to build the approved product behavior. Keep product requirements and user experience in the upstream PRD.

Run two ordered design phases:

1. **System Design** — behavior and contracts across components.
2. **Program Design** — the concrete in-code shape inside those components.

Use Cursor's `Shell`, `Read`, `Write`, `StrReplace`, `Task`, and `AskQuestion` tools. Resolve `references/tdd_template.md`, `references/artifact_template.html`, and `references/tdd_final_answer_resolved.md` relative to this file's installed directory. Do not depend on a user-specific path.

## Choose the interaction mode

Interactive mode is the default. Ask exactly one technical-design question at a time. Settle and obtain sign-off on System Design before opening Program Design.

Use delegated no-user mode only when the parent prompt contains:

```text
NO_USER_AVAILABLE: true
```

Do not infer this mode from being called through `Task`. In no-user mode:

- do not use `AskQuestion` or contact the user;
- enumerate each unresolved technical choice and its credible options;
- select the best codebase-supported answer and tag it `recommended`, or tag a gap-filling answer `assumed`;
- self-review System Design before starting Program Design, then self-review Program Design;
- embed a complete `Decision Ledger` section in the TDD;
- return absolute TDD and diagram paths, the ledger, and unresolved root questions in the parent's required envelope.

Return `needs_root` when a technical decision changes product behavior or cannot be safely recommended or assumed. Never hide an assumption.

## Keep the design cohesive

- Re-paint sections after a decision resolves; never append interview answers or a changelog.
- Use takeaway-style headings that reveal the design when skimmed.
- Keep prose short and place diagrams, signatures, and code-shape views beside the claims they support.
- Prefer the smallest set of views that exposes important decisions and tradeoffs.
- Express current behavior and the proposed delta inside System Design and Program Design; do not add duplicate current-state/target-state summaries.
- Keep exhaustive file inventories out of the TDD; the structure outline owns them.

## 1. Understand the context

Use `Shell` with `ls -La` to inventory the supplied task directory. Read each relevant artifact completely with `Read`, excluding research-question documents when the resolved research artifact is available. Record the canonical path and SHA-256 hash of every PRD, mockup, ticket, research, design, and other upstream artifact before gathering more evidence. Read `references/tdd_template.md` completely.

A PRD is preferred but not mandatory. Work from the approved PRD, ticket, research, and other supplied context. Cite rather than duplicate upstream material. Do not invent product requirements when context is thin.

When a decision depends on repository behavior, run a foreground `Task` with `model: inherit` and one appropriate read-only agent:

- `codebase-analyzer` for current implementation and data flow;
- `codebase-pattern-finder` for representative patterns and tests;
- `codebase-locator` for missing paths;
- `web-search-researcher` only for external primary-source facts.

Give each task one bounded question, require file-and-line evidence, and prohibit edits. Never use `Write` or `StrReplace` on a hashed upstream artifact. Integrate newly verified evidence only into the current TDD, its `Patterns to Follow`, and its decision ledger; if the TDD skeleton does not exist yet, retain the evidence in context until it does. Do not revise the PRD, mockups, research, ticket, or other upstream artifacts.

## 2. Write the skeleton

Select the next unused zero-padded index in the canonical task directory and write:

```text
<task-dir>/NN-tdd-<two-to-four-word-kebab-slug>.md
```

Use the bundled template. Start with:

- frontmatter with `type: design-tdd`, repository, branch, and `HEAD`;
- a title;
- empty `System Design`, `Program Design`, and `Patterns to Follow` sections;
- an empty `Decision Ledger` in no-user mode.

Do not add preamble, summaries, or speculative architecture.

In interactive mode, immediately use `AskQuestion` for the first system-design decision with credible options and a recommendation. In no-user mode, evaluate that decision from evidence, record it, and continue.

## 3. Design the system

System Design covers behavior between components: clients, services, endpoints, messages, schemas, queues, stores, and external systems. Show what exists and how the change alters it.

For each decision:

1. Choose the single cross-component question that unlocks the most remaining design.
2. Verify repository-dependent facts.
3. Express options with the clearest representation: Mermaid flow/sequence diagrams, high-level type signatures, endpoint or message shapes, and data contracts in the repository's language.
4. Present tradeoffs and a recommendation.
5. Resolve through the active interaction mode.
6. Rework the entire affected portion of `System Design` and update its ledger entry.

In interactive mode, ask exactly one decision per turn and wait. In no-user mode, evaluate one decision at a time and record alternatives, evidence, and rationale.

### Complex system diagrams

When Mermaid or text cannot communicate the decision, write a focused HTML artifact to:

```text
<task-dir>/diagram-<description>.html
```

Read `references/artifact_template.html`, preserve its stylesheet, and build the body from its prose and utility classes. Use realistic labels. Embed the result with a `task-artifact` block beside the relevant design text.

## 4. Review System Design

In interactive mode, ask the user to read `System Design` top to bottom and approve it. Incorporate corrections and do not start Program Design before approval.

In no-user mode, self-review the whole section. Confirm that current behavior, target delta, component boundaries, data/control flow, failure behavior, external interfaces, and public contracts agree with the upstream product context. Record the sign-off in the ledger. Return `needs_root` if a choice changes product behavior.

## 5. Design the program

Program Design defines the implementation shape inside components. Ask or resolve one decision at a time and show concrete code form. Almost every interactive question should include a code block.

Use only the views that clarify the change:

- call-stack trees for services, CLIs, workers, and orchestration;
- frontend component trees for UI structure, hooks, state, and package boundaries;
- high-level file-tree diffs when file responsibility is a design choice;
- dependency-injection maps for important seams;
- internal method signatures for key contracts not already covered;
- pseudocode for complex algorithms or state transitions.

For each decision, show two or three credible code-shape options when alternatives exist, explain the tradeoffs, recommend one, resolve it through the active mode, and rework all affected Program Design content. Record the decision with evidence and rationale.

Identify existing patterns to follow with repository-relative file and line evidence plus short representative snippets. Prefer existing interfaces and primitives over speculative abstractions.

If a technical choice changes product scope or UX, do not silently edit the product contract. Return `needs_root` with the affected PRD/mockup paths and exact conflict.

## 6. Review Program Design

In interactive mode, ask the user to review the complete `Program Design` and approve the code shape. Incorporate corrections before completion.

In no-user mode, self-review it against System Design, repository evidence, and the approved PRD. Confirm:

- code shape implements every required cross-component behavior;
- responsibilities and dependency direction are explicit;
- chosen patterns exist in the repository;
- failure, validation, and test seams are designable;
- every unresolved choice appears in the ledger as `recommended` or `assumed`;
- no exhaustive implementation plan has leaked into the TDD.
- every upstream artifact still matches its recorded SHA-256 hash.

## 7. Finish

Read `references/tdd_final_answer_resolved.md` relative to this skill and follow the branch for the active interaction mode. Return absolute artifact paths and direct evidence. Do not claim approval, a diagram, or a resolved decision without evidence.

Document precedence is:

```text
TDD > PRD > design discussion > research > ticket
```
