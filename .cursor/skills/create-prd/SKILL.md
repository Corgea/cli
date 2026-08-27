---
name: create-prd
description: Create a product requirements document through a guided product interview, or self-resolve it only when an orchestrating parent explicitly declares that no user is available.
disable-model-invocation: true
---

# Create PRD

Create the Product Requirements Document (PRD) that defines what is being built, why it matters, how people experience it, and how success will be recognized. Leave implementation architecture to the downstream TDD.

Use Cursor's `Shell`, `Read`, `Write`, `StrReplace`, `Task`, and `AskQuestion` tools. Resolve `references/prd_template.md` relative to this file's installed directory. Do not depend on a user-specific path.

## Choose the interaction mode

Interactive mode is the default. Ask exactly one product question at a time, wait for the answer, and modify the document only after the decision is settled.

Use delegated no-user mode only when the parent prompt contains the exact flag:

```text
NO_USER_AVAILABLE: true
```

Do not infer this mode from being called through `Task`. In no-user mode:

- do not use `AskQuestion` or contact the user;
- enumerate each unresolved choice and its credible options;
- choose the best answer supported by the ticket, research, and repository evidence;
- tag evidence-backed choices `recommended` and gap-filling choices `assumed`;
- self-approve the solution review only after checking the complete document;
- embed a complete `Decision Ledger` section in the PRD;
- return the absolute PRD path, mockup paths, ledger, and unresolved root questions in the parent's required envelope.

If a consequential choice cannot be safely recommended or assumed, return it to the parent as `needs_root`. Never hide an assumption.

## Build a cohesive document

- Re-paint affected sections instead of appending answers or a changelog.
- Patch only after a decision is resolved. Clarification and pushback are not decisions.
- Use takeaway-style headings that make the product shape clear when skimmed.
- Keep paragraphs short and place each mockup next to the prose it supports.
- Stay in product space: user experience, functionality, behavior, scope, and success. Put schemas, storage, and implementation architecture under `Deferred to TDD`.
- Use realistic labels and the product's existing design system in mockups.

## 1. Understand the context

Use `Shell` with `ls -La` to inventory the supplied task directory. Use `Read` to read each relevant input completely, excluding research-question documents when their resolved research artifact is present. Record the canonical path and SHA-256 hash of every ticket, research, design, and other upstream artifact before gathering more evidence. Read `references/prd_template.md` completely.

There is no mandatory upstream artifact. Work from the ticket, research, design context, or task text that exists. Cite upstream artifacts rather than duplicating them. Do not invent requirements when context is thin.

When a product choice depends on repository behavior, run a foreground `Task` with `model: inherit` and one appropriate read-only agent:

- `codebase-locator` to locate relevant files;
- `codebase-analyzer` to explain current behavior or the design system;
- `codebase-pattern-finder` to find comparable product patterns;
- `web-search-researcher` only for external primary-source facts.

Give the task one bounded question and require file-and-line evidence. Research agents must not edit source or any task artifact. Never use `Write` or `StrReplace` on a hashed upstream artifact. Integrate newly verified evidence only into the current PRD and its decision ledger; if the PRD skeleton does not exist yet, retain the evidence in context until it does. Do not revise the research artifact.

For UI work, establish the existing component library, colors, typography, spacing, borders, shadows, and theming before creating mockups. Use `codebase-analyzer` when research does not already contain this evidence.

## 2. Write the skeleton

Select the next unused zero-padded index in the canonical task directory and write:

```text
<task-dir>/NN-prd-<two-to-four-word-kebab-slug>.md
```

Use the bundled template. Start with only:

- frontmatter with `type: design-prd`, repository, branch, and `HEAD`;
- a title;
- a first-draft `Problem to Solve`;
- empty success, proposed-solution, and solution-details sections;
- an empty `Decision Ledger` in no-user mode.

Do not add setup prose or a speculative solution.

In interactive mode, immediately use `AskQuestion` to quote the drafted problem statement and ask whether it is correct. In no-user mode, verify the statement against supplied evidence, record the decision, and continue.

## 3. Settle the foundation

Resolve these in order:

1. **Problem to Solve** — what people experience today, whose problem it is, and why it matters.
2. **Success** — the observable lever that will show whether the change drove results.

Success may be a product metric, adoption signal, benchmark, reliability target, latency target, or qualitative read. For a small change with no honest measurement, explicitly record that conclusion instead of inventing a metric.

In interactive mode, present one decision with two or three meaningful options and a recommendation, then wait. When settled, use `StrReplace` to rework the relevant section and, when maintained, its ledger entry. Open the solution interview only after both foundation decisions are resolved.

In no-user mode, evaluate the same decisions one by one, write the selected result into the relevant section, and append a concise ledger entry with tag, alternatives considered, evidence, and rationale.

## 4. Resolve the solution

Walk the solution tree one decision at a time. For each choice:

1. Identify the single decision that unlocks the most remaining work.
2. Verify codebase-dependent facts before choosing.
3. Present credible options, tradeoffs, and a recommendation.
4. Resolve the choice through the selected interaction mode.
5. Rework all affected sections in one pass: `Proposed Solution`, `Solution Details`, `Alternative Solutions Considered`, `Out of Scope`, and `Deferred to TDD` when relevant.
6. Update the decision ledger and any affected mockup.

Never leave a question log in the PRD.

### HTML mockups

When a visual flow, layout, interaction, or state is under discussion, write a focused HTML mockup to:

```text
<task-dir>/mockup-<description>.html
```

Match the repository's product design system and use realistic content. Show side-by-side options when the decision benefits from comparison. Keep winning mockups current and embed them next to the relevant section:

````markdown
```task-artifact
.humanlayer/tasks/<task-slug>/mockup-<description>.html
```
````

In interactive mode, do not advance past requested mockup changes until the user approves the revised mockup. In no-user mode, validate the mockup against the selected behavior and record the choice in the ledger.

## 5. Review the whole solution

In interactive mode, after all branches are resolved, ask the user to read `Solution Details` top to bottom and approve the document as a whole. Incorporate feedback before completion.

In no-user mode, perform the same whole-document review yourself. Check that:

- problem, success, proposed behavior, mockups, alternatives, and scope agree;
- every unresolved choice appears in the ledger;
- every choice is tagged `recommended` or `assumed` with rationale;
- no technical implementation choice is presented as a product requirement;
- no open question is silently omitted.
- every upstream artifact still matches its recorded SHA-256 hash.

Return `needs_root` for any decision that remains unsafe to self-resolve.

## 6. Finish

Read `references/prd_final_answer_resolved.md` relative to this skill and follow the branch for the active interaction mode. Return absolute paths and direct evidence only. Do not claim approval, a mockup, or a resolved decision without evidence.

Document precedence is:

```text
PRD > design discussion > research > ticket
```
