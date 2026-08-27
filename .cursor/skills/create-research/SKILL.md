---
name: create-research
description: Research and document a codebase as it exists, using current source and authoritative dependency evidence. Use only when explicitly invoked.
disable-model-invocation: true
---

# Create Research

Create an objective technical map of the current system. Describe what exists, where it exists, how it works, and how components interact. Do not critique it, diagnose causes, recommend changes, or design the requested implementation.

## Inputs and installation

Require exactly one absolute research-questions document. Canonicalize and read it completely with `Read` before any delegation. Never read `ticket.md` or another task artifact unless the invoking prompt explicitly authorizes that exact file. If a task directory contains zero or multiple candidate question documents and no exact input was supplied, return `needs_root` with one precise question.

Resolve this loaded `SKILL.md` to an absolute path. Read `references/research_template.md` and, before reporting, `references/research_final_answer.md` beside it. Do not search another installation.

## Investigate

Decompose the questions into related research areas. Use 2-6 bounded foreground `Task` calls when the work warrants them:

- `codebase-locator` to find exhaustive or representative paths;
- `codebase-analyzer` to trace current implementation and data flow;
- `codebase-pattern-finder` to find existing conventions and examples;
- `web-search-researcher` for current primary documentation about an in-scope dependency.

Use `model: inherit` and self-contained, read-only prompts. Run independent searches concurrently when Cursor permits it, then wait for all results before synthesis. Require the helper agent's exact result contract, no changed paths, and evidence for each claim. Ask web research to return direct primary-source links.

Use live repository evidence as the primary source of truth. Verify important paths and line references with `Read` in this context. Group related questions; do not launch one helper per question by default. If synthesis leaves important open questions, run at most one additional targeted group before documenting the remainder as open.

## Write the research narrative

Gather the current ISO timestamp with timezone, repository name, branch, and `HEAD` with `Shell`. In the same canonical task directory as the input, choose the next chronological index and write:

```text
NN-research-<short-slug>.md
```

Use `Write` and the reference template. Fill every placeholder. The document must:

- answer the supplied questions as a cohesive story, not a question-by-question dump or file index;
- use takeaway headers that state what is true;
- weave repository-relative `file:line` or `file:start-end` citations into factual prose;
- use tables, Mermaid, trees, signatures, contracts, or pseudocode where they reveal structure faster;
- describe current testing patterns for every researched component and say when none exist;
- end with a comprehensive, grouped code-reference index and honest open questions;
- contain no recommendations, future design, change list, or diff-style proposal.

Verify cited files and sampled line ranges, confirm the artifact remains beneath the task directory, and calculate `git hash-object --no-filters -- <artifact>`. Read the final-answer reference and return its exact envelope. Report no source paths as changed.
