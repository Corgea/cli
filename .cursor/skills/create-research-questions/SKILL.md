---
name: create-research-questions
description: Create an objective query plan for researching how a codebase works today. Use only when explicitly invoked by a workflow or user.
disable-model-invocation: true
---

# Create Research Questions

Produce a focused query plan about the current system. Do not propose what to build, recommend changes, or leak the requested implementation into the questions.

## Inputs and installation

Require one absolute ticket or task-description path. Canonicalize it, require it to exist, and read it completely with `Read` before delegating. Capture every high-signal pointer verbatim: URLs, repositories, packages, dependencies, and paths.

Resolve this loaded `SKILL.md` to an absolute path and read `references/research_questions_template.md` beside it. Do not search another skill installation.

## Lightweight investigation

Use bounded foreground `Task` calls only when they materially improve the questions:

- `codebase-locator` for relevant source, configuration, and test locations;
- `codebase-analyzer` for current control flow and contracts;
- `codebase-pattern-finder` for representative current patterns;
- `web-search-researcher` only for authoritative external dependency behavior.

Use `model: inherit`. Group related work and keep each prompt read-only. Validate each helper's result against its agent contract; reject source changes, unsupported claims, and missing file evidence. Two or three helpers are normally enough. Do not delegate before reading the input yourself.

## Question rules

Write 2-7 questions unless the task is unusually broad. Questions must be positive and descriptive:

- what exists and where;
- how components, services, and modules interact;
- how data and control flow through the current system;
- what current contracts, constraints, failure modes, and tests exist;
- how named libraries or dependencies behave where relevant.

Never ask how the task should be implemented, what should change, why something has not been built, or which improvement to make. For possible frontend work, include one question covering the current design system: components, color values, typography, spacing, borders, shadows, and theming.

## Write the artifact

Resolve the task directory from the input path. It must be a canonical directory beneath the current repository. List it with `ls -La` through `Shell`. Choose the next unused zero-padded chronological index and write:

```text
.humanlayer/tasks/<task-slug>/NN-research-questions-<short-slug>.md
```

Use `Write` and the reference template. Fill all placeholders. Preserve the exact context pointers or omit that section when there are none. Include frontmatter for `task`, `type: research-questions`, `repo`, `branch`, and baseline `sha`.

Verify the file exists, resolves beneath the task directory, has the expected `type`, contains 2-7 questions, and calculate `git hash-object --no-filters -- <artifact>`.

Read `references/research_questions_final_answer.md` and return its envelope with the absolute artifact path and hash evidence. Report no source paths as changed.
