---
name: create-structure-outline
description: Create a decision-complete, phased implementation outline from approved task artifacts and repository evidence. Use only when explicitly invoked.
disable-model-invocation: true
---

# Create Structure Outline

Create the implementation contract consumed by `implement-outline`. It must leave no ownership, ordering, or verification decision to the implementer.

## Inputs and precedence

Require one canonical task directory beneath the current repository. List it with `ls -La` through `Shell`. Read all ticket, research, PRD, TDD, and design documents completely with `Read`; exclude research-questions documents. Read repository files needed to verify paths, signatures, test conventions, and runnable commands.

Apply this precedence among artifacts that exist:

```text
latest structure-outline revision > TDD > PRD > resolved design discussion > research > ticket
```

Stop with `needs_root` when a consequential conflict remains or design questions are unresolved.

Resolve this loaded `SKILL.md` to an absolute path and read `references/structure_outline_template.md` beside it. Do not search another installation.

## Close evidence gaps

Use bounded foreground `Task` calls with `model: inherit` only when evidence is missing:

- `codebase-locator` for relevant implementation and test paths;
- `codebase-analyzer` for exact current contracts and data flow;
- `codebase-pattern-finder` for representative change and test patterns;
- `web-search-researcher` only for primary external documentation required by the outline.

Validate every helper result and read decisive evidence yourself. User feedback updates the outline; verify any new factual claim before applying it.

## Design executable phases

Prefer thin vertical slices that deliver and verify behavior across the layers they require. Do not create horizontal phases such as all schema, then all API, then all UI when a vertical sequence is feasible. No phase may depend on a later phase before it can be verified.

For each phase, specify:

- an exact identifier and outcome;
- complete, canonical repository-relative source and test ownership paths;
- whether an owned path is a file or directory;
- any intentional sequential overlap with another phase and why it is safe;
- precise file changes and important interface or signature changes;
- exact automated commands, in order, plus the repository-relative working directory for each;
- manual checks only when human judgment is essential.

Ownership must cover every expected changed source or test path. Different phases must not overlap unless the outline explicitly assigns sequential ownership. Commands must be directly runnable, not prose, alternatives, placeholders, or partial examples. Prefer existing repository verification over invented commands.

## Define the Visual Validation Contract

Every outline must contain an explicit `Visual Validation Contract`.

- Set `applicable: true` when the work changes rendered user-facing output or an image/design is an expected result. This covers browser, desktop, and mobile UI, layout or styling fixes, generated-image output, and design-to-implementation work.
- Set `applicable: false` only for non-rendered work such as backend-only, API-only, database, infrastructure, or non-rendered CLI changes, and state the concrete reason.
- For applicable work, define 1-6 stable lowercase scenario IDs. Each scenario must specify route or entry point, deterministic setup state, exact actions, viewport, ready-state signal, capture point, expected visual outcome, and any selected design reference.
- Name the repository-native capture command when one exists. Otherwise state that available browser automation is required. Do not mark capture optional.
- Require baseline evidence before source edits and final evidence after automated checks. Both runs must use the same scenario setup, actions, viewport, ready state, and capture point.

An `applicable: true` outline is incomplete without reproducible scenarios. An `applicable: false` outline must contain no scenarios. Reject strings such as `applicable`, `APPLICABLE`, or `N/A`; the discriminator is always a JSON-style boolean. Return `needs_root` if applicability or required scenario details cannot be established from evidence.

## Write and verify the artifact

Choose the next chronological path:

```text
.humanlayer/tasks/<task-slug>/NN-structure-outline-<short-slug>.md
```

Use `Write` and the template. Fill every placeholder and include an unchecked implementation overview. Leave no open question in a completed outline; return `needs_root` instead when a decision is required. Do not create or suggest another checkout.

Verify:

- every owned path canonicalizes inside the repository;
- ownership is complete and overlap is explicitly resolved;
- every automated command has one working directory and no placeholder;
- documented test files and commands exist or are explicitly created by the owning phase;
- visual applicability is explicit and every applicable scenario is reproducible and complete;
- artifact type, branch, and baseline `sha` are correct.

Calculate `git hash-object --no-filters -- <artifact>`. Read `references/structure_outline_final_answer.md` and return its exact envelope. The compatibility file `references/structure_outline_final_answer_in_worktree.md` carries the same Cloud result and may be used only by callers that already reference that filename. Report no source changes.
