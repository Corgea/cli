---
name: create-design-discussion
description: Turn codebase research and a change request into explicit, user-resolved design decisions. Use only when explicitly invoked.
disable-model-invocation: true
---

# Create Design Discussion

Produce a design document that connects the requested behavior to verified current-system patterns and makes consequential choices explicit.

## Inputs and precedence

Require one canonical task directory beneath the current repository. List it with `ls -La` through `Shell`. Read every ticket, research, and existing design artifact completely with `Read`; do not read research-questions documents. Read relevant repository files named by those artifacts before delegating.

Use this precedence when inputs conflict:

```text
latest resolved design decision > research > ticket
```

Resolve this loaded `SKILL.md` to an absolute path and read `references/design_discussion_template.md` beside it. Do not search another installation.

## Fill evidence gaps

When existing research cannot support a design choice, use bounded foreground `Task` calls with `model: inherit`:

- `codebase-locator` for missing integration points;
- `codebase-analyzer` for current behavior and contracts;
- `codebase-pattern-finder` for representative patterns;
- `web-search-researcher` only for primary dependency documentation.

Keep helper prompts read-only and validate their result envelopes. Read decisive code evidence yourself before using it. Skip delegation when user feedback can be applied from evidence already present.

## Select or resume the artifact

On the first run, when no design artifact is supplied or recorded, choose the next chronological path:

```text
.humanlayer/tasks/<task-slug>/NN-design-discussion-<short-slug>.md
```

On a relaunch after `needs_root`, require the invoking prompt to supply the exact existing design-artifact path, its previously recorded hash, and the user's answer. Canonicalize the path, require it beneath the task directory with `type: design-discussion`, and verify `git hash-object --no-filters -- <artifact>` equals the supplied hash before editing. Revise that exact file in place with `StrReplace`; do not select a new chronological path, copy the document, or create a second design artifact. If the path or hash does not match, return `blocked` without writing.

## Write and resolve the design

For a first run, use `Write` and the reference template. For a relaunch, preserve unaffected content and use `StrReplace` only for the decisions and evidence changed by the user's answer. Include:

- a product-level current state, desired end state, and explicit non-goals;
- before and after architecture views where they add clarity;
- verified codebase patterns with repository-relative locations and concise snippets;
- a testing approach grounded in current tests;
- a **Smallest Viable Control** decision comparing existing control surfaces and selecting the least complex sufficient scope;
- explicit justification for any new persisted state, feature flag, dependency, infrastructure, concurrency, or cross-service control.

Every consequential unresolved choice begins under `Design Questions` with options, tradeoffs, and a recommendation. Do not silently choose for the user. Return `needs_root` with those questions so the root can use `AskQuestion`. When relaunched with explicit feedback, verify any factual claims, move answered items to `Resolved Design Questions` in the same artifact, record the decision and rationale, and retain rejected options briefly. Do not proceed as complete while consequential design questions remain open.

Verify the artifact's canonical path, expected type, resolved-question state, and calculate its new `git hash-object --no-filters -- <artifact>` value. On a relaunch, return the same absolute path and the replacement hash so the root can retain the prior hash as history and update the current state hash. Read `references/design_discussion_final_answer.md` when questions remain, otherwise read `references/design_discussion_final_answer_resolved.md`. Return the selected envelope exactly and report no source changes.
