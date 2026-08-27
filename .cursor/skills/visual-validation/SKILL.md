---
name: visual-validation
description: "Explicit-only: capture reproducible problem, before, and after evidence for rendered changes and generate a self-contained HTML comparison report; return applicable false for non-visual work."
disable-model-invocation: true
---

# Visual Validation

Collect visual evidence without treating image difference alone as proof of correctness.

## Input

Require an absolute task-directory path and one mode: `problem`, `baseline`, or `final`. In `final` mode, also require the caller's current automated-check results, `validationAttemptId: validation-N`, and positive integer `validationAttempt: N`; require the suffix and integer to match. Use **Read** to inspect the ticket, plan, validation documents, and existing visual manifest in that directory before acting.

Read [references/manifest.md](references/manifest.md) before creating or changing a manifest.

## Applicability

Visual validation applies when work changes rendered user-facing output or when an image or design is part of the expected result. This includes browser, desktop, and mobile UI, layout or styling fixes, generated-image output, and design-to-implementation work.

Return `applicable: false` with a concrete reason and create no `visual-evidence/` directory for database, backend-only, API-only, infrastructure, and non-rendered CLI changes. Do not invent screenshots for non-visual work. Reject string applicability values; accept only the booleans `true` and `false`.

## Capture tools

Use the repository's documented capture command when one exists. Otherwise use browser automation already available in the execution environment. Reuse an authorized browser session only when it is already available and scoped to the target application.

If applicable work has neither a repository-native capture path nor available browser automation, set the manifest status to `blocked`, add a concrete top-level blocking finding, and return a blocked result. Do not switch applicable work to `false` and do not add an optional skill dependency.

Prefer viewport screenshots over full-page captures. Wait for the plan's stable selector, visible text, URL, network-idle state, or other declared ready state; do not use arbitrary sleeps. Use the plan's viewport, defaulting browser captures to `1440x900` only when neither plan nor repository specifies one.

## Modes

### `problem`

Use when the workflow is reproducing a visually observable problem. Capture the narrowest screen state that proves the observation. Store it at `visual-evidence/problem/<scenario-id>.png` and record the exact route, setup, actions, viewport, capture point, commit, environment, and caption.

Do not diagnose or fix the problem. Return `applicable: false` when the problem is not visual while allowing other problem evidence to proceed.

### `baseline`

Run after the implementation plan is approved and before source changes begin.

1. Read the plan's Visual Validation Contract.
2. Return the non-applicable result when its discriminator is `applicable: false`.
3. Reject more than six scenarios.
4. Reproduce every scenario using its exact viewport and capture point.
5. Reuse a problem screenshot only when scenario, state, viewport, and capture point match exactly; otherwise capture `visual-evidence/before/<scenario-id>.png`.
6. Copy only plan-selected design references into `visual-evidence/design/` and record their source.
7. Use **Write** or **StrReplace** to create or update `visual-evidence/manifest.json` with status `baseline-captured`.

If an applicable baseline cannot be captured, preserve a manifest with status `blocked` and plain-string entries in top-level `blockingFindings`. Use `beforeUnavailableReason` only for a legitimate greenfield state with no comparable current screen, never for a capture failure.

### `final`

Run from `validate-implementation`, or from the RPI root verification-rerun stage, after automated checks.

1. Read the baseline manifest and approved plan.
2. Reproduce every scenario with the same setup, actions, viewport, and capture point.
3. Save each new capture at `visual-evidence/after/<validationAttemptId>/<scenario-id>.png`. Block rather than overwrite an existing attempt path. Never delete prior attempt directories or images.
4. Replace each scenario's current `after` object with that attempt-specific relative path and caption. The manifest points to the current attempt while prior attempt files remain intact.
5. Record whether the expected visual outcome is present and replace each scenario's observations with evidence from the current attempt. Difference alone is not a pass.
6. Replace stale top-level checks and blockers with the current automated-check results and current capture-specific blockers. Set manifest status to `final-captured` when captures completed or `blocked` when capture evidence failed. These are not yet the complete task findings.
7. Set `task.validationAttemptId` and `task.validationAttempt` to the current pair. Set `task.verdict` and `task.validationDate` to `null` before rendering so a prior attempt's verdict cannot appear as the current result. Do not decide or write the overall validation verdict.
8. Use **Shell** to run `python3 <this-skill-directory>/scripts/render_report.py --manifest <absolute-manifest-path> --output <absolute-task-directory>/YYYY-MM-DD-visual-validation-attempt-<validationAttempt>.html`. This is a preliminary report with a pending verdict.
9. Treat missing capture, unmet expected outcome, or renderer failure as a capture failure and return it to the invoking workflow verifier. `validate-implementation`, or the RPI root during its verification-rerun stage, merges the complete findings, writes the final verdict and validation date, and reruns the same attempt-specific report.

## Evidence rules

- Use stable lowercase scenario IDs containing letters, digits, and hyphens.
- Preserve problem, before, after, and selected design images as separate evidence classes. Preserve every `after/<validationAttemptId>/` directory across repair attempts.
- Store raster PNG, JPEG, GIF, or WebP only. Convert selected SVG or PDF references to PNG with existing repository or system tooling before adding them; the renderer rejects active or externally linked formats.
- Do not capture credentials, tokens, personal data, unrelated tabs, or developer tools containing sensitive values.
- Do not store cookies, browser profiles, or authentication state in the task directory or report.
- Keep evidence under the ignored `.humanlayer/tasks/<task>/` directory. Never stage or commit it.
- Run `python3 <this-skill-directory>/scripts/test_render_report.py` after changing the renderer or report template.

## Return contract

Return:

- `applicable`: boolean;
- `blocked`: boolean, true only when applicable evidence could not be produced;
- `reason`: applicability reason or blocker summary;
- `validationAttemptId` and `validationAttempt` in `final` mode;
- `manifestPath`: absolute path when applicable, otherwise `null`;
- `screenshots`: absolute paths created or reused in this mode;
- `reportPath`: absolute HTML path in successful `final` mode, otherwise `null`;
- `reportFinalized`: always `false` in this skill; the invoking workflow verifier owns final verdict rendering;
- capture and renderer commands with numeric exit codes.
