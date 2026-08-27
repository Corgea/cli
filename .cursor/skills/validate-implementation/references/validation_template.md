---
task: [task slug]
type: validation
validation_attempt_id: validation-N
validation_attempt: [positive integer]
repo: [repository root]
branch: [branch]
sha: [HEAD]
plan: [absolute plan or structure-outline path]
exec_plan: [absolute path or "none"]
visual_applicable: true|false
visual_manifest: [absolute path or "none"]
visual_report: [absolute path or "none"]
verdict: PASS|FAIL
---

# [Feature or Task] Validation

## Overview

[What was validated and the evidence-backed result.]

## Scope and Inputs

- Plan: `[path]`
- ExecPlan: `[path or none]`
- Validation date: `[YYYY-MM-DD]`
- Validation attempt: `[positive integer]`
- Repository state: `[branch, HEAD, and status summary]`

## Changed-Path Ownership

- Implementation start: `[SHA or documented default-branch merge-base fallback]`
- Allowlist: `[repository-relative file paths]`
- Derived changed paths: `[paths with committed/staged/unstaged/untracked source]`
- Allowlisted but unchanged: `[paths or none]`
- Outside allowlist: `[paths or none; any entry forces FAIL]`

## Verdict

**Verdict:** `PASS` or `FAIL`

[Concise rationale tied to required behavior and executed evidence.]

## Executed Checks

| Command | Working directory | Exit code | Result | Evidence |
|---|---|---:|---|---|
| `[exact command]` | `[path]` | `[number or N/A]` | `[pass/fail/blocked]` | [relevant output] |

## Independent Review

- Reviewer: `[qa or codebase-analyzer]`
- Decision: `[GO or NO-GO]`
- Confidence: `[value]`
- Blocking findings: `[findings or none]`
- Missing or weak evidence: `[items or none]`

## Visual Validation

- applicable: `[true or false]`
- Reason: `[why visual evidence applies or why the change is non-visual]`
- Manifest: `[absolute path or none]`
- HTML report: `[absolute path or none]`
- Scenario results: `[passed / total or none]`

[For each applicable scenario, record its evidence paths, viewport, expected outcome, observation, and result.]

## Plan Coverage

### Covered and Verified

- [criterion with code and command evidence]

### Missing, Mismatched, or Unproven

- [criterion and missing evidence, or `None`]

## Blocking Findings

- [blocking issue or `None`]

## Manual Validation Remaining

- [required manual step or `None`]

## Recommendation

[If PASS, state readiness for review. If FAIL, state what the invoking workflow must repair.]
