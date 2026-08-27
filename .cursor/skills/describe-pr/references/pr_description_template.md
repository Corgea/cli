# Pull Request Description Template

Use this template to create `pr-description.md`. Remove instructions and empty optional sections from the completed artifact.

# Summary

[Two or three sentences explaining the problem, the resulting behavior, and the implementation shape.]

## Context

- Ticket: [identifier and source URL when present]
- Plan: `[repository-relative path when present]`
- Comparison: `[base SHA]...[head SHA]`
- Walkthrough: `[repository-relative walkthrough path when generated; otherwise omit]`

## Problems addressed

[Describe the concrete problem and what becomes true after this change.]

## User-facing changes

- `[path]` — [observable behavior change]
- [Write `None` when the change has no user-facing effect.]

## Implementation

[Walk through the committed change by behavior or component. Cite repository-relative paths and symbols.]

## Deviations from the plan

### Implemented as planned

- [item or `None`]

### Deviations/surprises

- [item or `None`]

### Additions not in plan

- [item or `None`]

### Items planned but not implemented

- [item or `None`]

## Verification

- `[exact command]` — [result and numeric exit code]
- [manual verification still required, if any]

## Compatibility and migration notes

[Breaking changes, migration/rollout requirements, or `None`.]

## Changelog

[One concise line suitable for release notes.]
