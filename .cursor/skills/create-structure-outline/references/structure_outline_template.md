---
task: <task-slug>
type: structure-outline
repo: <current repository>
branch: <current branch>
sha: <baseline HEAD>
---

# <Plan Title>

<Two or three sentences describing the implementation approach.>

## Desired End State

- <Observable result>

## Implementation Overview

- [ ] Phase 1: <Phase title>
- [ ] Phase 2: <Phase title>

## Visual Validation Contract

**applicable**: <`true` or `false`>

**Reason**: <why rendered evidence is required or why the work is non-visual>

**Capture mechanism**: <exact repository-native command, `available browser automation`, or `none` only when `applicable: false`>

### Scenarios

<!-- `applicable: true` requires 1-6 scenarios. Replace this section with `None.` when `applicable: false`. -->

#### <stable-lowercase-scenario-id>

- **Route or entry point**: <exact route, screen, document, or generated output>
- **Setup state**: <deterministic fixtures, account state, seed data, or prerequisites>
- **Actions**: <ordered actions that reach the state>
- **Viewport**: <width>x<height>
- **Ready state**: <stable selector, visible text, URL, network-idle state, or equivalent signal>
- **Capture point**: <exact state and region to capture>
- **Expected visual outcome**: <observable result the final image must prove>
- **Design reference**: <exact source to copy into evidence, or `None`>

---

## Phase 1: <Phase Title>

<Independently verifiable vertical-slice outcome.>

### Path Ownership

- **File `path/to/source.ts`** — <why this phase owns it>
- **Directory `path/to/tests/`** — <why descendants are owned>
- **Sequential overlap** — <other phase and rationale, or `None`>

### File Changes

- **`path/to/source.ts`** — <exact behavior or interface change>
- **`path/to/source.test.ts`** — <coverage added or updated>

```text
<important new or changed signature, contract, or pseudocode>
```

### Validation

#### Automated Verification

- [ ] Working directory: `<repository-relative directory>`; command: `<exact runnable command>`

#### Manual Verification

- [ ] <Essential human-judgment check, or `None`>

---

## Phase 2: <Phase Title>

<Repeat the same ownership, changes, and validation structure.>

## Open Questions

None.
