### Status

- Attempt: `[validation-N / positive integer N]`
- Document: `[absolute path to YYYY-MM-DD-validation-attempt-N.md]`
- Document SHA-256: `[digest]`
- Verdict: `[PASS or FAIL]`
- Blocking findings: `[count or none]`
- Visual applicability: `[true or false — reason]`
- Visual evidence: `[absolute HTML report and manifest paths, or null when false]`

### Summary

[Two or three sentences explaining the result and strongest evidence.]

### Key Findings

- [finding with file path, exact command result, or missing proof]
- ...

### Independent Review

- Reviewer: `[qa or codebase-analyzer]`
- Decision: `[GO or NO-GO]`
- Confidence: `[value]`

### Changed-Path Ownership

- Allowlist: `[paths]`
- Derived changed paths: `[paths with Git sources]`
- Outside allowlist: `[paths or none]`

### Next Step

[For FAIL, return the blocking findings to the invoking workflow for repair. For PASS, proceed to `describe-pr`.]

The full evidence is available at the validation document path above.
