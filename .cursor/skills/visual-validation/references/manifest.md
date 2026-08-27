# Visual Evidence Manifest

Use JSON at `<task-dir>/visual-evidence/manifest.json` with `schemaVersion: 1`.

```json
{
  "schemaVersion": 1,
  "applicable": true,
  "reason": "Rendered account settings change",
  "status": "final-captured",
  "task": {
    "name": "account-settings",
    "repo": "example/repo",
    "branch": "feature/account-settings",
    "sha": "0123456789abcdef",
    "plan": ".humanlayer/tasks/account-settings/2026-07-22-plan.md",
    "validationAttemptId": "validation-1",
    "validationAttempt": 1,
    "validationDate": null,
    "verdict": null
  },
  "scenarios": [
    {
      "id": "edit-display-name",
      "title": "Edit display name",
      "expectedChange": "The saved value appears without clipping",
      "route": "http://localhost:3000/settings/profile",
      "setup": "Signed in as the seeded test user",
      "actions": ["Open Profile", "Enter a 40-character display name", "Save"],
      "capturePoint": "Success message is visible and the form is idle",
      "readyState": "Text 'Profile updated' is visible",
      "viewport": { "width": 1440, "height": 900 },
      "problem": {
        "path": "problem/edit-display-name.png",
        "caption": "Saved text clips at the right edge"
      },
      "before": {
        "path": "before/edit-display-name.png",
        "caption": "Current implementation"
      },
      "after": {
        "path": "after/validation-1/edit-display-name.png",
        "caption": "Validation attempt 1"
      },
      "beforeUnavailableReason": null,
      "designs": [
        {
          "path": "design/profile-reference.png",
          "caption": "Approved profile form design",
          "source": "ticket attachment"
        }
      ],
      "observations": ["The saved value is visible without clipping"]
    }
  ],
  "checks": [],
  "blockingFindings": []
}
```

## Required fields

- Require top-level `schemaVersion`, `applicable`, `reason`, `status`, `task`, and `scenarios`.
- Require `id`, `title`, `expectedChange`, `route`, `setup`, `actions`, `capturePoint`, `readyState`, `viewport`, `designs`, and `observations` for every scenario.
- Keep image paths relative to the manifest directory. Reject paths that escape that directory.
- Require `after.path` before report generation.
- In final mode, require matching `task.validationAttemptId: validation-N` and integer `task.validationAttempt: N`. Store current after captures under `after/<validationAttemptId>/`, update each scenario's `after.path` to that attempt, and preserve all earlier attempt directories.
- Require either `before.path`, `problem.path`, a non-empty `designs` list, or `beforeUnavailableReason` so a greenfield scenario explains what the result is compared against.
- Use `beforeUnavailableReason` only for a legitimate greenfield state with nothing current to capture. Put capture failures in top-level `blockingFindings` and set status `blocked`.
- Store `actions`, `observations`, and `blockingFindings` as arrays of strings.
- Store `checks` as objects with string fields `command`, `status`, and `note`.
- Limit scenarios to six and the generated self-contained HTML file to 20 MiB.

## Status values

Use `problem-captured`, `baseline-captured`, `final-captured`, or `blocked`. Use `blocked` with a concrete entry in `blockingFindings` whenever required evidence cannot be produced.
