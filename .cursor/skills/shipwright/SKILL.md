---
name: shipwright
description: Run the gated product pipeline from a task or Linear ticket through research, PRD, TDD, vertical-slice implementation, simplification, adversarial validation, one allowlisted local commit, and Cursor-owned pull-request publication. Use only when the user explicitly invokes /shipwright.
disable-model-invocation: true
---

# Shipwright

Run the product pipeline in order. Keep orchestration, user decisions, safety checks, and result validation in the root agent. Keep `.humanlayer/**` out of every commit. Cursor owns branch push and pull-request creation after this workflow finishes.

## Runtime contract

Use only Cursor's `Task`, `Shell`, `Read`, `Write`, `StrReplace`, and `AskQuestion` tools. Run delegated stages sequentially in the foreground.

Resolve the absolute directory containing this loaded `SKILL.md`, then treat that directory's parent as `<skills-root>`. Resolve every downstream instruction as `<skills-root>/<skill-name>/SKILL.md`. Block if a required file is missing or resolves outside `<skills-root>`. Never depend on a user-specific directory.

Delegate each stage with `Task` using the brain in this table, `model: inherit`, and a self-contained prompt containing absolute artifact paths, repository anchors, stage-specific authority, and the root overrides in this skill.

| Stage | Agent | Skill or prompt |
|---|---|---|
| Research questions | `brain-terra` | `create-research-questions` |
| Research | `brain-terra` | `create-research` |
| PRD / PRD revision | `brain-opus` | `create-prd` / `iterate-prd` |
| TDD / TDD revision | `brain-opus` | `create-tdd` / `iterate-tdd` |
| Outline / outline revision | `brain-sol` | `create-structure-outline` / `iterate-structure-outline` |
| Visual baseline | `brain-terra` | `visual-validation` |
| Phase implementation | `brain-grok` | direct bounded phase prompt |
| Simplification | `brain-sol` | `simplify` |
| Validation | `brain-terra` | `validate-implementation` |
| Refutation | `brain-sol` | direct read-only prompt |
| Repair | `brain-grok` | direct bounded repair prompt |
| Commit | `brain-luna` | `ci-commit` |
| PR description | `brain-sol` | `describe-pr` |

Do not invoke another implementation orchestrator. Each implementation phase and repair cycle gets a fresh bounded `brain-grok` task with explicit path ownership. Do not invoke an iteration skill for implementation repair.

### Require one stage envelope

Every delegated prompt must say that the parent's instructions override downstream checkpoints, commit steps, and final-answer templates. A stage must not contact the user. It must finish with exactly this envelope:

```text
STATUS: complete | blocked | needs_root
ARTIFACTS:
- <absolute path or none>
DECISIONS:
- <decision tagged recommended or assumed, or none>
QUESTIONS:
- <question for root or none>
VERIFICATION:
- <exact command/check, result, and numeric exit code when applicable, or none>
CHANGED_PATHS:
- <absolute path or none>
BLOCKER: <exact blocker or none>
```

Reject malformed envelopes, unsupported status values, relative artifact paths, or claims without required evidence. Run one corrective same-stage `Task` at most; block if the second result remains invalid. Route product choices, permission requests, destructive actions, credentials, and new authority to the root.

## Dispatch a new run or an exact resume action

Classify the request before running any new-run setup or writing any file. After trimming surrounding whitespace, recognize a resume only when the entire request is exactly one of:

```text
/shipwright approve-prd
/shipwright request-prd-changes
/shipwright approve-build
/shipwright request-build-changes
/shipwright leave-changes
/shipwright commit-anyway
```

Do not accept aliases, prefixes, suffixes, embedded feedback, or inferred approvals. Collect feedback for either `request-*-changes` action only after selecting and validating its saved run. Any other nonempty request is a new run only when it contains a task description or one Linear URL. If the request is only `/shipwright`, use `AskQuestion` for the task and do not inspect old state as an implied resume.

### Persist one durable run state

Every run owns exactly one canonical `<task-dir>/shipwright-state.json`. Create it immediately after validating and writing `ticket.md`. Update it after every accepted artifact, gate transition, user choice, implementation phase, simplification, validation, refutation, repair, commit, and PR-artifact stage. Read the file back after every `Write`, parse it as JSON, and verify that the written content matches the in-memory state.

The state schema is versioned and contains at least:

```json
{
  "version": 1,
  "task_slug": "safe-task-slug",
  "repo_root": "/absolute/repository/root",
  "branch": "named-non-default-branch",
  "default_branch": "default-branch",
  "baseline_head": "full-commit-id",
  "expected_head": "full-commit-id",
  "baseline_status": "",
  "expected_source_status": [],
  "ticket": {"path": "/absolute/path", "sha256": "hex-digest"},
  "artifacts": {
    "stage-name": [{"path": "/absolute/path", "sha256": "hex-digest"}]
  },
  "current_gate": "running:research-questions",
  "implementation_allowlist": [],
  "required_commands": [],
  "visual_validation": {
    "applicable": false,
    "contract_path": null,
    "baseline_artifacts": [],
    "final_artifacts": [],
    "manifest": {
      "path": null,
      "current_sha256": null,
      "previous_sha256": []
    }
  },
  "validation_attempts": [],
  "repair_attempts": [],
  "authorized_source_snapshot": null,
  "failed_source_snapshot": null,
  "choices": []
}
```

Store immutable artifact paths with SHA-256 hashes. The mutable visual manifest is never an entry in `artifacts`, `baseline_artifacts`, or `final_artifacts`; track it only through its dedicated `manifest` record. Before any task may mutate that manifest, prove its bytes hash to `current_sha256`, append that exact prior hash to `previous_sha256` once and only once, and persist state. After the task returns, require the manifest to remain a canonical regular file in `<task-dir>`, recompute its SHA-256, require a changed hash, and replace `current_sha256`. Block on a missing hash, duplicate history append, out-of-order history, or any unaccounted manifest mutation.

Store validation records with unique attempt IDs, exact commands and exit codes, visual results, verdicts, evidence paths, and the exact source snapshot described below. Store repair records with unique IDs, input verdict, changed paths, and outcome. Treat `choices` as an append-only event log: append the gate and exact action first, then append a linked feedback-hash event when a change action collects feedback. Never replace history. Allowed durable gate values are `running:<stage>`, `prd-approval`, `build-approval`, `failed-validation`, `publication-ready`, `left-changes`, and `complete`.

### Resume before new-run setup

For an exact resume action, do not create a slug, task directory, ticket, or state. Resolve the current repository root read-only, inventory direct child task directories beneath its canonical `.humanlayer/tasks` directory, and `Read` each regular `shipwright-state.json`. Reject state paths outside the tasks directory, symlinked state files, malformed JSON, unsupported versions, duplicate task slugs, or states whose `repo_root` differs from the current canonical root.

Map actions to required gates:

| Action | Required `current_gate` |
|---|---|
| `approve-prd`, `request-prd-changes` | `prd-approval` |
| `approve-build`, `request-build-changes` | `build-approval` |
| `leave-changes`, `commit-anyway` | `failed-validation` |

Filter candidates by the required gate. If none match, block with the expected gate. If exactly one matches, select it. If several match, use `AskQuestion` only to request one of their exact task identifiers; do not ask the user to repeat the action or provide feedback. The returned identifier must select exactly one state.

Before dispatching any action, prove all saved anchors:

1. Current repository root, named branch, default branch, and `HEAD` equal the saved values expected at this gate.
2. `.humanlayer/**` remains untracked and the repository exclude entry remains present exactly once.
3. Ticket, every saved immutable artifact, and every saved source-snapshot file are regular canonical files inside the selected task directory and match their saved SHA-256 hashes or snapshot digests. Separately require the visual manifest at its dedicated canonical path to match `current_sha256`, and require its ordered `previous_sha256` history to contain no duplicate or current hash.
4. The source status exactly matches `expected_source_status`; task artifacts are ignored. PRD and build gates require no source changes. The failed-validation gate requires an exact canonical source snapshot match to `failed_source_snapshot`, not status text alone, and permits only the saved implementation allowlist.
5. Validation and repair attempt IDs are unique, counts do not exceed one initial validation plus two repairs, and the saved gate agrees with their latest verdict.
6. Saved choices do not already contain a conflicting action for the same gate occurrence.

Block on any mismatch; never repair state implicitly. After proof, append the exact action to `choices`, set the next `current_gate`, persist state, and dispatch only the mapped continuation:

- `approve-prd` → TDD stage.
- `request-prd-changes` → use `AskQuestion` for exact product feedback, append its hash as a linked choice event, run PRD revision, then return to the PRD gate.
- `approve-build` → visual baseline stage, then approved implementation phases.
- `request-build-changes` → use `AskQuestion` for exact feedback, append its hash as a linked choice event, route it at the highest affected layer, then return to the required gate.
- `leave-changes` → set `left-changes` and report without committing.
- `commit-anyway` → record the failed verdict authorization and enter the sole commit stage.

Pass the selected state path and its verified state hash to every resumed stage. Never treat a task description as a resume or a resume action as a new task.

## Establish a safe keel

Accept a plain task description or one Linear ticket URL. Use the installed Linear connector for a URL. If the connector is unavailable or the ticket cannot be read, use `AskQuestion` to request the ticket text and stop.

Before writing any artifact:

1. Use `Shell` to resolve and record the canonical repository root, `HEAD`, current branch, and `git status --porcelain=v1 --untracked-files=all`.
2. Resolve the default branch from repository metadata. Fall back to the unambiguous target of `refs/remotes/origin/HEAD`; block if neither source yields exactly one branch.
3. Require a clean worktree, a named non-detached branch, and a branch different from the default branch.
4. Reject the run when `git ls-files -- .humanlayer` returns any tracked path.
5. Derive a safe lowercase kebab-case slug. Preserve a normalized ticket-ID prefix when present. Allow only `[a-z0-9-]`, collapse repeated hyphens, trim surrounding hyphens, and reject empty values, `.`, `..`, path separators, whitespace, shell metacharacters, substitutions, leading `-`, or traversal after canonicalization.
6. Resolve the canonical tasks root and candidate `<task-dir>` without creating either. Prove the candidate remains directly inside the tasks root, then use an `lstat`-equivalent check on the exact candidate. Before any new-run write, require that no file, directory, symlink, or other filesystem entry exists there. Any collision blocks; never inspect or reuse it as state. Exact resume actions are the only resume path.
7. Resolve the repository's exclude file with `git rev-parse --git-path info/exclude`. Use `Read` and `Write` to append the exact line `/.humanlayer/` only when absent, preserving all existing content and a final newline. Verify exactly one such line exists. This file is Git metadata, not source.
8. Create the previously absent `<task-dir>`, then write `<task-dir>/ticket.md` with the exact task text and source URL when present.
9. Write the initial `shipwright-state.json` with the recorded anchors, ticket path and hash, empty artifact/attempt/choice collections, and `current_gate: "running:research-questions"`.

The recorded repository root, baseline `HEAD`, branch, default branch, baseline status, ticket hash, and artifact hashes are the run anchor. Recheck them before implementation, commit, and final reporting.

### Validate artifacts and resume state

Before each artifact-producing stage, inventory existing task files and compute content hashes. Exclude the canonical state file from stage outputs. Accept an artifact only when it is an absolute canonical path inside `<task-dir>`, a regular nonempty file, and one of these is true:

- the stage newly created the expected canonical artifact;
- the artifact is the exact unchanged output of a completed stage and matches the same ticket and upstream artifact paths; or
- a revision changed the one assigned canonical artifact in place, incorporated the supplied feedback, and updated its embedded decision ledger.

Do not create duplicate stage artifacts. Block on multiple candidates, changed inputs, unexpected source edits, a divergent branch or `HEAD`, mismatched embedded paths, or conflicting run state. After accepting an artifact, add its canonical path and SHA-256 hash to state before advancing. Before implementation allow only ignored task artifacts and require no source changes. Before commit allow only the implementation allowlist plus ignored task artifacts.

### Bind authorization to an exact source snapshot

Read the [canonical source-snapshot schema](../ci-commit/references/source_snapshot.md) completely and use its exact byte encoding, ordering, and framing. Block on any conflicting snapshot instruction.

Status text and path allowlists are not commit authorization. Whenever this skill requests a source snapshot, create an immutable canonical JSON file under `<task-dir>/source-snapshots/<unique-id>.json` without modifying source. Build it from NUL-delimited Git output and raw filesystem reads so unusual filenames are unambiguous. Include:

- full `HEAD`, branch, raw `git status --porcelain=v2 -z --untracked-files=all`, `git ls-files --stage -z`, and staged/unstaged raw diff records with rename and copy detection enabled;
- every changed, deleted, rename/copy source and destination, and untracked path, encoded as base64 of the raw path bytes; base64-encode any complete raw Git record kept in JSON as well, and sort by decoded raw path bytes;
- for each path, HEAD state, index state, and worktree state separately;
- Git object IDs, Git modes, and SHA-256 of staged/HEAD blob bytes when present;
- worktree entry type, full `lstat` mode, SHA-256 of regular-file bytes or symlink-target bytes, and the prospective index mode/object ID Git would produce from that exact worktree state after applying repository attributes; represent absence explicitly;
- rename/copy relation and score plus an explicit untracked marker.

Reject submodules and unsupported special files. Exclude only ignored files and `.humanlayer/**`. Require the index to equal `HEAD` before validation or commit; still record the empty staged state so an unexpected staged edit changes the digest and blocks. Sort entries by decoded raw path bytes and serialize UTF-8 JSON with sorted keys, compact separators, and one trailing newline. The SHA-256 of those exact JSON bytes is the snapshot digest. Persist `{path, digest}`; the snapshot file is immutable and may not include itself or the mutable visual manifest.

Before and after every supposedly read-only validation or refutation task, rebuild the snapshot in memory and require its digest to equal the bound digest. Any mismatch proves source mutation and blocks; do not authorize or silently restore it. A repair invalidates `authorized_source_snapshot` before the worker starts. A successful validation plus non-refuting read-only review sets `authorized_source_snapshot` to that validation attempt's exact `{path, digest}`. A failed final verdict stores its exact `{path, digest}` as `failed_source_snapshot` before entering the failed-validation gate.

## Produce product and design artifacts

### 1. Research questions

Run `brain-terra` with resolved `create-research-questions/SKILL.md` and the absolute ticket path. Require one absolute research-questions artifact. Permit no source edit or commit.

### 2. Research

Run a fresh `brain-terra` task with resolved `create-research/SKILL.md` and the research-questions artifact as its only task-artifact input. Do not give this stage the ticket, task directory, or unrelated artifacts. Require repository-grounded evidence and one research artifact. Permit no source edit or commit.

### 3. PRD

Run `brain-opus` with resolved `create-prd/SKILL.md`, `<task-dir>`, and the research path. Include the exact flag `NO_USER_AVAILABLE: true`. This is the only condition that authorizes the skill to self-resolve its interview. Require it to enumerate unresolved product choices, choose the best supported answer, tag each choice `recommended` or `assumed`, self-approve its internal review, and embed the complete decision ledger in the PRD. Keep mockups inside `<task-dir>`. Permit no source edit or commit.

### 4. PRD approval gate

Read the PRD. Persist its path/hash and every mockup path/hash, set `current_gate: "prd-approval"`, set `expected_head` and `expected_source_status` from the verified clean anchors, and verify the saved state before presenting the gate. Present behavior and scope, assumed decisions first, recommended decisions, open questions, and clickable mockup paths. Ask with `AskQuestion`:

- `/shipwright approve-prd` (recommended) — continue to TDD.
- `/shipwright request-prd-changes` — collect exact product feedback.

Stop after asking. Route the returned exact action through the resume dispatcher, even when `AskQuestion` returns during the same turn. On changes, run a fresh `brain-opus` task with `iterate-prd`, the PRD path, the exact feedback, and `NO_USER_AVAILABLE: true`. Require in-place revision and an updated embedded ledger, save the new artifact hashes, then re-present this gate.

### 5. TDD

Run `brain-opus` with resolved `create-tdd/SKILL.md`, `<task-dir>`, and the approved PRD path. Include `NO_USER_AVAILABLE: true`. Require it to self-resolve the system-design and program-design interviews and their internal sign-offs, tag every decision `recommended` or `assumed`, and embed the complete decision ledger in the TDD. Keep diagrams inside `<task-dir>`. Permit no source edit or commit.

### 6. Vertical-slice outline

Run `brain-sol` with resolved `create-structure-outline/SKILL.md`, `<task-dir>`, and the absolute research, PRD, and TDD paths. Require thin vertical slices that each deliver testable behavior. Every phase must include:

- exact owned source paths;
- exact automated verification commands;
- manual verification steps that cannot be automated;
- dependencies and observable completion criteria.

Require a top-level `Visual Validation Contract` in the outline. It must declare either `applicable: false` with evidence that no user-visible behavior or rendering changes, or `applicable: true` with one or more named scenarios. Each applicable scenario must define a unique scenario ID, promised behavior tied to the PRD/mockup, deterministic starting state or fixture, startup command and working directory, route or entry point, viewport/browser requirements, exact user actions, baseline capture, expected final observations, capture artifact naming, and pass/fail criteria. Treat changed UI, rendered output, interaction states, visual regressions, and mockup-backed behavior as applicable. Reject `applicable: false` when any approved artifact promises visual behavior.

Reject vague commands, overlapping ownership, phases that cannot be verified independently, a missing/invalid Visual Validation Contract, or a recommendation to launch another implementation orchestrator. Return the ordered phases, complete exact command list, all manual steps, the parsed visual contract/scenarios, and open questions. Persist the outline path/hash, required commands, and visual contract in state.

### 7. Build approval gate

Run a read-only publication preflight: recorded branch/default branch, remote and upstream state, GitHub integration metadata availability, existing PR state when visible, and any publication blocker. Persist every approved artifact hash, set `current_gate: "build-approval"`, and verify the clean source status. Present the PRD and TDD ledgers, outline phases and ownership, every exact automated command, the complete Visual Validation Contract and scenarios, every outstanding manual step, open questions, and preflight result. Ask with `AskQuestion`:

- `/shipwright approve-build` (recommended) — authorize source edits, simplification, validation, one allowlisted local commit, and Cursor-owned publication.
- `/shipwright request-build-changes` — collect exact feedback.

Stop after asking. Route the returned exact action through the resume dispatcher, even when `AskQuestion` returns during the same turn. Route change feedback at the highest affected layer, then repeat required downstream stages:

- Product behavior or scope: revise with `iterate-prd`, return to the PRD gate, then regenerate TDD and outline.
- Technical design: revise with `iterate-tdd`, then regenerate the outline; return to the PRD gate first if product behavior changes.
- Slicing, verification, or visual evidence: revise with `iterate-structure-outline` and require the complete current phase, ownership, command, manual-check, and Visual Validation Contract lists.

Revision tasks include `NO_USER_AVAILABLE: true` only because the parent supplies exact feedback and owns the user interaction. Never silently reinterpret feedback at a lower layer.

## Build approved phases

After approval, recheck the run anchor and parse the approved outline in the root.

### Capture the visual baseline before source edits

Read the saved Visual Validation Contract before starting any implementation task. When `applicable: false`, verify its rationale against the PRD, mockups, TDD, and outline and store that verified boolean result in state.

When `applicable: true`, run a fresh `brain-terra` task with resolved `visual-validation/SKILL.md`, the exact contract, all scenario IDs, repository anchor, task directory, and `MODE: baseline`. Require it to prove that the application can start, the required browser/capture mechanism is available, each deterministic starting state can be reached, and every baseline image/evidence artifact is a regular nonempty file inside `<task-dir>`. Require a result for every scenario ID. Store immutable capture/evidence paths and hashes in `visual_validation.baseline_artifacts`. Store the one mutable manifest only in `visual_validation.manifest` with its canonical path, computed `current_sha256`, and empty `previous_sha256`; reject any result that also lists the manifest in an immutable artifact array.

Block before any source edit when capture capability is unavailable, startup fails, a scenario cannot reach its starting state, the returned scenario set differs from the contract, or any baseline artifact fails canonical-path/hash validation. Do not switch applicable work to `false`.

For each phase, run one fresh `brain-grok` task with the exact phase text; absolute ticket, research, PRD, TDD, and outline paths; explicit source-path ownership; prior changed paths; and current repository anchor. State that other work may exist, edits outside ownership must be preserved, only owned source paths may change, `.humanlayer/**` must not change, and no commit is allowed.

After each phase:

1. Compare actual changed paths against ownership and the prior diff.
2. Reject secrets, credentials, baselines, setup changes, generated local state, and unrelated edits.
3. Run the phase's automated commands sequentially exactly as written and record each numeric exit code.
4. Advance only when every command exits zero.
5. Mark phases with pending manual steps `automated complete; manual verification outstanding`.
6. Update `expected_source_status`, implementation allowlist, phase result, and exact command evidence in state before launching the next phase.

Return `needs_root` when implementation exposes a product choice, permission, destructive action, credential need, or authority not granted at the build gate.

## Simplify once

After all phase commands pass, compute the exact implementation allowlist from the union of phase-owned changed source paths. Block on any unexplained path.

Run `brain-sol` with resolved `simplify/SKILL.md`, repository root, pre-implementation `HEAD` and status, exact allowlist, current diff, and phase verification evidence. Require behavior and public-interface preservation; all reads and edits inside the allowlist; no task-artifact edits; no staging or commit; and the envelope to report resolved scope, applied/skipped candidates, changed paths, and verification. A verified no-op is complete. Reject any path outside the allowlist. Do not repeat simplification during repairs.

## Validate, refute, and repair

### Validate

Allocate a globally unique monotonic attempt pair from state before every validation task: `validationAttemptId: validation-N` and `validationAttempt: N`, where `N` is `1`, `2`, or `3`. Require the suffix and integer to match. Never reuse a pair after a failed, malformed, or interrupted task. Create the canonical exact source snapshot `source-snapshots/validation-N.json` and persist its path/digest on the pending attempt before dispatch. Include both attempt values and the source snapshot path/digest in every task name, prompt, required envelope, evidence filename, and returned verdict.

When visual validation applies, prove the baseline/current manifest matches `current_sha256`, append that hash exactly once to `previous_sha256`, and persist state before the validator task. The validator owns the one final capture for this attempt: it runs the fresh automated checks first, passes those current results to `visual-validation` final mode, and then finalizes the verdict and rerenders the same preliminary report within that single task. No separate root-level final capture may run for the same attempt.

Run `brain-terra` with resolved `validate-implementation/SKILL.md`, `visualFinalEvidenceMode: capture-in-validator`, both attempt values, all approved artifacts, current diff, exact implementation allowlist as `changedPathAllowlist`, exact tracked commands, the saved Visual Validation Contract, immutable baseline artifacts, expected manifest path/hash, and exact source snapshot path/digest. Require it to:

- treat the approved structure outline as the implementation plan regardless of filename;
- run every declared automated command exactly as written;
- discover and run repository-wide test, lint, typecheck, and build checks when defined;
- report every command verbatim with numeric exit code and relevant failure output;
- compare behavior against the PRD, mockups, TDD, and outline;
- consume and verify every saved baseline path/hash before assessing final behavior;
- when visual validation is applicable, consume every exact scenario ID and compare immutable baseline/final observations against the contract and approved mockups, failing on missing, extra, unavailable, or non-passing scenarios;
- when visual validation has `applicable: false`, verify the saved rationale still holds after inspecting the diff;
- distinguish unperformed manual checks.

After the task, recompute the source snapshot and require the bound digest. When applicable, require one complete returned result per scenario, recompute the finalized manifest hash, require it changed from the pre-validator hash, update `current_sha256`, verify the append-only hash history, and store the new attempt-specific captures plus the finalized HTML report as immutable `final_artifacts`. A preliminary or pending-verdict report is never accepted or persisted as final evidence. Normalize only leading/trailing whitespace and runs of internal whitespace when matching required commands to evidence. A required command passes only when its normalized reported command is exactly equal and exited zero. Substrings, supersets, or inferred equivalence do not count. Overturn any pass with a missing, altered, or nonzero command. Persist the completed attempt, verdict, exact evidence, finalized manifest hash, immutable visual evidence, and source snapshot before refutation or repair. No commit is allowed until the latest validator has consumed and passed the Visual Validation Contract.

### Refute a mechanical pass

On a mechanical pass, first recompute and bind the same source snapshot digest, then run one read-only `brain-sol` task with a unique `refutation-N` ID against that snapshot, the PRD, mockups, TDD, outline, Visual Validation Contract, immutable baseline/final visual evidence, current diff, tests, and validation evidence. Require it to try to prove missing promised behavior, an impossible mockup interaction, invalid visual evidence, vacuous tests, regressions, or unsupported claims. Recompute the exact snapshot after the task and require the same digest; any byte/mode mutation blocks and cannot authorize a commit. Any concrete evidence overturns the pass. A failed invocation or malformed envelope is a failed verdict. Persist the ID and result on the matching validation attempt. Only an upheld result sets `authorized_source_snapshot` to this attempt's snapshot path/digest.

### Repair with a fixed budget

Allow one initial validation and at most two repair/revalidation cycles. Allocate and persist a unique monotonic `repair-1` or `repair-2` ID before dispatch. Before each repair, clear `authorized_source_snapshot` and persist that invalidation. Run a fresh `brain-grok` task with that ID, the exact findings, approved artifacts, current diff, source ownership, allowlist, and prior attempts. Require it to verify every finding, fix all valid code findings, preserve unrelated edits, avoid weakening tests, edit only owned source paths, and never commit. Persist its changed paths, outcome, and resulting source status before allocating the next unique validation attempt ID; only the next full validation/refutation can reauthorize source.

Run the full validator and refuter sequence after each repair. Route new authority or product decisions to the root. After the third failed verdict, ask with `AskQuestion`:

- `/shipwright leave-changes` (recommended) — keep the working tree for manual follow-up.
- `/shipwright commit-anyway` — explicitly authorize a local commit despite recorded failures.

Before asking, create and persist the exact failed source snapshot as `failed_source_snapshot`, clear `authorized_source_snapshot`, set `current_gate: "failed-validation"`, and save the exact allowed dirty source status. Stop after asking and route the answer through the resume dispatcher. Do not commit without the second choice. On `/shipwright commit-anyway`, require the live snapshot to match `failed_source_snapshot` exactly, then set `authorized_source_snapshot` to that same path/digest with `authorization: "commit-anyway"`; any mismatch blocks.

## Commit once

Enter only after an upheld pass whose final validator consumed and passed the Visual Validation Contract, or explicit `/shipwright commit-anyway` recorded against `failed-validation`. Require a non-null `authorized_source_snapshot` carrying the corresponding upheld-validation or commit-anyway authorization. Recompute the live canonical source snapshot and require an exact digest match before any staging. Recheck branch, baseline, current `HEAD`, state hash, attempt IDs, and all immutable artifact and mutable-manifest hashes. Build the explicit allowlist from phase-owned changed source paths. Exclude task artifacts, visual captures, secrets, credentials, generated local state, baselines, setup changes, and unrelated paths.

Run `brain-luna` with resolved `ci-commit/SKILL.md`, the exact allowlist, validation/refutation/visual status, implementation summary, and the authorized snapshot path/digest/authorization. Require Luna to independently rebuild and match that exact snapshot before staging. Override broad staging: stage only explicit literal allowlisted paths. Never stage all paths. After staging, require every staged blob byte, mode, deletion, rename/copy relation, and newly added path to equal the authorized snapshot's prospective index state, with no extra path; block rather than restage on a mismatch. This is the pipeline's sole local commit stage. Record every resulting commit hash, verify the committed path/mode/content set derives exactly from the authorized snapshot and allowlist, update `expected_head`, and set the expected source status to clean.

On resume, reuse commits only when baseline-to-`HEAD` history exactly covers the allowlisted diff and includes no excluded path. Block on partial, extra, amended, or divergent history.

## Produce PR artifacts and hand publication to Cursor

Require the source tree to be clean except ignored task artifacts, on the same named non-default branch, with no divergent or unexpected commit.

Run `brain-sol` with resolved `describe-pr/SKILL.md`, all artifact paths, validation/refutation evidence, commit hashes, manual checks, and exact base/head branches. Override any source mutation or commit behavior. Require `pr-description.md` and an optional walkthrough artifact inside `<task-dir>`, validated by the artifact rules.

Persist the description/walkthrough paths and hashes and set `current_gate: "publication-ready"`. Do not push, create, update, or mark a pull request ready. Cursor Cloud must push the branch and create or update the pull request through its configured repository integration. Report the requested base/head, commit hashes, description path, walkthrough path, state path/hash, and that publication is ready for Cursor. Treat the final PR URL as unavailable until Cursor returns it. Set `current_gate: "complete"` only after Cursor provides publication evidence.

## Report

Report:

- state path/hash plus ticket, research-question, research, PRD, mockup, TDD, diagram, outline, visual baseline/final, PR-description, and walkthrough paths;
- final PRD and TDD decision ledgers, including assumed items and gate resolutions;
- phases, exact automated commands and exit codes, outstanding manual checks, and open questions;
- simplification scope, applied/skipped candidates, changed paths, and verification;
- every validation attempt, refutation outcome, repair summary, and any commit-anyway choice;
- commit hashes and Cursor publication readiness;
- blockers or publication risks.

Never claim a manual check ran, a phase requiring it is fully complete, a commit exists, or a pull request is ready without direct evidence.
