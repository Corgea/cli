---
name: thermo-nuclear-code-quality-review
description: Run an extremely strict, read-only maintainability review for abstraction quality, giant files, and spaghetti-condition growth. Use only for an explicitly requested thermo-nuclear, thermonuclear, or especially harsh code-quality audit.
disable-model-invocation: true
---

# Thermo-Nuclear Code Quality Review

Perform an unusually strict, read-only audit of the current branch. Focus on implementation quality, maintainability, abstraction quality, and codebase health. Search for "code judo": behavior-preserving restructurings that make the implementation dramatically smaller, more direct, and more inevitable in hindsight.

## Read-only contract

Use only Cursor's **Shell** and **Read** tools. Never edit files, alter the index, create artifacts, invoke another agent, commit, push, create a pull request, publish comments, or run a formatter, generator, test, or other command that can write to the checkout. Return findings in the response only.

Treat the entire current branch state as the review target:

1. Resolve the repository root, current branch, `HEAD`, and default branch from local Git metadata. Prefer the remote symbolic default branch, then a locally resolvable `main`, then `master`. Stop with one precise blocker when no default branch can be resolved.
2. Find the merge base between `HEAD` and the resolved default branch. Inspect the complete committed `merge-base...HEAD` diff, including rename and copy detection.
3. Separately inspect the complete staged diff, unstaged diff, and every untracked file reported by `git status --porcelain=v2 -z --untracked-files=all`. Do not omit a path because it also appears in another diff.
4. Read every changed file and enough unchanged surrounding code to understand its ownership boundary, callers, contracts, existing helpers, and local conventions. Search for canonical utilities and representative patterns before claiming duplication or architectural drift.
5. Compare current and merge-base line counts for every materially enlarged file. Always identify a file that crosses from below 1,000 lines to 1,000 lines or more.

Use NUL-delimited Git output when enumerating paths. Treat filenames as literal paths, not pathspecs. If output truncates, inspect the diff in bounded per-file segments until every changed path is covered. Do not use network state as a substitute for the local checkout.

## Review baseline

Rethink how the changes could be structured or implemented to improve code quality without changing behavior. Improve abstractions and modularity, reduce spaghetti code, and increase succinctness and legibility. Be ambitious where a clear restructuring would materially simplify the codebase. Measure twice, cut once.

## Non-negotiable standards

### 1. Push for structural simplification

- Do not stop at local cleanup when a reframing could remove whole branches, helpers, modes, conditionals, or layers.
- Prefer deleting complexity to rearranging it.
- Favor the design that uses the existing architecture naturally and leaves fewer concepts in a reader's head.
- A refactor that only moves complexity is not a code-judo improvement.

### 2. Treat the 1,000-line threshold as a strong smell

- Do not let a change push a file from below 1,000 lines to 1,000 lines or more without a compelling structural reason.
- Prefer focused modules, helpers, or components over continued file growth.
- Explicitly ask for decomposition when the threshold is crossed.
- Waive the concern only when the large file remains clearly organized and splitting it would make ownership or comprehension worse.

### 3. Reject spaghetti growth

- Treat new ad-hoc conditionals, scattered special cases, nullable modes, one-off flags, and branches inserted into unrelated flows as design problems rather than style nits.
- Prefer a dedicated abstraction, pure helper, typed model, explicit dispatcher, state machine, policy object, or separate module when it removes tangled control flow.
- Call out technically correct changes that make surrounding code harder to reason about.

### 4. Prefer direct, boring code

- Flag brittle, magical, generic mechanisms that obscure a simple data shape or invariant.
- Challenge thin abstractions, identity wrappers, and pass-through helpers that add indirection without clarity.
- Prefer simplifications that remove moving pieces over abstractions that merely redistribute them.

### 5. Keep types and boundaries clean

- Question unnecessary optionality, `unknown`, `any`, casts, silent fallbacks, and loosely shaped objects when a clearer contract is available.
- Prefer explicit typed models and shared contracts when they simplify the control flow.
- Call out feature logic leaking into shared paths or implementation details leaking through APIs.
- Move behavior to the package, service, or module that canonically owns the concept, and reuse existing canonical helpers instead of bespoke near-duplicates.

### 6. Challenge brittle orchestration and state updates

- Treat needless sequential orchestration as a design smell when independent work can remain clearer in parallel.
- Push related updates toward an atomic structure when partial application would leave confusing state.
- Do not turn this into a micro-optimization exercise; flag these issues only when the cleaner design is concrete.

## Questions for every meaningful change

- Is there a code-judo move that would make this dramatically simpler?
- Can fewer concepts, branches, flags, or helper layers express the same behavior?
- Does the change improve or weaken the local architecture?
- Did branching complexity grow where a better model should exist?
- Did a cohesive module become more coupled, stateful, or difficult to scan?
- Is the logic in the right file and ownership layer?
- Did a file or component cross a healthy size boundary?
- Do repeated conditionals reveal a missing model or helper?
- Is each abstraction earning its indirection?
- Do casts, optionality, fallbacks, or ad-hoc shapes hide the real invariant?
- Did the change duplicate a canonical helper or leak details across a boundary?
- Is orchestration more sequential or state mutation less atomic than necessary?

## Flag aggressively

Raise a finding when evidence shows:

- a complicated implementation where a credible reframing deletes whole categories of complexity;
- a refactor that moves code without reducing conceptual load;
- a file crossing the 1,000-line threshold, especially when the new code has a clear separate owner;
- conditionals or narrow edge-case handling bolted into an already busy or unrelated path;
- feature-specific behavior scattered through general-purpose modules;
- magic handling that hides straightforward structure;
- wrappers, casts, loose types, or optional parameters that obscure rather than clarify the contract;
- copied logic or a bespoke helper where a canonical utility already exists;
- logic placed in the wrong package or layer;
- independent work serialized into brittle orchestration; or
- related updates that can leave state partially applied.

Do not invent an architectural alternative merely to demand change. A structural finding needs a concrete, behavior-preserving direction grounded in repository evidence.

## Preferred remedies

Prefer recommendations that delete an indirection layer, simplify the state model until branches disappear, correct an ownership boundary, turn special cases into the default flow, extract a focused pure function or module, replace condition chains with a typed model or dispatcher, separate orchestration from business logic, collapse duplicate branches, reuse an existing canonical helper, make a type boundary explicit, parallelize genuinely independent work, or make related updates atomic.

Do not settle for a rename or cosmetic cleanup when the evidence points to a structural problem. Do not recommend a larger abstraction when direct code is clearer.

## Findings format

Report only high-conviction, actionable findings. Order them by impact, then by:

1. structural regressions;
2. missed code-judo simplifications;
3. spaghetti and branching growth;
4. boundary, abstraction, and type-contract problems;
5. file-size and decomposition concerns;
6. modularity issues; and
7. legibility and maintainability concerns.

For each finding include:

- a short imperative title and severity;
- a tight repository-relative `path:line` or line-range citation to changed code;
- concrete evidence from the diff and relevant surrounding code;
- why the structure materially harms maintainability; and
- a specific behavior-preserving direction that removes or isolates the complexity.

Keep citations narrow. Do not flood the response with cosmetic nits. When there are no qualifying findings, say `No high-conviction maintainability findings.` Then name any material evidence gap or residual risk, such as an unreadable generated file, without turning it into a finding.

## Approval bar

Correct behavior alone is insufficient. The change passes this review only when it has:

- no clear structural regression;
- no obvious, evidence-backed opportunity for dramatic simplification left on the table;
- no unjustified file-size explosion;
- no spaghetti growth from special-case branching;
- no hacky or magical abstraction that weakens comprehension;
- no unnecessary wrapper, cast, or optionality churn obscuring the design;
- no clear architecture-boundary leak or canonical-helper duplication; and
- no missed decomposition that would materially improve maintainability.

Treat a plausible code-judo simplification, a new crossing of the 1,000-line threshold, scattered feature checks, unnecessary indirection, cast-heavy contracts, helper duplication, or a clear wrong-layer placement as a presumptive blocker. State the issue directly and ask for a cleaner decomposition.
