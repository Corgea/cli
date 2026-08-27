---
name: ci-commit
description: "Explicit-only: create the workflow's local git commit from an exact path allowlist after rejecting task artifacts, secrets, and unrelated changes."
disable-model-invocation: true
---

# Commit Changes

Create the workflow's local commit. This skill is the only commit point; it does not implement, repair, publish, or create a pull request.

Read [references/source_snapshot.md](references/source_snapshot.md) completely. It is the single canonical source-snapshot schema for RPI, Shipwright, and this commit stage. Block on any caller instruction or authorization that conflicts with it.

## Required input

Require:

- the absolute repository root;
- an explicit list of repository-relative files owned by the completed implementation;
- the verification verdict authorizing a commit;
- the absolute path to an immutable canonical authorized source-snapshot file and its SHA-256 digest, produced by the invoking workflow after its last verification or explicitly authorized failed verdict;
- an optional commit subject.

Do not infer ownership from the current diff. Require the snapshot to be a regular non-symlink file outside the source allowlist, hash its exact bytes, and match the supplied digest before parsing it. An empty allowlist, missing or malformed snapshot, digest mismatch, or verdict other than the invoking workflow's accepted state is blocking. Do not contact the user; return the blocker to the orchestrator.

The snapshot must use the workflow's fixed canonical-JSON schema and cover every staged, unstaged, deleted, renamed, copied, type-changed, and untracked source path. Raw paths, complete porcelain-v2 records, and rename/copy endpoints are base64-encoded before JSON serialization and entries are sorted by decoded raw path bytes. Each entry also contains `HEAD` and index modes/object IDs; filesystem kind and full `lstat` mode; SHA-256 of current regular-file or symlink-target bytes; prospective Git index mode/object ID after repository attributes; and an explicit deletion marker where applicable. Reject an authorization that omits either a dirty path or an allowlisted change.

## Preflight

Use **Shell** to record:

- current branch, `HEAD`, and repository root;
- `git status --short --untracked-files=all`;
- staged paths and all changed paths;
- the complete diff for every allowlisted path.

Before touching the index, independently reconstruct the complete canonical source snapshot using `git status --porcelain=v2 -z --untracked-files=all`, `git ls-files --stage -z`, and raw filesystem hashing without following symlinks. Serialize with the shared schema's sorted object keys, entries ordered by decoded raw path bytes, compact JSON separators, UTF-8 encoding, and exactly one trailing LF byte. No other whitespace is allowed. Require exact canonical JSON equality and SHA-256 digest equality with the supplied authorization. Do not accept status-only, path-only, patch-only, timestamp, or size comparisons.

Normalize every allowlisted entry to a repository-relative file path. Treat every entry as a literal path, never as a Git pathspec; pathspec metacharacters are permitted only when the repository contains that exact changed name. Reject paths outside the repository, directories, NUL bytes, deleted paths not explicitly named, and duplicate aliases for the same path. Use NUL-delimited Git output for all path comparisons so whitespace and newlines remain unambiguous.

Block before changing the index when any of these holds:

- a changed or staged path is outside the allowlist;
- any tracked, changed, staged, or allowlisted path is under `.humanlayer/`;
- a path is an environment file, credential store, private key, certificate bundle, token file, browser profile, or other secret-bearing local state;
- the diff contains a likely credential or private-key value;
- the allowlisted diff is empty;
- the index differs from `HEAD` before this skill starts;
- repository instructions or required verification evidence prohibit the commit.

Never print a suspected secret. Report only its path and the class of match.

## Stage and commit

Draft one focused imperative commit subject from the verified change when none was provided.

Stage each allowlisted file explicitly with `git --literal-pathspecs add -- <path>`. Bulk staging (`git add -A`, `git add .`, directories, or globs) is prohibited.

Before committing, use **Shell** to verify:

- parse `git diff --cached --name-status -z -M -C --find-copies-harder`, expand every rename/copy into both raw endpoints and every other record into its one raw path, and require that expanded set to exactly equal the normalized literal allowlist;
- `git diff --cached --check` exits zero;
- the staged diff still contains no task artifacts or suspected secrets;
- no unowned work appeared after preflight.

For every authorized path, compare the staged index mode and object ID with the snapshot's prospective index mode and object ID. A deletion must have no index entry. Both old and new endpoints of a rename or copy must match the authorized transition. Require no unstaged allowlisted changes after staging. Because staging intentionally changes the index portion of the snapshot, do not replace the authorization with a newly computed digest; prove instead that all working-tree bytes/modes stayed equal to the authorization and that the resulting index is its exact prospective state. Block on a clean/smudge, line-ending, mode, symlink, rename, or path mismatch.

Create one local commit with the approved subject. Do not amend an existing commit. Do not contact remotes or create/update a pull request.

## Evidence

After the commit, collect and return:

- status: `complete` or `blocked`;
- `HEAD` before and after;
- commit SHA and subject from `git log -1 --format=%H%n%s`;
- committed raw transitions from `git diff-tree --no-commit-id --name-status -r -z -M -C --find-copies-harder HEAD`, with rename/copy records expanded to both endpoints;
- committed tree modes/object IDs matched to the authorized prospective index entries;
- the authorized source-snapshot SHA-256 digest;
- final `git status --short --untracked-files=all`;
- every verification command with its numeric exit code;
- the exact blocker, or `none`.

The committed path list must exactly match the allowlisted changed files. Never claim success without the commit SHA and path evidence.
