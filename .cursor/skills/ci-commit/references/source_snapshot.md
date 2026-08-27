# Canonical Source Snapshot

RPI, Shipwright, and `ci-commit` use this single schema. A workflow may add authorization metadata beside the snapshot, but it must not alter these bytes or reinterpret a field.

## Capture boundary

Capture from the canonical repository root with NUL-delimited Git output and byte-safe filesystem APIs. The index must equal `HEAD`; record its state anyway so staged content cannot be hidden. Ignore only Git-ignored paths and `.humanlayer/**`. Reject submodules, conflicted index stages, sockets, devices, FIFOs, and other unsupported special files.

Collect:

- raw current branch bytes, baseline `HEAD`, and current `HEAD`;
- `git status --porcelain=v2 -z --untracked-files=all`;
- `git ls-files --stage -z`;
- cached and worktree raw diff records with `-z -M -C --find-copies-harder`;
- all staged, unstaged, deleted, type-changed, renamed, copied, and untracked paths.

For each path, store:

- raw repository-relative path bytes;
- its full status fields and rename/copy relation and score, including both endpoints;
- `HEAD` mode, object ID, and SHA-256 of blob bytes, or an absent marker;
- index mode, stage, object ID, and SHA-256 of blob bytes, or an absent marker;
- worktree `lstat` type and full mode plus SHA-256 of regular-file bytes or symlink-target bytes, or an absent marker;
- prospective index mode and object ID for that exact worktree state after applying repository attributes, or an absent marker for deletion;
- an explicit untracked flag.

Never follow a symlink. Read and hash its target bytes. Do not substitute timestamps, sizes, patch text, or status text for content hashes.

## Byte encoding and JSON

Use standard padded RFC 4648 base64 for every raw byte string: branch, Git streams, paths, and rename/copy endpoints. All other strings are fixed ASCII enums or hexadecimal digests. The document contains only integers, booleans, nulls, arrays, and objects; it contains no floats.

Use this top-level shape and no extra top-level fields:

```json
{
  "schema_version": 1,
  "baseline_head": "hex-object-id",
  "head": "hex-object-id",
  "branch_b64": "base64",
  "git_streams": {
    "status_porcelain_v2_z_b64": "base64",
    "index_stage_z_b64": "base64",
    "cached_raw_z_b64": "base64",
    "worktree_raw_z_b64": "base64"
  },
  "entries": []
}
```

Every `entries` element uses exactly this shape and no extra fields:

```json
{
  "path_b64": "base64",
  "status_records_b64": [],
  "change_kinds": [],
  "relations": [],
  "head": {
    "present": false,
    "mode": null,
    "object_id": null,
    "sha256": null
  },
  "index": {
    "present": false,
    "mode": null,
    "stage": null,
    "object_id": null,
    "sha256": null
  },
  "worktree": {
    "present": false,
    "kind": null,
    "lstat_mode": null,
    "sha256": null
  },
  "prospective_index": {
    "present": false,
    "mode": null,
    "object_id": null
  },
  "untracked": false
}
```

Apply these exact entry rules:

- `path_b64` decodes to one nonempty raw repository-relative path with no NUL, absolute prefix, `.`/`..` component, or trailing slash. Decoded paths are unique.
- `status_records_b64` contains each complete logical NUL-delimited porcelain/raw record involving this path, including every path field. Sort decoded record bytes lexicographically and remove exact duplicates.
- `change_kinds` is a duplicate-free lexicographically sorted subset of the fixed strings `added`, `copied`, `deleted`, `modified`, `renamed`, `type-changed`, and `untracked`.
- Each `relations` element has exactly the four keys shown by `{"kind":"rename","role":"source","peer_path_b64":"base64","score":100}`. `kind` is exactly `copy` or `rename`; `role` is exactly `destination` or `source`; `score` is an integer from 0 through 100. Add the reciprocal relation to the peer entry. Sort relations by `kind`, then `role`, then decoded peer-path bytes, then score; remove exact duplicates.
- A present `head` state has `present: true`, a six-character lowercase-octal Git file mode (`100644`, `100755`, or `120000`), a lowercase hexadecimal `object_id` in the repository's object format, and lowercase 64-hex SHA-256 of the referenced blob bytes. An absent state uses exactly the four values shown above.
- A present `index` state uses the same mode/object/hash rules plus integer `stage: 0`. Any other stage is blocking. An absent state uses exactly the five values shown above.
- A present `worktree` state has `present: true`, `kind: "regular"` or `kind: "symlink"`, integer `lstat_mode` containing the complete platform mode, and lowercase 64-hex SHA-256 of raw file bytes or symlink-target bytes. An absent state uses exactly the four values shown above.
- A present `prospective_index` state has `present: true`, one allowed Git file mode, and the lowercase hexadecimal object ID Git will stage from the authorized worktree state. A deletion uses exactly the three absent values shown above.
- `untracked` is `true` only when Git reports the path untracked and both `head.present` and `index.present` are false; otherwise it is `false`.

Reject an entry that violates a cross-field rule, contains an unknown enum or key, omits a required key, uses a different absent marker, or disagrees with the captured Git streams.

Sort entry objects by decoded raw `path_b64` bytes. Sort every object key lexicographically; fixed keys are ASCII. Preserve array order where it is part of the schema. Serialize UTF-8 JSON with compact separators `,` and `:`, no optional whitespace, and exactly one trailing LF byte. SHA-256 over the complete serialized bytes, including that LF, is the authorization digest.

The snapshot file is immutable, regular, non-symlinked, inside the ignored task directory, and excluded from its own capture. Rebuilding from unchanged source must produce byte-identical JSON and the same digest.

## Commit verification

Before staging, rebuild the full snapshot and require byte equality and digest equality with the authorized file. Stage each allowlisted path with Git literal-pathspec mode.

After staging, the index fields are expected to differ from the pre-stage capture. Do not create a replacement authorization. Instead:

1. Parse `git diff --cached --name-status -z -M -C --find-copies-harder` and expand rename/copy records to both raw endpoints.
2. Require that expanded raw path set to equal the literal allowlist exactly.
3. Require each staged mode and object ID to equal its entry's `prospective_index` state; a deletion has no index entry.
4. Rehash current worktree bytes, symlink targets, and modes and require them to match the authorization.
5. Require no unstaged allowlisted change and no new unowned change.

After committing, parse the commit transition with the same NUL-delimited name-status expansion and prove its modes and object IDs match the authorized prospective index state. The commit must contain no extra or missing path.
