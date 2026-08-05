# Examples

## `upload_checkmarx_report.py` — upload a Checkmarx report over the HTTP API

A standalone, dependency-free Python script that does what `corgea upload
<checkmarx-report>` does, for pipelines that cannot run the CLI binary. If you
*can* run the CLI, prefer it:

```bash
corgea upload report.xml --project-name my-service --wait
```

### Try it

`examples/checkmarx/` is a self-contained fixture: a `CxXMLResults` report plus
the two vulnerable Python files it points at.

```bash
export CORGEA_TOKEN=<your token>          # or run `corgea login <token>` first
cd examples/checkmarx
python3 ../upload_checkmarx_report.py report.xml --project-name checkmarx-demo --wait
```

```
Uploading 2 source file(s) referenced by the report...
  uploaded src/db.py
  uploaded src/login.py
Uploading the report as project 'checkmarx-demo' (engine=checkmarx)...

Scan scan-abc-123 created.
https://www.corgea.app/project/42/?scan_id=scan-abc-123
```

Run it from the root of the tree Checkmarx scanned, or point `--source-root` at
that tree: the report's paths are resolved relative to it.

### Options

| Flag | Meaning |
|------|---------|
| `--project-name` | Corgea project. Defaults to the git remote's repo name, else the source root's directory name. |
| `--source-root` | Directory the report's file paths are relative to. Defaults to the current directory. |
| `--wait` | Poll until the scan completes, then print a severity summary. |
| `--allow-missing-files` | Warn instead of failing when a referenced source file is absent. |
| `--url` / `--token` | Override `$CORGEA_URL` / `$CORGEA_TOKEN` and `~/.corgea/config.toml`. |

Accepted reports: `CxXMLResults` XML, Checkmarx CLI JSON
(`totalCount`/`results`/`scanID`), and Checkmarx web JSON
(`scanResults`/`reportId`). All three upload under `engine=checkmarx`.

### The API calls

Corgea analyzes findings against the source they point at, so the referenced
files are uploaded first. A client-generated `run_id` is what ties those uploads
to the report that follows.

```
GET  /api/v1/verify
POST /api/v1/code-upload?run_id=<uuid>&path=<repo-relative path>   # once per file, multipart "file"
POST /api/v1/scan-upload?engine=checkmarx&run_id=<uuid>&project=<name>&ci=<bool>&ci_platform=<name>
POST /api/v1/git-config-upload?run_id=<uuid>                       # if .git/config exists
GET  /api/v1/scan/<scan_id>                                        # --wait, until status == "complete"
GET  /api/v1/scan/<scan_id>/issues?page=<n>&page_size=30           # --wait
```

Every request carries `CORGEA-SOURCE` plus either `CORGEA-TOKEN: <token>` or, for
a JWT, `Authorization: Bearer <token>`. `scan-upload` sends the report as the
raw body under `Content-Type: application/json` even when it is XML — `engine`
is what selects the parser server side. Reports over 50 MB are split into 1 MB
chunks carrying `Upload-Offset` and `Upload-Length`.

`tests/cloud_commands_e2e/checkmarx_example.rs` runs this script and `corgea
upload` against the same stub server and asserts both produce the same request
sequence, so the example cannot drift from the CLI.

## `deps_skill.rs`

Prints or refreshes the generated section of `skills/corgea/SKILL.md`.

```bash
cargo run --example deps_skill -- [print|check|update]
```
