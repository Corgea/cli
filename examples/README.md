# Examples

## `upload_checkmarx.py` — upload a Checkmarx report

Creates a Corgea scan from a Checkmarx report. Same API flow as
`corgea upload`, without waiting for the scan to finish.

```bash
export CORGEA_TOKEN=<your token>
./upload_checkmarx.py <code_path> <report_path>
```

| Arg | Meaning |
|-----|---------|
| `code_path` | Root of the tree Checkmarx scanned (report paths are relative to this) |
| `report_path` | Checkmarx report: `CxXMLResults` XML, CLI JSON, or web JSON |

Optional env vars: `CORGEA_URL` (default `https://www.corgea.app`), `PROJECT`
(default: basename of `code_path`).

### Try it

```bash
export CORGEA_TOKEN=<your token>
./upload_checkmarx.py ./checkmarx ./checkmarx/report.xml
```

```
Uploading 2 source file(s) from .../examples/checkmarx...
  src/db.py
  src/login.py
Uploading report as project 'checkmarx'...
Scan scan-abc-123 created.
https://www.corgea.app/project/42/?scan_id=scan-abc-123
```

Stdlib only — no `pip install`.

## `deps_skill.rs`

```bash
cargo run --example deps_skill -- [print|check|update]
```
