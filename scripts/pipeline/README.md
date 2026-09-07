# Pipeline scripts

Helper scripts we hand to customers who run Corgea from a CI/CD pipeline with
the `corgea` CLI. They are plain bash so they can be reviewed and dropped into
a locked-down build agent without installing anything beyond `corgea`, `jq` and
`curl`.

## `upload_fpr_and_report.sh`

Uploads a Fortify `.fpr` to Corgea with the CLI, waits for the scan, prints
every finding with its triage and suggested fix, and — when the `BITBUCKET_*`
variables are set — posts those findings to a Bitbucket Server / Data Center
pull request as review comments.

```bash
# upload, wait, print
./upload_fpr_and_report.sh report.fpr CS_CPATS

# report a scan that already finished
SCAN_ID=6f212b83-4c4b-4bdd-81f8-b9412648e108 ./upload_fpr_and_report.sh --report-only

# same, plus review comments on the pull request
export BITBUCKET_URL=https://bitbucket.example.com
export BITBUCKET_PROJECT=CPATS
export BITBUCKET_REPO=myletters-backend
export BITBUCKET_TOKEN=***          # HTTP access token
./upload_fpr_and_report.sh report.fpr CS_CPATS

# see the comments it would post, without posting them
DRY_RUN=1 ./upload_fpr_and_report.sh report.fpr CS_CPATS
```

The Corgea part is unchanged from the script customers already run: it shells
out to `corgea upload`, `corgea wait`, `corgea ls` and `corgea inspect`. All the
Bitbucket work happens in the script, not in the CLI.

### What gets posted

One comment per finding, anchored to the line in the diff. Bitbucket Server
renders markdown but has no `<details>` element, so each comment is written the
way Bitbucket collapses it — the whole point on the first line, the explanation
and the fix after it, behind "Show more":

- **Valid finding**: `🔴 SQL Injection (Critical · 🔒 Security) — <one-line summary> [View in Corgea ↗]`,
  then the issue explanation, the fix explanation, and the fix itself.
- **False positive**: `✅ False positive — Fortify flagged X here, but Corgea's triage found it is not exploitable: <reason>`,
  then the full reasoning and what the scanner reported. Set
  `POST_FALSE_POSITIVES=0` to leave these out.
- **Summary**: one pull request comment with the severity breakdown and a link
  to the scan. Set `POST_SUMMARY=0` to skip it.

A Corgea fix is posted as an applicable ` ```suggestion ` block — the reviewer
applies it from the pull request — but only when the patch is a single
contiguous change and every line it replaces is still in the diff with the code
the patch was computed against. Otherwise the fix is shown as a ` ```diff `
block to apply by hand, which is also what happens with `POST_SUGGESTIONS=0`.
Multi-line suggestions need Bitbucket Data Center 9.3 or newer.

Findings in files the pull request does not touch are counted in the summary
comment and otherwise skipped; `POST_OUTSIDE_DIFF=1` posts them as plain pull
request comments instead.

Re-running on the same pull request does not duplicate anything: every comment
ends with a `corgea-issue: <id>` (or `corgea-scan: <id>`) marker that the script
looks for before posting.

### Configuration

| Variable | Meaning |
| --- | --- |
| `BITBUCKET_URL` | Base URL of the Bitbucket server. Required to post. |
| `BITBUCKET_PROJECT` | Project key (`~username` for a personal repo). Required. |
| `BITBUCKET_REPO` | Repository slug. Required. |
| `BITBUCKET_TOKEN` | HTTP access token, sent as `Authorization: Bearer`. |
| `BITBUCKET_USER` / `BITBUCKET_PASSWORD` | Basic auth, instead of a token. |
| `BITBUCKET_PR` | Pull request id. Auto-detected from the branch when unset. |
| `BITBUCKET_BRANCH` | Branch used for that auto-detection. Defaults to `HEAD`. |
| `BITBUCKET_API_PATH` | REST prefix. Default `/rest/api/1.0`. |
| `BITBUCKET_CA_BUNDLE` | CA bundle for an internal certificate authority. |
| `BITBUCKET_INSECURE` | `1` skips TLS verification. Last resort. |
| `STRIP_PATH_PREFIX` | Build-machine prefix to strip from scanner paths. |
| `SCANNER_LABEL` | Scanner named in the comments. Default `Fortify`. |
| `POST_FALSE_POSITIVES` | `0` to skip auto-triaged false positives. |
| `POST_SUGGESTIONS` | `0` to always show a diff instead of a suggestion. |
| `POST_SUMMARY` | `0` to skip the summary comment. |
| `POST_OUTSIDE_DIFF` | `1` to comment on findings outside the diff too. |
| `DIFF_CONTEXT_LINES` | Diff context requested from Bitbucket. Default 10. |
| `DRY_RUN` | `1` prints the comments instead of posting them. |
| `CORGEA_URL` | Corgea base URL for links. Falls back to `~/.corgea/config.toml`. |

Credentials are written to a `0600` curl config file, so they never appear in
the process list of the build agent.

### Permissions

Corgea: *Can Add SAST Scan*, *Can View SAST Scan*, *Can View Issue*.

Bitbucket: repository read (to read the diff) plus the right to comment on the
pull request — the account behind `BITBUCKET_TOKEN` is the author of the
comments.

### Troubleshooting

- **`404` right after the upload.** The scan takes a moment to register, which
  is why the script sleeps before `corgea wait`.
- **No comments, "no open pull request found".** The branch has no open pull
  request, or the build is a branch build rather than a pull request build.
  Pass `--pr <id>`.
- **No comments, "could not reach ...".** The build agent cannot reach
  Bitbucket, or the internal certificate authority is not trusted. Set
  `BITBUCKET_CA_BUNDLE`.
- **Findings show up as "outside the PR diff".** Fortify recorded
  build-machine paths that the script could not map onto the repository. Set
  `STRIP_PATH_PREFIX` to the build workspace prefix.
- **A fix appears as a diff rather than an applicable suggestion.** The patch
  touches more than one place in the file, or the file changed after the scan.
  Both are cases where applying it blindly would corrupt the file.
