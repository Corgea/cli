#!/usr/bin/env bash
# upload_fpr_and_report.sh
#
# Upload a Fortify .fpr to Corgea, wait until the scan finishes, print each
# finding (false-positive vs valid triage, reasoning, suggested fix), and
# optionally post those findings to a Bitbucket Server / Data Center pull
# request as review comments.
#
# Prerequisites:
#   1. Install corgea CLI, jq and curl
#   2. Log in once:
#        corgea login --url https://corgea.example.com YOUR_TOKEN
#
# Mode 1 — upload + wait + report (usual case):
#   ./upload_fpr_and_report.sh <path-to.fpr> [project-name]
#
#   <path-to.fpr>   Required. Path to the Fortify FPR file on disk.
#   [project-name]  Optional. Name of the project in Corgea where this scan
#                   should appear (e.g. CS_CPATS → https://corgea.example.com/project/CS_CPATS).
#                   It is NOT a filesystem path.
#                   If omitted, corgea picks one for you: git repo name if you're
#                   in a git checkout, otherwise the current directory's name.
#
#   Examples:
#     # Upload into whatever project name corgea infers from CWD/git:
#     ./upload_fpr_and_report.sh ~/Downloads/report.fpr
#
#     # Upload into an explicit Corgea project named CS_CPATS:
#     ./upload_fpr_and_report.sh ~/Downloads/report.fpr CS_CPATS
#
# Mode 2 — report an already-finished scan (no upload):
#   SCAN_ID=<scan-uuid> ./upload_fpr_and_report.sh --report-only
#
#   Example:
#     SCAN_ID=6f212b83-4c4b-4bdd-81f8-b9412648e108 \
#       ./upload_fpr_and_report.sh --report-only
#
# ------------------------------------------------------------------------------
# Posting the findings to a Bitbucket Server / Data Center pull request
# ------------------------------------------------------------------------------
# Set the BITBUCKET_* variables below and the script adds one more step after
# the console report: every finding that lands in a file the pull request
# touches is posted as a review comment, and findings Corgea auto-triaged as
# false positives are posted as such ("Fortify flagged X here, but ... because").
# Valid findings that come with a Corgea fix are posted as an applicable
# ```suggestion block, so the reviewer can apply the fix from the PR.
#
# Nothing is posted unless BITBUCKET_URL, BITBUCKET_PROJECT, BITBUCKET_REPO and
# a credential are all set, so the two existing modes above keep working as-is.
#
# Required:
#   BITBUCKET_URL        Base URL of the Bitbucket server, e.g. https://bitbucket.example.com
#   BITBUCKET_PROJECT    Project key, e.g. CPATS (use ~username for a personal repo)
#   BITBUCKET_REPO       Repository slug, e.g. myletters-backend
#   BITBUCKET_TOKEN      HTTP access token (sent as `Authorization: Bearer`)
#                        — or BITBUCKET_USER + BITBUCKET_PASSWORD for basic auth
#
# Optional:
#   BITBUCKET_PR         Pull request id. Auto-detected from the current branch
#                        (or BITBUCKET_BRANCH) when omitted.
#   BITBUCKET_BRANCH     Source branch used to auto-detect the pull request.
#                        Defaults to the checked-out branch.
#   BITBUCKET_API_PATH   REST prefix. Default /rest/api/1.0 (Bitbucket DC v1004).
#   BITBUCKET_CA_BUNDLE  CA bundle for an internal certificate authority.
#   BITBUCKET_INSECURE   1 to skip TLS verification (last resort, not advised).
#   STRIP_PATH_PREFIX    Prefix to strip from Fortify paths so they become
#                        repo-relative, e.g. /builds/agent/workspace/
#   SCANNER_LABEL        Scanner named in the comments. Default: Fortify
#   POST_FALSE_POSITIVES 1 (default) to comment on auto-triaged false positives.
#   POST_SUGGESTIONS     1 (default) to include applicable ```suggestion blocks.
#   POST_SUMMARY         1 (default) to post one summary comment on the PR.
#   POST_OUTSIDE_DIFF    1 to also post findings whose file the PR does not touch
#                        as plain pull request comments. Default 0 (they are only
#                        counted in the summary comment).
#   DIFF_CONTEXT_LINES   Context lines requested from Bitbucket when deciding
#                        whether a finding's line is part of the diff. Default 10.
#   CORGEA_URL           Corgea base URL used for the "View in Corgea" links.
#                        Falls back to ~/.corgea/config.toml, then corgea.app.
#
# Re-running the script on the same pull request does not duplicate comments:
# every comment carries a `corgea-issue: <id>` marker that is checked first.
#
#   Example (Bitbucket Pipelines-style CI step):
#     export BITBUCKET_URL=https://bitbucket.example.com
#     export BITBUCKET_PROJECT=CPATS
#     export BITBUCKET_REPO=myletters-backend
#     export BITBUCKET_TOKEN=***
#     ./upload_fpr_and_report.sh myletters-backend.fpr CS_CPATS
#
#   Preview the comments without posting anything:
#     DRY_RUN=1 ./upload_fpr_and_report.sh myletters-backend.fpr CS_CPATS
#
# Corgea permissions needed: Can Add SAST Scan, Can View SAST Scan, Can View Issue.
# Bitbucket permissions needed: repository read (to read the diff) and the right
# to comment on the pull request.

set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage:
  ./upload_fpr_and_report.sh [options] <path-to.fpr> [project-name]
  SCAN_ID=<scan-uuid> ./upload_fpr_and_report.sh --report-only [options]

Options:
  --report-only        Report an already-finished scan (needs SCAN_ID).
  --pr <id>            Bitbucket pull request id to comment on.
  --dry-run            Print the Bitbucket comments instead of posting them.
  --no-bitbucket       Skip the Bitbucket step even if it is configured.
  -h, --help           Show this help.

Examples:
  ./upload_fpr_and_report.sh ~/Downloads/report.fpr CS_CPATS
  SCAN_ID=6f212b83-4c4b-4bdd-81f8-b9412648e108 ./upload_fpr_and_report.sh --report-only

Login first:  corgea login --url https://corgea.example.com YOUR_TOKEN
Requires:     corgea, jq (curl too, when posting to Bitbucket)

Bitbucket posting is configured with BITBUCKET_URL, BITBUCKET_PROJECT,
BITBUCKET_REPO and BITBUCKET_TOKEN (or BITBUCKET_USER/BITBUCKET_PASSWORD).
See the comments at the top of this script for the full list.
EOF
}

command -v corgea >/dev/null || { echo "corgea not found in PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

# corgea inspect --json sometimes embeds unescaped control chars; strip them for jq.
sanitize_json() {
  tr -d '\000-\010\013\014\016-\037'
}

warn() { echo "$*" >&2; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
mkdir -p "$WORKDIR/issues" "$WORKDIR/diffs"

# ------------------------------------------------------------------------------
# Bitbucket configuration (all optional: unset means "don't post")
# ------------------------------------------------------------------------------
BITBUCKET_URL="${BITBUCKET_URL:-}"
BITBUCKET_PROJECT="${BITBUCKET_PROJECT:-}"
BITBUCKET_REPO="${BITBUCKET_REPO:-}"
BITBUCKET_PR="${BITBUCKET_PR:-}"
BITBUCKET_BRANCH="${BITBUCKET_BRANCH:-}"
BITBUCKET_TOKEN="${BITBUCKET_TOKEN:-}"
BITBUCKET_USER="${BITBUCKET_USER:-}"
BITBUCKET_PASSWORD="${BITBUCKET_PASSWORD:-}"
BITBUCKET_API_PATH="${BITBUCKET_API_PATH:-/rest/api/1.0}"
BITBUCKET_CA_BUNDLE="${BITBUCKET_CA_BUNDLE:-}"
BITBUCKET_INSECURE="${BITBUCKET_INSECURE:-0}"
STRIP_PATH_PREFIX="${STRIP_PATH_PREFIX:-}"
SCANNER_LABEL="${SCANNER_LABEL:-Fortify}"
POST_FALSE_POSITIVES="${POST_FALSE_POSITIVES:-1}"
POST_SUGGESTIONS="${POST_SUGGESTIONS:-1}"
POST_SUMMARY="${POST_SUMMARY:-1}"
POST_OUTSIDE_DIFF="${POST_OUTSIDE_DIFF:-0}"
DIFF_CONTEXT_LINES="${DIFF_CONTEXT_LINES:-10}"
DRY_RUN="${DRY_RUN:-0}"
NO_BITBUCKET=0

REPORT_ONLY=0
PROJECT_NAME=""
FPR=""

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --report-only) REPORT_ONLY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-bitbucket) NO_BITBUCKET=1; shift ;;
    --pr) BITBUCKET_PR="${2:-}"; shift 2 ;;
    --pr=*) BITBUCKET_PR="${1#*=}"; shift ;;
    --) shift; while [[ $# -gt 0 ]]; do POSITIONAL+=("$1"); shift; done ;;
    -*) echo "error: unknown option: $1" >&2; usage; exit 1 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
if ((${#POSITIONAL[@]})); then set -- "${POSITIONAL[@]}"; else set --; fi

if [[ "$REPORT_ONLY" -eq 1 ]]; then
  if [[ -z "${SCAN_ID:-}" ]]; then
    echo "error: SCAN_ID env var is required with --report-only" >&2
    usage
    exit 1
  fi
else
  FPR="${1:-}"
  PROJECT_NAME="${2:-}"

  if [[ -z "$FPR" || ! -f "$FPR" ]]; then
    [[ -n "$FPR" ]] && echo "error: FPR file not found: $FPR" >&2
    usage
    exit 1
  fi

  UPLOAD_ARGS=("$FPR")
  if [[ -n "$PROJECT_NAME" ]]; then
    UPLOAD_ARGS+=(--project-name "$PROJECT_NAME")
  fi

  echo "==> Uploading $FPR ..."
  UPLOAD_LOG="$WORKDIR/upload.log"

  set +e
  corgea upload "${UPLOAD_ARGS[@]}" 2>&1 | tee "$UPLOAD_LOG"
  UPLOAD_RC=${PIPESTATUS[0]}
  set -e
  if [[ "$UPLOAD_RC" -ne 0 ]]; then
    echo "Upload failed (exit $UPLOAD_RC)" >&2
    exit "$UPLOAD_RC"
  fi

  # Support both current CLI ("Scan ID: ...") and newer ("Scan has started with ID: ..." / scan_id=).
  SCAN_ID="$(
    sed -nE \
      -e 's/.*[Ss]can has started with ID:[[:space:]]*([A-Za-z0-9_-]+).*/\1/p' \
      -e 's/.*[Ss]can ID:[[:space:]]*([A-Za-z0-9_-]+).*/\1/p' \
      "$UPLOAD_LOG" | head -1
  )"
  if [[ -z "$SCAN_ID" ]]; then
    SCAN_ID="$(grep -oE 'scan_id=[A-Za-z0-9_-]+' "$UPLOAD_LOG" | head -1 | cut -d= -f2 || true)"
  fi
  if [[ -z "$SCAN_ID" ]]; then
    echo "Could not parse scan id from upload output" >&2
    exit 1
  fi

  echo
  echo "==> Waiting for scan $SCAN_ID to register ..."
  sleep 15
  echo "==> Waiting for scan $SCAN_ID ..."
  corgea wait "$SCAN_ID"
fi

echo
echo "==> Fetching issues for scan $SCAN_ID ..."

PAGE=1
TOTAL_PAGES=1
ISSUE_IDS=()

while [[ "$PAGE" -le "$TOTAL_PAGES" ]]; do
  PAGE_JSON="$(corgea ls --issues --scan-id "$SCAN_ID" --json --page "$PAGE" --page-size 50 | sanitize_json)"
  TOTAL_PAGES="$(echo "$PAGE_JSON" | jq -r '.total_pages // 1')"

  while IFS= read -r id; do
    [[ -n "$id" ]] && ISSUE_IDS+=("$id")
  done < <(echo "$PAGE_JSON" | jq -r '(.results // .issues // [])[]?.id // empty')

  PAGE=$((PAGE + 1))
done

echo "Found ${#ISSUE_IDS[@]} issue(s)."
echo

FP_COUNT=0
VALID_COUNT=0
FIX_COUNT=0
CR_COUNT=0
HI_COUNT=0
ME_COUNT=0
LO_COUNT=0

for ISSUE_ID in "${ISSUE_IDS[@]:-}"; do
  [[ -z "$ISSUE_ID" ]] && continue
  DETAIL="$(corgea inspect --issue --json "$ISSUE_ID" | sanitize_json)"
  ISSUE="$(echo "$DETAIL" | jq -c '.issue')"
  # Kept for the Bitbucket step, which needs the same fields per finding.
  printf '%s' "$ISSUE" > "$WORKDIR/issues/$ISSUE_ID.json"

  FILE="$(echo "$ISSUE" | jq -r '.location.file.path // empty')"
  LINE="$(echo "$ISSUE" | jq -r '.location.line_number // empty')"
  CAT="$(echo "$ISSUE" | jq -r '.classification.name // .classification.id // empty')"
  URGENCY="$(echo "$ISSUE" | jq -r '.urgency // empty')"
  STATUS="$(echo "$ISSUE" | jq -r '.status // empty')"

  FP_STATUS="$(echo "$ISSUE" | jq -r '.auto_triage.false_positive_detection.status // "unknown"')"
  FP_REASON="$(echo "$ISSUE" | jq -r '.auto_triage.false_positive_detection.reasoning // empty')"

  FIX_STATUS="$(echo "$ISSUE" | jq -r '.auto_fix_suggestion.status // "none"')"
  FIX_EXPL="$(echo "$ISSUE" | jq -r '.auto_fix_suggestion.patch.explanation // empty')"
  FIX_DIFF="$(echo "$ISSUE" | jq -r '.auto_fix_suggestion.patch.diff // empty')"
  ISSUE_EXPL="$(echo "$ISSUE" | jq -r '.details.explanation // empty')"

  if [[ "$FP_STATUS" == "false_positive" ]]; then
    FP_LABEL="FALSE POSITIVE"
    FP_COUNT=$((FP_COUNT + 1))
  else
    FP_LABEL="VALID (not a false positive)"
    VALID_COUNT=$((VALID_COUNT + 1))
    case "$URGENCY" in
      CR) CR_COUNT=$((CR_COUNT + 1)) ;;
      HI) HI_COUNT=$((HI_COUNT + 1)) ;;
      ME) ME_COUNT=$((ME_COUNT + 1)) ;;
      LO) LO_COUNT=$((LO_COUNT + 1)) ;;
    esac
  fi

  echo "================================================================================"
  echo "Issue:    $ISSUE_ID"
  echo "Finding:  $CAT  |  urgency=$URGENCY  |  status=$STATUS"
  echo "Location: $FILE:$LINE"
  echo "Triage:   $FP_LABEL  (auto_triage=$FP_STATUS)"
  if [[ -n "$FP_REASON" ]]; then
    echo
    echo "FP reasoning:"
    echo "$FP_REASON"
  fi
  if [[ -n "$ISSUE_EXPL" ]]; then
    echo
    echo "Issue explanation:"
    echo "$ISSUE_EXPL"
  fi

  echo
  echo "Fix status: $FIX_STATUS"
  if [[ -n "$FIX_EXPL" || -n "$FIX_DIFF" ]]; then
    FIX_COUNT=$((FIX_COUNT + 1))
    if [[ -n "$FIX_EXPL" ]]; then
      echo
      echo "Suggested fix explanation:"
      echo "$FIX_EXPL"
    fi
    if [[ -n "$FIX_DIFF" ]]; then
      echo
      echo "Suggested fix diff:"
      echo "$FIX_DIFF"
    fi
  else
    echo "(no suggested fix patch available)"
  fi
  echo
done

# ==============================================================================
# Bitbucket Server / Data Center pull request comments
# ==============================================================================

# Corgea base URL for the "View in Corgea" links: env, then the CLI config.
corgea_base_url() {
  local url=""
  if [[ -n "${CORGEA_URL:-}" ]]; then
    url="$CORGEA_URL"
  elif [[ -f "$HOME/.corgea/config.toml" ]]; then
    url="$(sed -nE 's/^[[:space:]]*url[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$HOME/.corgea/config.toml" | head -1)"
  fi
  [[ -z "$url" ]] && url="https://www.corgea.app"
  printf '%s' "${url%/}"
}

bitbucket_configured() {
  [[ "$NO_BITBUCKET" -eq 0 ]] &&
    [[ -n "$BITBUCKET_URL" && -n "$BITBUCKET_PROJECT" && -n "$BITBUCKET_REPO" ]] &&
    [[ -n "$BITBUCKET_TOKEN" || ( -n "$BITBUCKET_USER" && -n "$BITBUCKET_PASSWORD" ) ]]
}

# Percent-encode a file path, keeping the slashes that make up the URL path.
url_encode_path() {
  jq -rn --arg p "$1" '$p | split("/") | map(@uri) | join("/")'
}

url_encode() {
  jq -rn --arg v "$1" '$v | @uri'
}

# Credentials live in a 0600 curl config file so they never appear in `ps`.
setup_bitbucket_auth() {
  CURL_CFG="$WORKDIR/curl.cfg"
  : > "$CURL_CFG"
  chmod 600 "$CURL_CFG"
  {
    echo 'silent'
    echo 'show-error'
    if [[ -n "$BITBUCKET_TOKEN" ]]; then
      printf 'header = "Authorization: Bearer %s"\n' "$BITBUCKET_TOKEN"
    else
      printf 'user = "%s:%s"\n' "$BITBUCKET_USER" "$BITBUCKET_PASSWORD"
    fi
    if [[ -n "$BITBUCKET_CA_BUNDLE" ]]; then
      printf 'cacert = "%s"\n' "$BITBUCKET_CA_BUNDLE"
    fi
    if [[ "$BITBUCKET_INSECURE" == "1" ]]; then
      echo 'insecure'
    fi
  } >> "$CURL_CFG"
  return 0
}

BB_STATUS=""
BB_BODY="$WORKDIR/bb_body.json"

# bb_request METHOD PATH_AND_QUERY [BODY_FILE] — response body lands in $BB_BODY.
bb_request() {
  local method="$1" path="$2" body_file="${3:-}"
  local -a args=(--config "$CURL_CFG" -o "$BB_BODY" -w '%{http_code}'
                 -X "$method" -H 'Accept: application/json')
  if [[ -n "$body_file" ]]; then
    args+=(-H 'Content-Type: application/json' --data-binary "@$body_file")
  fi
  BB_STATUS="$(curl "${args[@]}" "${BITBUCKET_URL%/}${BITBUCKET_API_PATH}${path}")" || return 1
  [[ "$BB_STATUS" =~ ^2[0-9][0-9]$ ]]
}

bb_error() {
  local detail
  if [[ "$BB_STATUS" == "000" || -z "$BB_STATUS" ]]; then
    printf 'could not reach %s — check BITBUCKET_URL, the proxy, and TLS trust (BITBUCKET_CA_BUNDLE)' \
      "${BITBUCKET_URL%/}"
    return 0
  fi
  detail="$(jq -r '[.errors[]?.message] | join("; ") // empty' "$BB_BODY" 2>/dev/null || true)"
  [[ -z "$detail" ]] && detail="$(head -c 300 "$BB_BODY" 2>/dev/null || true)"
  printf 'HTTP %s %s' "$BB_STATUS" "$detail"
}

BB_PR_PATH=""   # /projects/X/repos/Y/pull-requests/N

# Resolve the pull request: BITBUCKET_PR, else the open PR from this branch.
resolve_pull_request() {
  local project repo
  project="$(url_encode "$BITBUCKET_PROJECT")"
  repo="$(url_encode "$BITBUCKET_REPO")"

  if [[ -z "$BITBUCKET_PR" ]]; then
    local branch="$BITBUCKET_BRANCH"
    if [[ -z "$branch" ]]; then
      branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    fi
    if [[ -z "$branch" || "$branch" == "HEAD" ]]; then
      warn "Bitbucket: no pull request id given and the current branch could not be determined."
      warn "           Pass --pr <id> or set BITBUCKET_PR / BITBUCKET_BRANCH."
      return 1
    fi
    if ! bb_request GET "/projects/$project/repos/$repo/pull-requests?state=OPEN&direction=OUTGOING&limit=25&at=refs/heads/$(url_encode "$branch")"; then
      warn "Bitbucket: could not list pull requests for branch '$branch' ($(bb_error))."
      return 1
    fi
    BITBUCKET_PR="$(jq -r '.values[0].id // empty' "$BB_BODY")"
    local found
    found="$(jq -r '.values | length' "$BB_BODY")"
    if [[ -z "$BITBUCKET_PR" ]]; then
      warn "Bitbucket: no open pull request found for branch '$branch'; skipping comments."
      return 1
    fi
    if [[ "$found" -gt 1 ]]; then
      warn "Bitbucket: branch '$branch' has $found open pull requests; commenting on #$BITBUCKET_PR."
    fi
  fi

  BB_PR_PATH="/projects/$project/repos/$repo/pull-requests/$BITBUCKET_PR"
  if ! bb_request GET "$BB_PR_PATH"; then
    warn "Bitbucket: cannot read pull request #$BITBUCKET_PR ($(bb_error))."
    return 1
  fi
  return 0
}

# Paths the pull request touches, one per line.
CHANGED_PATHS="$WORKDIR/changed_paths.txt"
fetch_changed_paths() {
  if ! bb_request GET "$BB_PR_PATH/changes?limit=1000"; then
    warn "Bitbucket: cannot read the changed files of PR #$BITBUCKET_PR ($(bb_error))."
    return 1
  fi
  jq -r '.values[]?.path?.toString // empty' "$BB_BODY" > "$CHANGED_PATHS"
  if [[ "$(jq -r '.isLastPage // true' "$BB_BODY")" != "true" ]]; then
    warn "Bitbucket: PR #$BITBUCKET_PR changes more than 1000 files; findings in the rest are only listed in Corgea."
  fi
  return 0
}

# Comments already on the pull request, used to avoid duplicates on re-runs.
EXISTING_COMMENTS="$WORKDIR/existing_comments.txt"
fetch_existing_comments() {
  : > "$EXISTING_COMMENTS"
  local start=0 is_last next
  while :; do
    if ! bb_request GET "$BB_PR_PATH/activities?limit=100&start=$start"; then
      warn "Bitbucket: cannot read existing comments ($(bb_error)); duplicate comments are possible."
      return 0
    fi
    # Replies are nested under .comments, so walk every text in the payload.
    # shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
    jq -r '[.. | objects | select(has("text")) | .text] | .[]' "$BB_BODY" \
      | tr '\n' ' ' | grep -oE 'corgea-(issue|scan): `[^`]+`' >> "$EXISTING_COMMENTS" || true
    is_last="$(jq -r '.isLastPage // true' "$BB_BODY")"
    next="$(jq -r '.nextPageStart // empty' "$BB_BODY")"
    [[ "$is_last" == "true" || -z "$next" ]] && break
    start="$next"
  done
  return 0
}

# Every comment ends with one of these so a re-run recognizes its own work.
# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
issue_marker() { printf 'corgea-issue: `%s`' "$1"; }
# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
scan_marker() { printf 'corgea-scan: `%s`' "$1"; }

marker_exists() {
  grep -qxF "$1" "$EXISTING_COMMENTS" 2>/dev/null
}

# Map a scanner path onto a path the pull request actually touches. Fortify
# records build-machine paths, so an exact match is tried first and then the
# longest changed path that shares a whole trailing directory chain with it.
resolve_repo_path() {
  local raw="$1" candidate
  candidate="${raw#./}"
  if [[ -n "$STRIP_PATH_PREFIX" ]]; then
    candidate="${candidate#"${STRIP_PATH_PREFIX%/}/"}"
    candidate="${candidate#"$STRIP_PATH_PREFIX"}"
  fi
  candidate="${candidate#/}"

  if grep -qxF "$candidate" "$CHANGED_PATHS"; then
    printf '%s' "$candidate"
    return 0
  fi
  local best="" changed
  while IFS= read -r changed; do
    [[ -z "$changed" ]] && continue
    if [[ "$candidate" == *"/$changed" || "$changed" == *"/$candidate" ]]; then
      if [[ ${#changed} -gt ${#best} ]]; then best="$changed"; fi
    fi
  done < "$CHANGED_PATHS"
  [[ -z "$best" ]] && return 1
  printf '%s' "$best"
}

# Cache the pull request diff of one file; prints the cache path.
diff_file_for() {
  local path="$1" key cache
  key="$(printf '%s' "$path" | tr -c '[:alnum:]' '_')"
  cache="$WORKDIR/diffs/$key.json"
  if [[ ! -f "$cache" ]]; then
    if bb_request GET "$BB_PR_PATH/diff/$(url_encode_path "$path")?contextLines=$DIFF_CONTEXT_LINES&withComments=false"; then
      cp "$BB_BODY" "$cache"
    else
      echo '{"diffs":[]}' > "$cache"
    fi
  fi
  printf '%s' "$cache"
}

# ADDED / CONTEXT for a line of the post-merge file, empty when it is not in the diff.
diff_line_type() {
  local path="$1" line="$2" cache
  cache="$(diff_file_for "$path")"
  jq -r --argjson n "$line" '
    [ .diffs[]?.hunks[]?.segments[]?
      | select(.type != "REMOVED")
      | .type as $t
      | .lines[]? | select(.destination == $n) | $t
    ] | first // ""
  ' "$cache"
}

# The text Bitbucket has for a line, used to verify a suggestion still applies.
diff_line_text() {
  local path="$1" line="$2" cache
  cache="$(diff_file_for "$path")"
  jq -r --argjson n "$line" '
    [ .diffs[]?.hunks[]?.segments[]?
      | select(.type != "REMOVED")
      | .lines[]? | select(.destination == $n) | .line
    ] | first // ""
  ' "$cache"
}

# Corgea explanations carry a little inline markup; Bitbucket renders markdown.
clean_markup() {
  sed -e 's|<li>|- |g' -e 's|</li>||g' \
      -e 's|<bullet_point>|- |g' -e 's|</bullet_point>||g' \
      -e 's|<point>|- |g' -e 's|</point>||g' \
      -e 's|<item>|- |g' -e 's|</item>||g' \
      -e 's|<code>|`|g' -e 's|</code>|`|g' \
      -e 's|<br>|\n|g'
}

# Text reduced to one whitespace-normalized line, for comparisons.
plain_text() {
  printf '%s' "$1" | clean_markup | tr '\n\t' '  ' | sed -e 's/  */ /g' -e 's/^ *//' -e 's/ *$//'
}

# True when a details section would only repeat the headline.
same_as_headline() {
  [[ "$(plain_text "$1")" == "$(plain_text "$2")" ]]
}

# One line that carries the whole point of the finding.
summarize() {
  local one sentence
  one="$(plain_text "$1")"
  sentence="${one%%. *}"
  if [[ ${#sentence} -ge 40 && ${#sentence} -lt ${#one} ]]; then
    one="$sentence."
  fi
  if [[ ${#one} -gt 240 ]]; then
    one="${one:0:237}..."
  fi
  printf '%s' "$one"
}

urgency_icon() {
  case "$1" in
    CR|HI) printf '🔴' ;;
    ME) printf '🟠' ;;
    *) printf '⚪' ;;
  esac
}

urgency_name() {
  case "$1" in
    CR) printf 'Critical' ;;
    HI) printf 'High' ;;
    ME) printf 'Medium' ;;
    LO) printf 'Low' ;;
    *) printf '%s' "$1" ;;
  esac
}

# Turn a Corgea fix patch into an applicable suggestion.
#
# Reads a unified diff on stdin and prints, for a single-file single-hunk patch:
#   FILE  <path>
#   RANGE <first-line> <last-line>     lines of the pre-fix file to replace
#   ORIG  <line> <text>                what those lines are expected to contain
#   REPL  <text>                       what they should be replaced with
# Exits 2 when the patch cannot be expressed as one contiguous replacement,
# which is when the caller falls back to showing the diff instead.
parse_fix_patch() {
  awk '
    # Header rules only apply outside a hunk: inside one, every line is
    # prefixed with +/-/space, so "--- x" there is content, not a header.
    /^diff --git / { if (!inhunk) next }
    /^index / { if (!inhunk) next }
    /^--- / { if (!inhunk) next }
    /^\+\+\+ / {
      if (!inhunk) {
        files++
        p = $2
        sub(/^b\//, "", p)
        if (p != "/dev/null") file = p
        next
      }
    }
    /^@@/ {
      hunks++
      if (hunks > 1) { exit 2 }
      hdr = $2
      sub(/^-/, "", hdr)
      split(hdr, a, ",")
      old_start = a[1] + 0
      inhunk = 1
      next
    }
    {
      if (!inhunk) next
      if (substr($0, 1, 1) == "\\") next   # "\ No newline at end of file"
      if ($0 == "") { n++; op[n] = " "; txt[n] = ""; next }
      c = substr($0, 1, 1)
      if (c == "+" || c == "-" || c == " ") {
        n++
        op[n] = c
        txt[n] = substr($0, 2)
      } else {
        inhunk = 0
      }
    }
    END {
      if (files > 1 || hunks != 1 || n == 0) exit 2

      first = 0; last = 0
      for (i = 1; i <= n; i++) if (op[i] != " ") { if (!first) first = i; last = i }
      if (!first) exit 2

      # A pure insertion has no line of its own to replace, so it borrows the
      # neighbouring context line and reproduces it in the replacement.
      if (op[first] == "+" && first > 1) first--
      if (op[last] == "+" && last < n) last++

      start = old_start
      for (i = 1; i < first; i++) if (op[i] != "+") start++
      count = 0
      for (i = first; i <= last; i++) if (op[i] != "+") count++
      if (count < 1) exit 2

      printf "FILE %s\n", file
      printf "RANGE %d %d\n", start, start + count - 1
      ln = start
      for (i = first; i <= last; i++) if (op[i] != "+") { printf "ORIG %d %s\n", ln, txt[i]; ln++ }
      for (i = first; i <= last; i++) if (op[i] != "-") printf "REPL %s\n", txt[i]
    }
  '
}

rstrip() { printf '%s' "${1%"${1##*[![:space:]]}"}"; }

# Globals set by build_suggestion_block.
SUGGESTION_TEXT=""
SUGGESTION_START=""
SUGGESTION_END=""

# Build a ```suggestion block for a finding, but only when Bitbucket can apply
# it: every replaced line must be in the diff and still hold the code the patch
# was computed against. Returns 1 when the fix cannot be offered that way.
build_suggestion_block() {
  local path="$1" patch="$2"
  SUGGESTION_TEXT=""; SUGGESTION_START=""; SUGGESTION_END=""

  local parsed="$WORKDIR/fix_patch.txt"
  if ! printf '%s\n' "$patch" | parse_fix_patch > "$parsed" 2>/dev/null; then
    return 1
  fi
  [[ -s "$parsed" ]] || return 1

  local line rest lineno expected actual replacement=""
  while IFS= read -r line; do
    case "$line" in
      "RANGE "*)
        rest="${line#RANGE }"
        SUGGESTION_START="${rest%% *}"
        SUGGESTION_END="${rest#* }"
        ;;
      "ORIG "*)
        rest="${line#ORIG }"
        lineno="${rest%% *}"
        if [[ "$rest" == *" "* ]]; then expected="${rest#* }"; else expected=""; fi
        if [[ "$(diff_line_type "$path" "$lineno")" == "" ]]; then
          return 1
        fi
        actual="$(diff_line_text "$path" "$lineno")"
        if [[ "$(rstrip "$actual")" != "$(rstrip "$expected")" ]]; then
          return 1
        fi
        ;;
      "REPL "*)
        replacement+="${line#REPL }"$'\n'
        ;;
    esac
  done < "$parsed"

  [[ -n "$SUGGESTION_START" && -n "$SUGGESTION_END" ]] || return 1
  SUGGESTION_TEXT='```suggestion'$'\n'"${replacement%$'\n'}"$'\n''```'
  return 0
}

# Bitbucket Server has no <details> element, so the comment is written the way
# the platform collapses it: the whole point on the first line, everything else
# after it, behind "Show more".
render_comment() {
  local kind="$1" issue_id="$2" classification="$3" urgency="$4" headline="$5"
  local issue_expl="$6" fp_reason="$7" fix_expl="$8" fix_block="$9"
  local corgea_url; corgea_url="$(corgea_base_url)"

  if [[ "$kind" == "false_positive" ]]; then
    printf '%s\n' "✅ **False positive** — $SCANNER_LABEL flagged **$classification** here, but Corgea's triage found it is not exploitable: $headline [View in Corgea ↗]($corgea_url/issue/$issue_id)"
    printf '\n'
    if [[ -n "$fp_reason" ]] && ! same_as_headline "$fp_reason" "$headline"; then
      printf '%s\n\n' "**🔍 Why this is a false positive**"
      printf '%s\n\n' "$(printf '%s' "$fp_reason" | clean_markup)"
    fi
    if [[ -n "$issue_expl" ]] && ! same_as_headline "$issue_expl" "$headline"; then
      printf '%s\n\n' "**🎟️ What $SCANNER_LABEL reported**"
      printf '%s\n\n' "$(printf '%s' "$issue_expl" | clean_markup)"
    fi
    printf '%s\n' "No change is needed here. Disagree? Reopen it in Corgea and the triage is revisited."
  else
    printf '%s\n' "$(urgency_icon "$urgency") **$classification** ($(urgency_name "$urgency") · 🔒 Security) — $headline [View in Corgea ↗]($corgea_url/issue/$issue_id)"
    printf '\n'
    if [[ -n "$issue_expl" ]] && ! same_as_headline "$issue_expl" "$headline"; then
      printf '%s\n\n' "**🎟️ Issue explanation**"
      printf '%s\n\n' "$(printf '%s' "$issue_expl" | clean_markup)"
    fi
    if [[ -n "$fix_expl" ]]; then
      printf '%s\n\n' "**🪄 Fix explanation**"
      printf '%s\n\n' "$(printf '%s' "$fix_expl" | clean_markup)"
    fi
    if [[ -n "$fix_block" ]]; then
      printf '%s\n\n' "$fix_block"
    fi
  fi
  printf '\n%s\n' "_Corgea · $SCANNER_LABEL finding · scan \`$SCAN_ID\` · $(issue_marker "$issue_id")_"
}

# Anchor JSON for a line comment; falls back to a whole-file anchor when the
# line is not part of the diff, and to nothing when the file is not either.
build_anchor() {
  local path="$1" start="$2" end="$3"
  local start_type end_type

  if [[ -n "$start" && -n "$end" ]]; then
    start_type="$(diff_line_type "$path" "$start")"
    end_type="$(diff_line_type "$path" "$end")"
    if [[ -n "$start_type" && -n "$end_type" ]]; then
      if [[ "$start" -eq "$end" ]]; then
        jq -nc --arg path "$path" --argjson line "$end" --arg lt "$end_type" \
          '{path: $path, srcPath: $path, diffType: "EFFECTIVE", fileType: "TO", line: $line, lineType: $lt}'
        return 0
      fi
      # Bitbucket DC >= 9.3: a multi-line suggestion replaces exactly the
      # anchored span, which needs multilineMarker + multilineSpan.
      jq -nc --arg path "$path" --argjson line "$end" --arg lt "$end_type" \
             --argjson start "$start" --arg st "$start_type" \
        '{path: $path, srcPath: $path, diffType: "EFFECTIVE", fileType: "TO",
          line: $line, lineType: $lt,
          multilineMarker: {startLine: $start, startLineType: $st},
          multilineSpan: {dstSpanStart: $start, dstSpanEnd: $line}}'
      return 0
    fi
  fi

  jq -nc --arg path "$path" '{path: $path, srcPath: $path, diffType: "EFFECTIVE"}'
  return 0
}

POSTED_COUNT=0
POSTED_FP_COUNT=0
POSTED_SUGGESTION_COUNT=0
SKIPPED_EXISTING=0
OUTSIDE_DIFF_COUNT=0
FAILED_COUNT=0

post_comment() {
  local text="$1" anchor="${2:-}"
  local payload="$WORKDIR/payload.json"

  if [[ -n "$anchor" ]]; then
    jq -n --arg text "$text" --argjson anchor "$anchor" '{text: $text, anchor: $anchor}' > "$payload"
  else
    jq -n --arg text "$text" '{text: $text}' > "$payload"
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "--- would post to PR #$BITBUCKET_PR ---"
    [[ -n "$anchor" ]] && echo "anchor: $anchor"
    printf '%s\n' "$text"
    echo "---"
    return 0
  fi

  if ! bb_request POST "$BB_PR_PATH/comments" "$payload"; then
    warn "Bitbucket: failed to post a comment ($(bb_error))."
    return 1
  fi
  return 0
}

post_issue_comment() {
  local issue_id="$1"
  local issue_file="$WORKDIR/issues/$issue_id.json"
  [[ -f "$issue_file" ]] || return 0

  if marker_exists "$(issue_marker "$issue_id")"; then
    SKIPPED_EXISTING=$((SKIPPED_EXISTING + 1))
    return 0
  fi

  local file line classification urgency fp_status fp_reason issue_expl fix_expl fix_diff
  file="$(jq -r '.location.file.path // empty' "$issue_file")"
  line="$(jq -r '.location.line_number // 0' "$issue_file")"
  classification="$(jq -r '.classification.name // .classification.id // "Security issue"' "$issue_file")"
  urgency="$(jq -r '.urgency // empty' "$issue_file")"
  fp_status="$(jq -r '.auto_triage.false_positive_detection.status // "unknown"' "$issue_file")"
  fp_reason="$(jq -r '.auto_triage.false_positive_detection.reasoning // empty' "$issue_file")"
  issue_expl="$(jq -r '.details.explanation // empty' "$issue_file")"
  fix_expl="$(jq -r '.auto_fix_suggestion.patch.explanation // empty' "$issue_file")"
  fix_diff="$(jq -r '.auto_fix_suggestion.patch.diff // empty' "$issue_file")"

  local is_fp=0
  [[ "$fp_status" == "false_positive" ]] && is_fp=1
  if [[ "$is_fp" -eq 1 && "$POST_FALSE_POSITIVES" != "1" ]]; then
    return 0
  fi

  local path
  if ! path="$(resolve_repo_path "$file")"; then
    OUTSIDE_DIFF_COUNT=$((OUTSIDE_DIFF_COUNT + 1))
    if [[ "$POST_OUTSIDE_DIFF" != "1" ]]; then
      return 0
    fi
    path=""
  fi

  local headline fix_block="" anchor="" start="" end="" has_suggestion=0
  if [[ "$is_fp" -eq 1 ]]; then
    headline="$(summarize "${fp_reason:-$issue_expl}")"
  else
    headline="$(summarize "${issue_expl:-$classification detected at $file:$line}")"
    if [[ -n "$path" && "$POST_SUGGESTIONS" == "1" && -n "$fix_diff" ]] &&
       build_suggestion_block "$path" "$fix_diff"; then
      fix_block="$SUGGESTION_TEXT"
      start="$SUGGESTION_START"
      end="$SUGGESTION_END"
      has_suggestion=1
    elif [[ -n "$fix_diff" ]]; then
      # Not applicable as-is (multiple hunks, or the file moved on since the
      # scan), so the fix is shown as a diff the reviewer applies by hand.
      fix_block='```diff'$'\n'"$fix_diff"$'\n''```'
    fi
  fi

  if [[ -n "$path" ]]; then
    if [[ -z "$start" ]]; then start="$line"; end="$line"; fi
    anchor="$(build_anchor "$path" "$start" "$end")"
  fi

  local text
  text="$(render_comment "$([[ "$is_fp" -eq 1 ]] && echo false_positive || echo finding)" \
            "$issue_id" "$classification" "$urgency" "$headline" \
            "$issue_expl" "$fp_reason" "$fix_expl" "$fix_block")"

  if post_comment "$text" "$anchor"; then
    POSTED_COUNT=$((POSTED_COUNT + 1))
    [[ "$is_fp" -eq 1 ]] && POSTED_FP_COUNT=$((POSTED_FP_COUNT + 1))
    [[ "$has_suggestion" -eq 1 ]] && POSTED_SUGGESTION_COUNT=$((POSTED_SUGGESTION_COUNT + 1))
  else
    FAILED_COUNT=$((FAILED_COUNT + 1))
  fi
  return 0
}

post_summary_comment() {
  local corgea_url scan_link total
  if marker_exists "$(scan_marker "$SCAN_ID")"; then
    return 0
  fi
  corgea_url="$(corgea_base_url)"
  scan_link="$corgea_url/scan/?scan_id=$SCAN_ID"
  total=${#ISSUE_IDS[@]}

  local text
  text="$(
    printf '%s\n\n' "🐕 **Corgea** reviewed the $SCANNER_LABEL report for this pull request: $total finding(s), $FP_COUNT auto-triaged as false positive. [See the full scan in Corgea ↗]($scan_link)"
    printf '%s\n' "| Result | Count |"
    printf '%s\n' "| --- | --- |"
    printf '%s\n' "| 🔴 Critical | $CR_COUNT |"
    printf '%s\n' "| 🔴 High | $HI_COUNT |"
    printf '%s\n' "| 🟠 Medium | $ME_COUNT |"
    printf '%s\n' "| ⚪ Low | $LO_COUNT |"
    printf '%s\n' "| ✅ False positive (auto-triaged) | $FP_COUNT |"
    printf '%s\n\n' "| 🪄 With an applicable suggestion | $POSTED_SUGGESTION_COUNT |"
    printf '%s\n' "Commented on $POSTED_COUNT finding(s) in this diff."
    if [[ "$OUTSIDE_DIFF_COUNT" -gt 0 ]]; then
      printf '%s\n' "$OUTSIDE_DIFF_COUNT finding(s) are in files this pull request does not touch and are only listed in Corgea."
    fi
    if [[ "$SKIPPED_EXISTING" -gt 0 ]]; then
      printf '%s\n' "$SKIPPED_EXISTING finding(s) were already commented on by an earlier run."
    fi
    printf '\n%s\n' "_Corgea · $(scan_marker "$SCAN_ID")_"
  )"

  post_comment "$text" "" || true
}

post_findings_to_bitbucket() {
  command -v curl >/dev/null || { warn "curl is required to post Bitbucket comments; skipping."; return 0; }

  echo
  echo "==> Posting findings to Bitbucket ..."
  setup_bitbucket_auth

  if ! resolve_pull_request; then
    return 0
  fi
  echo "    Pull request: ${BITBUCKET_PROJECT}/${BITBUCKET_REPO} #$BITBUCKET_PR"

  if ! fetch_changed_paths; then
    return 0
  fi
  fetch_existing_comments

  local issue_id
  for issue_id in "${ISSUE_IDS[@]:-}"; do
    [[ -z "$issue_id" ]] && continue
    post_issue_comment "$issue_id"
  done

  if [[ "$POST_SUMMARY" == "1" ]]; then
    post_summary_comment
  fi

  echo "    Comments posted:      $POSTED_COUNT (of which false positives: $POSTED_FP_COUNT)"
  echo "    With a suggestion:    $POSTED_SUGGESTION_COUNT"
  echo "    Already commented:    $SKIPPED_EXISTING"
  echo "    Outside the PR diff:  $OUTSIDE_DIFF_COUNT"
  if [[ "$FAILED_COUNT" -gt 0 ]]; then
    echo "    Failed to post:       $FAILED_COUNT"
  fi
}

if bitbucket_configured; then
  post_findings_to_bitbucket
elif [[ "$NO_BITBUCKET" -eq 0 && -n "$BITBUCKET_URL" ]]; then
  warn
  warn "Bitbucket posting is half-configured and was skipped."
  warn "Set BITBUCKET_URL, BITBUCKET_PROJECT, BITBUCKET_REPO and BITBUCKET_TOKEN"
  warn "(or BITBUCKET_USER + BITBUCKET_PASSWORD)."
fi

echo "================================================================================"
echo "Summary for scan $SCAN_ID"
echo "  Total issues:      ${#ISSUE_IDS[@]}"
echo "  False positives:   $FP_COUNT"
echo "  Valid findings:    $VALID_COUNT"
echo "  With fix patches:  $FIX_COUNT"
if bitbucket_configured; then
  echo "  Bitbucket comments: $POSTED_COUNT posted, $SKIPPED_EXISTING already present"
fi
