#!/usr/bin/env bash
# Upload a Checkmarx report to Corgea (same flow as `corgea upload`).
#
# Usage:
#   export CORGEA_TOKEN=<token>
#   ./upload_checkmarx.sh <code_path> <report_path>
#
# Optional:
#   CORGEA_URL   Corgea base URL (default: https://www.corgea.app)
#   PROJECT      Project name (default: basename of <code_path>)
#
# Creates the scan and prints the scan URL. Does not wait for it to finish.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <code_path> <report_path>" >&2
  exit 2
fi

CODE_PATH=$(cd "$1" && pwd)
REPORT_PATH=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
BASE_URL="${CORGEA_URL:-https://www.corgea.app}"
BASE_URL="${BASE_URL%/}"
TOKEN="${CORGEA_TOKEN:?set CORGEA_TOKEN}"
PROJECT="${PROJECT:-$(basename "$CODE_PATH")}"
PROJECT=$(printf '%s' "$PROJECT" | tr -c 'A-Za-z0-9._-' '_')
RUN_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
API="$BASE_URL/api/v1"

if [[ ! -f "$REPORT_PATH" ]]; then
  echo "error: report not found: $REPORT_PATH" >&2
  exit 1
fi

# Opaque tokens use CORGEA-TOKEN; JWTs (a.b.c) use Authorization: Bearer.
AUTH_ARGS=(-H "CORGEA-SOURCE: cli")
if [[ "$TOKEN" == *.*.* && "$TOKEN" != *..* ]]; then
  AUTH_ARGS+=(-H "Authorization: Bearer $TOKEN")
else
  AUTH_ARGS+=(-H "CORGEA-TOKEN: $TOKEN")
fi

curl -fsS "${AUTH_ARGS[@]}" "$API/verify" >/dev/null

# Extract repo-relative source paths from Checkmarx XML / CLI JSON / web JSON.
# Mirrors the CLI: strip a leading separator from each path named by the report.
mapfile -t PATHS < <(python3 - "$REPORT_PATH" <<'PY'
import json, sys, xml.etree.ElementTree as ET
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8-sig").strip()
paths = []

if text.startswith("<?xml") and "<CxXMLResults" in text:
    for el in ET.fromstring(text).iter():
        tag = el.tag.rpartition("}")[2]
        if tag == "Result" and el.get("FileName"):
            paths.append(el.get("FileName").lstrip("/\\"))
        elif tag == "FileName" and (el.text or "").strip():
            paths.append(el.text.strip().lstrip("/\\"))
else:
    data = json.loads(text)
    if {"totalCount", "results", "scanID"} <= data.keys():
        for r in data.get("results") or []:
            for n in ((r.get("data") or {}).get("nodes") or []):
                if isinstance(n.get("fileName"), str):
                    paths.append(n["fileName"][1:])
    elif {"scanResults", "reportId"} <= data.keys():
        for lang in (((data.get("scanResults") or {}).get("sast") or {}).get("languages") or []):
            for q in lang.get("queries") or []:
                for v in q.get("vulnerabilities") or []:
                    for n in v.get("nodes") or []:
                        if isinstance(n.get("fileName"), str):
                            paths.append(n["fileName"][1:])
    else:
        sys.exit("unrecognized Checkmarx report format")

seen = set()
for p in paths:
    if p and p not in seen:
        seen.add(p)
        print(p)
PY
)

if [[ ${#PATHS[@]} -eq 0 ]]; then
  echo "no findings in report, nothing to upload"
  exit 0
fi

echo "Uploading ${#PATHS[@]} source file(s) from $CODE_PATH..."
for rel in "${PATHS[@]}"; do
  file="$CODE_PATH/$rel"
  if [[ ! -f "$file" ]]; then
    echo "error: $rel referenced by the report but missing under $CODE_PATH" >&2
    exit 1
  fi
  # Same as the CLI: path is passed raw in the query string.
  curl -fsS "${AUTH_ARGS[@]}" \
    -F "file=@${file}" \
    "${API}/code-upload?run_id=${RUN_ID}&path=${rel}" \
    >/dev/null
  echo "  $rel"
done

echo "Uploading report as project '$PROJECT'..."
RESPONSE=$(curl -fsS "${AUTH_ARGS[@]}" \
  -H "Content-Type: application/json" \
  --data-binary @"$REPORT_PATH" \
  "${API}/scan-upload?engine=checkmarx&run_id=${RUN_ID}&project=${PROJECT}&ci=false&ci_platform=unknown")

SCAN_ID=$(printf '%s' "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sast_scan_id"])')
PROJECT_ID=$(printf '%s' "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("project_id") or "")')

if [[ -f "$CODE_PATH/.git/config" ]]; then
  curl -fsS "${AUTH_ARGS[@]}" \
    -F "file=@${CODE_PATH}/.git/config" \
    "${API}/git-config-upload?run_id=${RUN_ID}" >/dev/null || true
fi

if [[ -n "$PROJECT_ID" ]]; then
  echo "Scan $SCAN_ID created."
  echo "${BASE_URL}/project/${PROJECT_ID}/?scan_id=${SCAN_ID}"
else
  echo "Scan $SCAN_ID created."
  echo "${BASE_URL}/project/${PROJECT}?scan_id=${SCAN_ID}"
fi
