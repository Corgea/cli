#!/usr/bin/env bash
set -euo pipefail

INJECT_SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
exec python3 "$INJECT_SCRIPT_DIR/inject_walkthrough_diffs.py" "$@"
