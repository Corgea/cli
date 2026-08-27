#!/usr/bin/env python3
"""Inject base64-encoded committed diffs into a walkthrough HTML artifact."""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile


START_MARKER = "<!-- inject-walkthrough-diffs:start (generated; re-run the script to refresh) -->"
END_MARKER = "<!-- inject-walkthrough-diffs:end -->"
DIFF_FILE = re.compile(r'diffFile\s*:\s*"((?:\\.|[^"\\])*)"')
STASH_OPEN = re.compile(r'<div\b(?=[^>]*\bid=["\']diffs["\'])[^>]*>', re.IGNORECASE)
STASH_CLOSE = re.compile(r'^[ \t]*</div>[ \t]*$', re.MULTILINE | re.IGNORECASE)


class InjectionError(RuntimeError):
    pass


def mask_html_comments(document: str) -> str:
    """Replace HTML comment bodies with offset-preserving whitespace."""
    masked = list(document)
    cursor = 0
    while True:
        start = document.find("<!--", cursor)
        if start < 0:
            break
        close = document.find("-->", start + 4)
        end = len(document) if close < 0 else close + 3
        for index in range(start, end):
            if masked[index] not in "\r\n":
                masked[index] = " "
        cursor = end
    return "".join(masked)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fill a walkthrough diff stash from a committed local git range."
    )
    parser.add_argument("target", type=Path, help="walkthrough HTML file to update")
    parser.add_argument(
        "base_dir",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="repository root containing the committed diff",
    )
    parser.add_argument("--range", dest="revision_range", required=True)
    parser.add_argument("--max-lines", type=int, default=0)
    return parser.parse_args()


def requested_paths(document: str) -> list[str]:
    paths: set[str] = set()
    for encoded in DIFF_FILE.findall(mask_html_comments(document)):
        try:
            path = json.loads(f'"{encoded}"')
        except json.JSONDecodeError as exc:
            raise InjectionError(f"invalid diffFile string: {encoded}") from exc
        pure = PurePosixPath(path)
        if not path or pure.is_absolute() or ".." in pure.parts or path == ".":
            raise InjectionError(f"diffFile must be a repository-relative path: {path}")
        paths.add(path)
    return sorted(paths)


def repository_root(base_dir: Path) -> Path:
    base = base_dir.resolve()
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=base,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise InjectionError(result.stderr.strip() or f"not a git repository: {base}")
    root = Path(result.stdout.strip()).resolve()
    if root != base:
        raise InjectionError(f"base-dir must be the repository root: {root}")
    return root


def file_diff(root: Path, revision_range: str, path: str, max_lines: int) -> bytes:
    result = subprocess.run(
        ["git", "--literal-pathspecs", "diff", "--no-ext-diff", revision_range, "--", path],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise InjectionError(error or f"git diff failed for {path}")
    payload = result.stdout
    if max_lines > 0:
        lines = payload.splitlines(keepends=True)
        if len(lines) > max_lines:
            omitted = len(lines) - max_lines
            payload = b"".join(lines[:max_lines]) + (
                f"@@ … {omitted} more lines elided; inspect the committed diff for full context @@\n"
            ).encode("utf-8")
    return payload


def encoded_block(path: str, payload: bytes) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    escaped_path = html.escape(path, quote=True)
    return (
        f'<script type="application/octet-stream" data-diff="{escaped_path}" '
        f'data-encoding="base64">{encoded}</script>'
    )


def replace_stash(document: str, blocks: list[str]) -> str:
    comment_masked = mask_html_comments(document)
    opening = STASH_OPEN.search(comment_masked)
    if not opening:
        raise InjectionError('target has no <div id="diffs"> stash')

    marker_start = document.find(START_MARKER, opening.end())
    if marker_start >= 0:
        marker_end = document.find(END_MARKER, marker_start + len(START_MARKER))
        if marker_end < 0:
            raise InjectionError("generated diff stash is missing its end marker")
        close = STASH_CLOSE.search(comment_masked, marker_end + len(END_MARKER))
    else:
        close = STASH_CLOSE.search(comment_masked, opening.end())
    if not close:
        raise InjectionError("diff stash is missing its closing div")

    generated = "\n".join([START_MARKER, *blocks, END_MARKER])
    return document[: opening.end()] + "\n" + generated + "\n" + document[close.start() :]


def write_atomic(path: Path, content: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    options = arguments()
    if options.max_lines < 0:
        print("error: --max-lines must be zero or positive", file=sys.stderr)
        return 2
    if options.revision_range.startswith("-"):
        print("error: --range must be a revision range, not an option", file=sys.stderr)
        return 2

    target = options.target.resolve()
    if not target.is_file():
        print(f"error: walkthrough not found: {target}", file=sys.stderr)
        return 2

    try:
        document = target.read_text(encoding="utf-8")
        paths = requested_paths(document)
        if not paths:
            print("inject-walkthrough-diffs: no diffFile entries found; nothing to inject")
            return 0
        root = repository_root(options.base_dir)
        blocks: list[str] = []
        missing: list[str] = []
        for path in paths:
            payload = file_diff(root, options.revision_range, path, options.max_lines)
            if payload:
                blocks.append(encoded_block(path, payload))
            else:
                missing.append(path)
        write_atomic(target, replace_stash(document, blocks))
    except (InjectionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"inject-walkthrough-diffs: injected {len(blocks)}/{len(paths)} file diffs into {target}")
    if missing:
        print("warning: no diff found for requested paths:", file=sys.stderr)
        for path in missing:
            print(f"  - {path}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
