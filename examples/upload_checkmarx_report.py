#!/usr/bin/env python3
"""Upload a Checkmarx report to Corgea over the raw HTTP API.

This reproduces what `corgea upload <checkmarx-report>` does, so it can be used
as a reference for wiring Corgea into a pipeline that cannot run the CLI binary.
The request sequence is:

    GET  /api/v1/verify
    POST /api/v1/code-upload?run_id=<uuid>&path=<repo-relative path>   (per file)
    POST /api/v1/scan-upload?engine=checkmarx&run_id=<uuid>&project=...
    POST /api/v1/git-config-upload?run_id=<uuid>                       (if .git/config exists)
    GET  /api/v1/scan/<scan_id>                                        (--wait)
    GET  /api/v1/scan/<scan_id>/issues?page=N&page_size=30             (--wait)

Checkmarx findings reference source files by path. Corgea needs the matching
source, so every path named by the report is uploaded under a shared `run_id`
before the report itself; the `run_id` is what ties the two together server side.

Usage:
    export CORGEA_TOKEN=<your token>
    ./upload_checkmarx_report.py checkmarx_report.xml --project-name my-service --wait

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any, Iterable

DEFAULT_URL = "https://www.corgea.app"
API_BASE = "/api/v1"
ENGINE = "checkmarx"

# Reports larger than this are streamed as `Upload-Offset`/`Upload-Length`
# chunks instead of a single body, matching the CLI's limits.
MAX_SINGLE_UPLOAD_BYTES = 50 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024

POLL_INTERVAL_SECONDS = 1
ISSUE_PAGE_SIZE = 30
URGENCY_ORDER = ("CR", "HI", "ME", "LO")


class CorgeaError(Exception):
    """A request was rejected, or the report could not be parsed."""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def read_cli_config() -> dict[str, str]:
    """Read `~/.corgea/config.toml`, the file `corgea login` writes."""
    path = Path.home() / ".corgea" / "config.toml"
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import tomllib

        return {k: v for k, v in tomllib.loads(text).items() if isinstance(v, str)}
    except ImportError:  # Python < 3.11
        pairs = re.findall(r'^\s*(\w+)\s*=\s*"([^"]*)"\s*$', text, re.MULTILINE)
        return dict(pairs)


def resolve_url(override: str | None) -> str:
    config = read_cli_config()
    url = override or os.environ.get("CORGEA_URL") or config.get("url") or DEFAULT_URL
    return url.rstrip("/")


def resolve_token(override: str | None) -> str:
    config = read_cli_config()
    token = override or os.environ.get("CORGEA_TOKEN") or config.get("token") or ""
    if not token:
        raise CorgeaError(
            "No Corgea token. Set CORGEA_TOKEN, pass --token, or run `corgea login <token>`."
        )
    return token


def auth_headers(token: str) -> dict[str, str]:
    """A JWT goes in `Authorization`; an opaque token in `CORGEA-TOKEN`."""
    segments = token.split(".", 3)
    if len(segments) == 3 and all(segments):
        headers = {"Authorization": f"Bearer {token}"}
    else:
        headers = {"CORGEA-TOKEN": token}
    headers["CORGEA-SOURCE"] = os.environ.get("CORGEA_SOURCE", "cli")
    return headers


def sanitize_project_name(name: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name)


def determine_project_name(provided: str | None, root: Path) -> str:
    """`--project-name`, else the git remote's repo name, else the directory."""
    if provided:
        return sanitize_project_name(provided)

    git_config = root / ".git" / "config"
    if git_config.is_file():
        match = re.search(
            r'\[remote "origin"\][^\[]*?url\s*=\s*(\S+)',
            git_config.read_text(encoding="utf-8", errors="replace"),
            re.DOTALL,
        )
        if match:
            repo = match.group(1).removesuffix(".git").rstrip("/")
            tail = re.split(r"[/:]", repo)[-1].strip()
            if tail:
                return sanitize_project_name(tail)

    return sanitize_project_name(root.resolve().name)


def ci_context(project: str, github_env: dict[str, str]) -> tuple[bool, str, str]:
    """Corgea keys CI scans to `{repo}-{pr}` so a PR gets one project."""
    in_ci = "CI" in os.environ and "GITHUB_ACTIONS" in os.environ
    platform = "github" if "GITHUB_ACTIONS" in os.environ else "unknown"
    if in_ci:
        project = f"{github_env['GITHUB_REPOSITORY']}-{github_env['GITHUB_PR']}"
    return in_ci, platform, project


# --------------------------------------------------------------------------
# Checkmarx report parsing
# --------------------------------------------------------------------------


def _strip_leading_separator(path: str) -> str:
    return path.lstrip("/\\")


def parse_checkmarx_xml(text: str) -> list[str]:
    """`CxXMLResults`: paths live on `Result/@FileName` or `<FileName>` nodes."""
    paths: list[str] = []
    for element in ElementTree.fromstring(text).iter():
        tag = element.tag.rpartition("}")[2]
        if tag == "Result":
            candidate = element.get("FileName", "")
        elif tag == "FileName":
            candidate = element.text or ""
        else:
            continue
        candidate = _strip_leading_separator(candidate.strip())
        if candidate:
            paths.append(candidate)
    return paths


def _paths_from_nodes(nodes: Iterable[Any]) -> Iterable[str]:
    # Checkmarx JSON prefixes every path with the scan root separator, which the
    # CLI drops by removing the first character rather than stripping a set of
    # separators. Mirror that so both produce identical `path` query values.
    for node in nodes:
        if isinstance(node, dict) and isinstance(node.get("fileName"), str):
            yield node["fileName"][1:]


def parse_checkmarx_cli_json(data: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for result in data.get("results") or []:
        nodes = (result.get("data") or {}).get("nodes") or []
        paths.extend(_paths_from_nodes(nodes))
    return paths


def parse_checkmarx_web_json(data: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    sast = ((data.get("scanResults") or {}).get("sast") or {})
    for language in sast.get("languages") or []:
        for query in language.get("queries") or []:
            for vulnerability in query.get("vulnerabilities") or []:
                paths.extend(_paths_from_nodes(vulnerability.get("nodes") or []))
    return paths


def parse_report(text: str) -> list[str]:
    """Return the source paths a Checkmarx report references, in report order."""
    if text.startswith("<?xml") and "<CxXMLResults" in text:
        return parse_checkmarx_xml(text)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        if {"totalCount", "results", "scanID"} <= data.keys():
            return parse_checkmarx_cli_json(data)
        if {"scanResults", "reportId"} <= data.keys():
            return parse_checkmarx_web_json(data)

    raise CorgeaError(
        "Unrecognized Checkmarx report. Expected CxXMLResults XML, Checkmarx CLI "
        "JSON (totalCount/results/scanID), or Checkmarx web JSON (scanResults/reportId)."
    )


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


class CorgeaApi:
    def __init__(self, base_url: str, token: str, timeout: int = 150) -> None:
        self.base_url = base_url
        self.headers = auth_headers(token)
        self.timeout = timeout

    def _url(self, path: str, query: dict[str, str] | None = None) -> str:
        url = f"{self.base_url}{API_BASE}{path}"
        if query:
            # `safe="/"` keeps repo-relative paths readable in the query string.
            encoded = urllib.parse.urlencode(
                query, quote_via=urllib.parse.quote, safe="/"
            )
            url = f"{url}?{encoded}"
        return url

    def request(
        self,
        method: str,
        path: str,
        query: dict[str, str] | None = None,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            self._url(path, query), data=body, method=method
        )
        for name, value in {**self.headers, **(headers or {})}.items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()
        except urllib.error.URLError as error:
            raise CorgeaError(f"{method} {path} failed: {error.reason}") from error

    def json_get(self, path: str, query: dict[str, str] | None = None) -> dict[str, Any]:
        status, _, body = self.request("GET", path, query=query)
        if status >= 400:
            raise CorgeaError(f"GET {path} returned {status}: {body.decode(errors='replace')}")
        return json.loads(body or b"{}")


def encode_multipart_file(field: str, path: Path) -> tuple[str, bytes]:
    """Build a `multipart/form-data` body holding a single file part."""
    boundary = uuid.uuid4().hex
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{path.name}"\r\n'
        f"Content-Type: {mime}\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return f"multipart/form-data; boundary={boundary}", head + path.read_bytes() + tail


# --------------------------------------------------------------------------
# Upload steps
# --------------------------------------------------------------------------


def verify_token(api: CorgeaApi) -> None:
    body = api.json_get("/verify")
    if body.get("status") != "ok":
        raise CorgeaError(f"Token rejected by {api.base_url}: {body}")


def upload_source_files(
    api: CorgeaApi, run_id: str, paths: list[str], root: Path, allow_missing: bool
) -> int:
    """Upload each referenced file once, keyed to `run_id` by its repo-relative path."""
    uploaded = 0
    for path in dict.fromkeys(paths):  # de-duplicate, keep report order
        local = root / path
        if not local.is_file():
            message = f"{path} is referenced by the report but missing under {root}"
            if not allow_missing:
                raise CorgeaError(
                    f"{message}. Run from the scanned source tree, pass --source-root, "
                    "or use --allow-missing-files to upload the report without it."
                )
            print(f"  warning: skipping {message}", file=sys.stderr)
            continue

        content_type, body = encode_multipart_file("file", local)
        status, _, response = api.request(
            "POST",
            "/code-upload",
            query={"run_id": run_id, "path": path},
            body=body,
            headers={"Content-Type": content_type},
        )
        if status >= 400:
            raise CorgeaError(
                f"code-upload of {path} returned {status}: {response.decode(errors='replace')}"
            )
        uploaded += 1
        print(f"  uploaded {path}")
    return uploaded


def upload_report(
    api: CorgeaApi, run_id: str, report: str, project: str, in_ci: bool, platform: str
) -> tuple[str, str | None]:
    """POST the report and return `(scan_id, project_id)`."""
    query = {
        "engine": ENGINE,
        "run_id": run_id,
        "project": project,
        "ci": "true" if in_ci else "false",
        "ci_platform": platform,
    }
    repo_data = os.environ.get("REPO_DATA", "")
    if repo_data:
        query["repo_data"] = repo_data

    payload = report.encode("utf-8")
    # The endpoint is declared JSON even for Checkmarx XML; the `engine`
    # query parameter is what selects the parser server side.
    headers = {"Content-Type": "application/json"}

    if len(payload) <= MAX_SINGLE_UPLOAD_BYTES:
        status, _, response = api.request(
            "POST", "/scan-upload", query=query, body=payload, headers=headers
        )
    else:
        status, response_headers, response = _upload_report_in_chunks(
            api, query, payload, headers
        )
        del response_headers

    if status >= 400:
        raise CorgeaError(
            f"scan-upload returned {status}: {response.decode(errors='replace')}"
        )

    body = json.loads(response or b"{}")
    scan_id = body.get("sast_scan_id")
    if scan_id is None:
        raise CorgeaError(f"scan-upload succeeded but returned no sast_scan_id: {body}")
    project_id = body.get("project_id")
    return str(scan_id), None if project_id is None else str(project_id)


def _upload_report_in_chunks(
    api: CorgeaApi, query: dict[str, str], payload: bytes, headers: dict[str, str]
) -> tuple[int, dict[str, str], bytes]:
    total = len(payload)
    offset = 0
    status, response_headers, response = 0, {}, b""
    while offset < total:
        chunk = payload[offset : offset + CHUNK_BYTES]
        status, response_headers, response = api.request(
            "POST",
            "/scan-upload",
            query=query,
            body=chunk,
            headers={
                **headers,
                "Upload-Offset": str(offset),
                "Upload-Length": str(total),
            },
        )
        if status >= 400:
            return status, response_headers, response
        offset += len(chunk)
        # A mismatch means chunks landed on different server instances; the
        # assembled report would be corrupt, so stop rather than finish it.
        acknowledged = response_headers.get("Upload-Offset")
        if acknowledged is not None and acknowledged.isdigit():
            if int(acknowledged) != offset:
                raise CorgeaError(
                    f"Upload offset mismatch: server has {acknowledged} bytes, expected {offset}."
                )
        print(f"  sent {offset}/{total} bytes")
    return status, response_headers, response


def upload_git_config(api: CorgeaApi, run_id: str, root: Path) -> None:
    """Optional: lets Corgea attach the scan to the right repo and branch."""
    git_config = root / ".git" / "config"
    if not git_config.is_file():
        return
    content_type, body = encode_multipart_file("file", git_config)
    status, _, response = api.request(
        "POST",
        "/git-config-upload",
        query={"run_id": run_id},
        body=body,
        headers={"Content-Type": content_type},
    )
    if status >= 400:
        print(
            f"  warning: git-config-upload returned {status}: "
            f"{response.decode(errors='replace')}",
            file=sys.stderr,
        )


def scan_url(base_url: str, scan_id: str, project_id: str | None, project: str) -> str:
    if project_id:
        return f"{base_url}/project/{project_id}/?scan_id={scan_id}"
    return f"{base_url}/project/{urllib.parse.quote(project, safe='')}?scan_id={scan_id}"


def wait_for_scan(api: CorgeaApi, scan_id: str) -> None:
    while True:
        scan = api.json_get(f"/scan/{scan_id}")
        status = scan.get("status", "")
        if status == "complete":
            return
        print(f"  scan status: {status or 'unknown'}")
        time.sleep(POLL_INTERVAL_SECONDS)


def print_issue_summary(api: CorgeaApi, scan_id: str) -> None:
    counts: dict[str, int] = {}
    total = 0
    page = 1
    while True:
        body = api.json_get(
            f"/scan/{scan_id}/issues",
            query={"page": str(page), "page_size": str(ISSUE_PAGE_SIZE)},
        )
        issues = body.get("issues") or []
        for issue in issues:
            counts[issue.get("urgency", "?")] = counts.get(issue.get("urgency", "?"), 0) + 1
            total += 1
        if page >= int(body.get("total_pages") or 1) or not issues:
            break
        page += 1

    print("\nScan Results:\n")
    print(f"{'Classification':<20} | Count")
    print(f"{'':-<20} | ")
    for urgency in URGENCY_ORDER:
        print(f"{urgency:<20} | {counts.get(urgency, 0)}")
    print(f"{'':-<20} | ")
    print(f"{'Total':<20} | {total}")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload a Checkmarx report to Corgea via the HTTP API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s checkmarx_report.xml\n"
            "  %(prog)s cx_results.json --project-name payments-api --wait\n"
        ),
    )
    parser.add_argument("report", help="Checkmarx report: CxXMLResults XML, or CLI/web JSON")
    parser.add_argument(
        "--project-name",
        help="Corgea project. Defaults to the git repo name, else the source root's name.",
    )
    parser.add_argument(
        "--source-root",
        default=".",
        type=Path,
        help="Directory the report's file paths are relative to (default: current directory).",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Poll until the scan completes and print an issue summary.",
    )
    parser.add_argument(
        "--allow-missing-files",
        action="store_true",
        help="Warn instead of failing when a referenced source file is absent.",
    )
    parser.add_argument("--url", help="Corgea base URL (default: $CORGEA_URL or the CLI config).")
    parser.add_argument("--token", help="Corgea token (default: $CORGEA_TOKEN or the CLI config).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    report_path = Path(args.report)
    if not report_path.is_file():
        raise CorgeaError(f"Report not found: {report_path}")
    # A BOM would break both the XML declaration check and json.loads.
    report = report_path.read_text(encoding="utf-8-sig").strip()

    paths = parse_report(report)
    if not paths:
        print("No findings in the report, nothing to upload.")
        return 0

    root = args.source_root
    api = CorgeaApi(resolve_url(args.url), resolve_token(args.token))
    run_id = str(uuid.uuid4())

    verify_token(api)

    project = determine_project_name(args.project_name, root)
    in_ci, platform, project = ci_context(project, dict(os.environ))

    print(f"Uploading {len(set(paths))} source file(s) referenced by the report...")
    if upload_source_files(api, run_id, paths, root, args.allow_missing_files) == 0:
        raise CorgeaError("No source files were uploaded; Corgea cannot analyze the findings.")

    print(f"Uploading the report as project '{project}' (engine={ENGINE})...")
    scan_id, project_id = upload_report(api, run_id, report, project, in_ci, platform)
    upload_git_config(api, run_id, root)

    url = scan_url(api.base_url, scan_id, project_id, project)
    print(f"\nScan {scan_id} created.\n{url}")

    if args.wait:
        print("\nWaiting for the scan to complete...")
        wait_for_scan(api, scan_id)
        print_issue_summary(api, scan_id)
        print(f"\n{url}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CorgeaError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
