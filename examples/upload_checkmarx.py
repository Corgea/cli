#!/usr/bin/env python3
"""Upload a Checkmarx report to Corgea (same flow as `corgea upload`).

Usage:
    export CORGEA_TOKEN=<token>
    ./upload_checkmarx.py <code_path> <report_path>

Optional env:
    CORGEA_URL   Corgea base URL (default: https://www.corgea.app)
    PROJECT      Project name (default: basename of <code_path>)

Creates the scan and prints the scan URL. Does not wait for it to finish.
Requires only the Python standard library.
"""

from __future__ import annotations

import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_URL = "https://www.corgea.app"


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def auth_headers(token: str) -> dict[str, str]:
    parts = token.split(".", 3)
    if len(parts) == 3 and all(parts):
        headers = {"Authorization": f"Bearer {token}"}
    else:
        headers = {"CORGEA-TOKEN": token}
    headers["CORGEA-SOURCE"] = "cli"
    return headers


def request(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in {**headers, **(extra_headers or {})}.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=150) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        die(f"{method} {url} -> {e.code}: {e.read().decode(errors='replace')}")
    except urllib.error.URLError as e:
        die(f"{method} {url} failed: {e.reason}")


def multipart_file(path: Path) -> tuple[str, bytes]:
    boundary = uuid.uuid4().hex
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        f"Content-Type: {mime}\r\n\r\n"
    ).encode()
    return f"multipart/form-data; boundary={boundary}", head + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()


def extract_paths(report: str) -> list[str]:
    paths: list[str] = []
    if report.startswith("<?xml") and "<CxXMLResults" in report:
        for el in ET.fromstring(report).iter():
            tag = el.tag.rpartition("}")[2]
            if tag == "Result" and el.get("FileName"):
                paths.append(el.get("FileName", "").lstrip("/\\"))
            elif tag == "FileName" and (el.text or "").strip():
                paths.append(el.text.strip().lstrip("/\\"))
    else:
        data = json.loads(report)
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
            die("unrecognized Checkmarx report format")

    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def main() -> None:
    if len(sys.argv) != 3:
        die(f"usage: {sys.argv[0]} <code_path> <report_path>", code=2)

    code_path = Path(sys.argv[1]).resolve()
    report_path = Path(sys.argv[2]).resolve()
    if not report_path.is_file():
        die(f"report not found: {report_path}")

    token = os.environ.get("CORGEA_TOKEN")
    if not token:
        die("set CORGEA_TOKEN")
    base = os.environ.get("CORGEA_URL", DEFAULT_URL).rstrip("/")
    project = os.environ.get("PROJECT", code_path.name)
    project = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in project)
    run_id = str(uuid.uuid4())
    api = f"{base}/api/v1"
    headers = auth_headers(token)

    report = report_path.read_text(encoding="utf-8-sig").strip()
    paths = extract_paths(report)
    if not paths:
        print("no findings in report, nothing to upload")
        return

    request("GET", f"{api}/verify", headers)

    print(f"Uploading {len(paths)} source file(s) from {code_path}...")
    for rel in paths:
        file = code_path / rel
        if not file.is_file():
            die(f"{rel} referenced by the report but missing under {code_path}")
        ctype, body = multipart_file(file)
        # Same as the CLI: path is passed raw in the query string.
        url = f"{api}/code-upload?run_id={run_id}&path={rel}"
        request("POST", url, headers, data=body, extra_headers={"Content-Type": ctype})
        print(f"  {rel}")

    print(f"Uploading report as project '{project}'...")
    qs = urllib.parse.urlencode(
        {
            "engine": "checkmarx",
            "run_id": run_id,
            "project": project,
            "ci": "false",
            "ci_platform": "unknown",
        }
    )
    resp = request(
        "POST",
        f"{api}/scan-upload?{qs}",
        headers,
        data=report.encode("utf-8"),
        extra_headers={"Content-Type": "application/json"},
    )
    data = json.loads(resp)
    scan_id = str(data["sast_scan_id"])
    project_id = data.get("project_id")

    git_config = code_path / ".git" / "config"
    if git_config.is_file():
        ctype, body = multipart_file(git_config)
        req = urllib.request.Request(
            f"{api}/git-config-upload?run_id={run_id}",
            data=body,
            method="POST",
        )
        for k, v in {**headers, "Content-Type": ctype}.items():
            req.add_header(k, v)
        try:
            urllib.request.urlopen(req, timeout=150).read()
        except urllib.error.URLError:
            pass

    print(f"Scan {scan_id} created.")
    if project_id is not None:
        print(f"{base}/project/{project_id}/?scan_id={scan_id}")
    else:
        print(f"{base}/project/{urllib.parse.quote(project, safe='')}?scan_id={scan_id}")


if __name__ == "__main__":
    main()
