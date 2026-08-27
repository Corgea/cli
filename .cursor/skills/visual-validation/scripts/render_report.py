#!/usr/bin/env python3
"""Render a bounded, self-contained visual-validation report from a JSON manifest."""

from __future__ import annotations

import argparse
import base64
import html
import json
import mimetypes
import os
from pathlib import Path
import struct
import sys
import tempfile
from typing import Any

MAX_SCENARIOS = 6
MAX_REPORT_BYTES = 20 * 1024 * 1024
ALLOWED_IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}


class ManifestError(ValueError):
    pass


def text(value: Any, fallback: str = "Not recorded") -> str:
    if value is None or value == "":
        value = fallback
    return html.escape(str(value), quote=True)


def resolve_image(manifest_dir: Path, raw_path: str) -> Path:
    candidate = (manifest_dir / raw_path).resolve()
    root = manifest_dir.resolve()
    if candidate != root and root not in candidate.parents:
        raise ManifestError(f"image path escapes manifest directory: {raw_path}")
    if not candidate.is_file():
        raise ManifestError(f"image not found: {raw_path}")
    return candidate


def image_dimensions(data: bytes) -> tuple[int, int] | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        return struct.unpack("<HH", data[6:10])
    if data.startswith(b"\xff\xd8"):
        offset = 2
        while offset + 9 < len(data):
            if data[offset] != 0xFF:
                offset += 1
                continue
            marker = data[offset + 1]
            offset += 2
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                continue
            if offset + 2 > len(data):
                break
            length = struct.unpack(">H", data[offset : offset + 2])[0]
            if length < 2 or offset + length > len(data):
                break
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                height, width = struct.unpack(">HH", data[offset + 3 : offset + 7])
                return width, height
            offset += length
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8X":
            return 1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little")
        if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
            width, height = struct.unpack("<HH", data[26:30])
            return width & 0x3FFF, height & 0x3FFF
        if chunk == b"VP8L" and data[20] == 0x2F:
            bits = int.from_bytes(data[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    return None


def embedded_image(manifest_dir: Path, image: dict[str, Any]) -> dict[str, Any]:
    raw_path = image.get("path")
    if not raw_path:
        raise ManifestError("image entry is missing path")
    path = resolve_image(manifest_dir, raw_path)
    data = path.read_bytes()
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    if mime not in ALLOWED_IMAGE_MIME_TYPES:
        raise ManifestError(f"unsupported image format for evidence: {raw_path}")
    return {
        "src": f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}",
        "caption": image.get("caption") or path.name,
        "source": image.get("source"),
        "dimensions": image_dimensions(data),
    }


def render_figure(label: str, image: dict[str, Any]) -> str:
    source = f" · {text(image['source'])}" if image.get("source") else ""
    return (
        f'<figure><img src="{image["src"]}" alt="{text(label)}">'
        f'<figcaption><strong>{text(label)}</strong>{text(image["caption"])}{source}</figcaption></figure>'
    )


def render_list(items: list[Any]) -> str:
    return "<ul>" + "".join(f"<li>{text(item)}</li>" for item in items) + "</ul>"


def require_string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ManifestError(f"{field} must be an array of strings")
    return value


def render_scenario(manifest_dir: Path, scenario: dict[str, Any]) -> str:
    scenario_id = scenario.get("id")
    if not scenario_id:
        raise ManifestError("scenario is missing id")
    after_raw = scenario.get("after")
    if not isinstance(after_raw, dict) or not after_raw.get("path"):
        raise ManifestError(f"scenario {scenario_id} is missing required after image")
    after = embedded_image(manifest_dir, after_raw)
    evidence: list[tuple[str, dict[str, Any]]] = []
    comparison_before: dict[str, Any] | None = None
    if isinstance(scenario.get("problem"), dict) and scenario["problem"].get("path"):
        problem = embedded_image(manifest_dir, scenario["problem"])
        evidence.append(("Problem", problem))
    if isinstance(scenario.get("before"), dict) and scenario["before"].get("path"):
        comparison_before = embedded_image(manifest_dir, scenario["before"])
        evidence.append(("Before", comparison_before))
    elif evidence:
        comparison_before = evidence[0][1]
    designs = scenario.get("designs") or []
    if not isinstance(designs, list):
        raise ManifestError(f"scenario {scenario_id} designs must be a list")
    for design in designs:
        evidence.append(("Design reference", embedded_image(manifest_dir, design)))
    if not evidence and not scenario.get("beforeUnavailableReason"):
        raise ManifestError(
            f"scenario {scenario_id} needs before/problem/design evidence or beforeUnavailableReason"
        )
    evidence.append(("After", after))

    viewport = scenario.get("viewport") or {}
    actions = require_string_list(scenario.get("actions"), f"scenario {scenario_id} actions")
    details = [
        ("Expected change", scenario.get("expectedChange")),
        ("Route / screen", scenario.get("route")),
        ("Setup", scenario.get("setup")),
        ("Capture point", scenario.get("capturePoint")),
        ("Ready state", scenario.get("readyState")),
        ("Viewport", f"{viewport.get('width', '?')} × {viewport.get('height', '?')}")
    ]
    details_html = "".join(
        f'<div class="detail"><dt>{text(label)}</dt><dd>{text(value)}</dd></div>' for label, value in details
    )
    gallery = "".join(render_figure(label, item) for label, item in evidence)
    actions_html = f'<div class="note"><strong>Actions</strong>{render_list(actions)}</div>' if actions else ""
    observations = require_string_list(
        scenario.get("observations"), f"scenario {scenario_id} observations"
    )
    observations_html = (
        f'<div class="note"><strong>Validation observations</strong>{render_list(observations)}</div>'
        if observations else ""
    )
    unavailable_html = (
        f'<div class="note"><strong>No comparable before state</strong><p>{text(scenario.get("beforeUnavailableReason"))}</p></div>'
        if scenario.get("beforeUnavailableReason") else ""
    )
    slider = ""
    if comparison_before:
        if comparison_before["dimensions"] and comparison_before["dimensions"] == after["dimensions"]:
            slider = (
                '<div class="compare" data-compare><h3>Interactive comparison</h3>'
                f'<div class="compare-stage"><img src="{comparison_before["src"]}" alt="Before">'
                f'<img class="after" src="{after["src"]}" alt="After"></div>'
                '<input type="range" min="0" max="100" value="50" aria-label="Reveal after image"></div>'
            )
        else:
            slider = '<div class="note"><strong>Interactive comparison unavailable</strong><p>Before and after image dimensions differ or could not be detected. Use the static panels above.</p></div>'
    return (
        f'<section class="scenario"><div class="scenario-head"><div><p class="scenario-id">{text(scenario_id)}</p>'
        f'<h2>{text(scenario.get("title"), scenario_id)}</h2></div></div>'
        f'<dl class="details">{details_html}</dl>{actions_html}<div class="gallery">{gallery}</div>'
        f'{slider}{unavailable_html}{observations_html}</section>'
    )


def render_report(manifest_path: Path, template_path: Path) -> str:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if manifest.get("schemaVersion") != 1:
        raise ManifestError("schemaVersion must be 1")
    if manifest.get("applicable") is not True:
        raise ManifestError("cannot render a report for non-visual work")
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ManifestError("manifest must contain at least one scenario")
    if len(scenarios) > MAX_SCENARIOS:
        raise ManifestError(f"manifest has {len(scenarios)} scenarios; maximum is {MAX_SCENARIOS}")
    task = manifest.get("task") or {}
    verdict = str(task.get("verdict") or "PENDING").upper()
    verdict_class = "pass" if verdict == "PASS" else "fail" if verdict == "FAIL" else ""
    scenario_html = "".join(render_scenario(manifest_path.parent, scenario) for scenario in scenarios)
    findings = require_string_list(manifest.get("blockingFindings"), "blockingFindings")
    checks = manifest.get("checks") or []
    if not isinstance(checks, list) or any(not isinstance(item, dict) for item in checks):
        raise ManifestError("checks must be an array of objects")
    for index, item in enumerate(checks):
        if any(not isinstance(item.get(field, ""), str) for field in ("command", "status", "note")):
            raise ManifestError(f"checks[{index}] command, status, and note must be strings")
    findings_html = (
        f'<section class="findings"><strong>Blocking findings</strong>{render_list(findings)}</section>'
        if findings else ""
    )
    checks_html = ""
    if checks:
        check_items = [f"{item.get('command', 'check')} — {item.get('status', 'unknown')}: {item.get('note', '')}" for item in checks]
        checks_html = f'<section class="checks"><strong>Executed checks</strong>{render_list(check_items)}</section>'
    body = (
        '<header><p class="eyebrow">Visual implementation evidence</p>'
        f'<h1>{text(task.get("name"), "Implementation validation")}</h1>'
        f'<p class="lede">{text(manifest.get("reason"), "Before-and-after evidence for user-visible work")}</p>'
        f'<div class="meta"><span class="pill {verdict_class}">{text(verdict)}</span>'
        f'<span class="pill">Branch {text(task.get("branch"))}</span><span class="pill">SHA {text(task.get("sha"))}</span>'
        f'<span class="pill">Validated {text(task.get("validationDate"))}</span></div></header>'
        '<section class="summary">'
        f'<div><strong>{len(scenarios)}</strong><span>visual scenario{"s" if len(scenarios) != 1 else ""}</span></div>'
        f'<div><strong>{len(findings)}</strong><span>blocking finding{"s" if len(findings) != 1 else ""}</span></div>'
        f'<div><strong>{len(checks)}</strong><span>executed check{"s" if len(checks) != 1 else ""}</span></div></section>'
        f'{scenario_html}{findings_html}{checks_html}'
    )
    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read template: {exc}") from exc
    return template.replace("__DOCUMENT_TITLE__", text(f"{task.get('name', 'Implementation')} visual validation")).replace("__REPORT_BODY__", body)


def write_atomic(output: Path, content: str) -> None:
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise ManifestError(
            f"rendered report is {len(encoded)} bytes; maximum is {MAX_REPORT_BYTES} bytes"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
        os.replace(temporary, output)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--template",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "assets" / "report-template.html",
    )
    options = parser.parse_args()
    try:
        report = render_report(options.manifest.resolve(), options.template.resolve())
        write_atomic(options.output.resolve(), report)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(options.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
