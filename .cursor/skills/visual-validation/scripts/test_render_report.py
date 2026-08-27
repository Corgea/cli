#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib


MODULE_PATH = Path(__file__).with_name("render_report.py")
SPEC = importlib.util.spec_from_file_location("render_report", MODULE_PATH)
assert SPEC and SPEC.loader
render_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render_report)


def png(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    row = b"\x00" + bytes(rgb) * width
    raw = row * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def manifest(scenarios: list[dict]) -> dict:
    return {
        "schemaVersion": 1,
        "applicable": True,
        "reason": "A <script>alert('reason')</script> visual change",
        "status": "final-captured",
        "task": {
            "name": "Profile <script>alert('title')</script>",
            "repo": "example/repo",
            "branch": "feature/profile",
            "sha": "abc123",
            "plan": "plan.md",
            "validationDate": "2026-07-22",
            "verdict": "PASS",
        },
        "scenarios": scenarios,
        "checks": [{"command": "npm test", "status": "pass", "note": "42 passed"}],
        "blockingFindings": [],
    }


def scenario(before: str | None = "before.png", after: str = "after.png") -> dict:
    return {
        "id": "profile-form",
        "title": "Profile form",
        "expectedChange": "Long names do not clip",
        "route": "http://localhost:3000/profile",
        "setup": "Seeded user",
        "actions": ["Enter a long name", "Save"],
        "capturePoint": "Success message visible",
        "readyState": "Profile updated",
        "viewport": {"width": 1440, "height": 900},
        "problem": None,
        "before": {"path": before, "caption": "Before"} if before else None,
        "after": {"path": after, "caption": "After"},
        "beforeUnavailableReason": "New screen" if not before else None,
        "designs": [],
        "observations": ["Expected result is visible"],
    }


class RenderReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.template = MODULE_PATH.parent.parent / "assets" / "report-template.html"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, value: dict) -> Path:
        path = self.root / "manifest.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def write_images(self, before_size: tuple[int, int] = (2, 2), after_size: tuple[int, int] = (2, 2)) -> None:
        (self.root / "before.png").write_bytes(png(*before_size, (180, 40, 40)))
        (self.root / "after.png").write_bytes(png(*after_size, (20, 130, 85)))

    def test_embeds_images_slider_and_escapes_manifest_text(self) -> None:
        self.write_images()
        report = render_report.render_report(self.write_manifest(manifest([scenario()])), self.template)
        self.assertIn("data:image/png;base64,", report)
        self.assertIn('data-compare', report)
        self.assertIn("Content-Security-Policy", report)
        self.assertNotIn("<script>alert('title')</script>", report)
        self.assertIn("&lt;script&gt;alert(&#x27;title&#x27;)&lt;/script&gt;", report)

    def test_dimension_mismatch_keeps_static_panels_without_slider(self) -> None:
        self.write_images(after_size=(3, 2))
        report = render_report.render_report(self.write_manifest(manifest([scenario()])), self.template)
        self.assertNotIn('<div class="compare" data-compare>', report)
        self.assertIn("Before and after image dimensions differ", report)
        self.assertEqual(report.count("data:image/png;base64,"), 2)

    def test_greenfield_scenario_can_explain_missing_before(self) -> None:
        (self.root / "after.png").write_bytes(png(2, 2, (20, 130, 85)))
        report = render_report.render_report(self.write_manifest(manifest([scenario(before=None)])), self.template)
        self.assertIn("No comparable before state", report)
        self.assertIn("New screen", report)

    def test_missing_after_image_fails(self) -> None:
        self.write_images()
        value = scenario()
        value["after"] = None
        with self.assertRaisesRegex(render_report.ManifestError, "missing required after image"):
            render_report.render_report(self.write_manifest(manifest([value])), self.template)

    def test_more_than_six_scenarios_fails(self) -> None:
        value = [dict(scenario(), id=f"scenario-{index}") for index in range(7)]
        with self.assertRaisesRegex(render_report.ManifestError, "maximum is 6"):
            render_report.render_report(self.write_manifest(manifest(value)), self.template)

    def test_image_path_cannot_escape_manifest_directory(self) -> None:
        (self.root.parent / "outside.png").write_bytes(png(1, 1, (0, 0, 0)))
        (self.root / "after.png").write_bytes(png(1, 1, (0, 0, 0)))
        value = scenario(before="../outside.png")
        with self.assertRaisesRegex(render_report.ManifestError, "escapes manifest directory"):
            render_report.render_report(self.write_manifest(manifest([value])), self.template)

    def test_non_visual_manifest_does_not_render(self) -> None:
        value = manifest([scenario()])
        value["applicable"] = False
        with self.assertRaisesRegex(render_report.ManifestError, "non-visual work"):
            render_report.render_report(self.write_manifest(value), self.template)

    def test_blocking_findings_must_be_strings(self) -> None:
        self.write_images()
        value = manifest([scenario()])
        value["blockingFindings"] = [{"finding": "not uniform"}]
        with self.assertRaisesRegex(render_report.ManifestError, "array of strings"):
            render_report.render_report(self.write_manifest(value), self.template)

    def test_atomic_writer_enforces_size_limit_without_replacing_prior_report(self) -> None:
        output = self.root / "report.html"
        output.write_text("prior", encoding="utf-8")
        original_limit = render_report.MAX_REPORT_BYTES
        render_report.MAX_REPORT_BYTES = 4
        try:
            with self.assertRaisesRegex(render_report.ManifestError, "maximum is 4 bytes"):
                render_report.write_atomic(output, "larger")
        finally:
            render_report.MAX_REPORT_BYTES = original_limit
        self.assertEqual(output.read_text(encoding="utf-8"), "prior")


if __name__ == "__main__":
    unittest.main()
