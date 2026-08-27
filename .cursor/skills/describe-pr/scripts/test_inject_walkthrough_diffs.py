#!/usr/bin/env python3

from __future__ import annotations

import base64
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


WRAPPER = Path(__file__).with_name("inject-walkthrough-diffs.sh")
TEMPLATE = Path(__file__).parent.parent / "references" / "pr_walkthrough_example.html"


class InjectWalkthroughDiffsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.command("git", "init", "-q")
        self.command("git", "config", "user.name", "Walkthrough Test")
        self.command("git", "config", "user.email", "walkthrough@example.invalid")
        (self.root / "payload.txt").write_text("before\n", encoding="utf-8")
        self.command("git", "add", "--", "payload.txt")
        self.command("git", "commit", "-qm", "base")
        (self.root / "payload.txt").write_text(
            "before\n</ScRiPt><script>alert('not executable')</script>\nafter\n",
            encoding="utf-8",
        )
        self.command("git", "add", "--", "payload.txt")
        self.command("git", "commit", "-qm", "change payload")
        self.walkthrough = self.root / "walkthrough.html"
        self.walkthrough.write_text(
            '<!doctype html>\n<div id="diffs" hidden>\n</div>\n'
            '<script>const NODES = [{ diffFile: "payload.txt" }];</script>\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self, *command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def inject(self) -> str:
        result = self.command(
            str(WRAPPER),
            str(self.walkthrough),
            str(self.root),
            "--range",
            "HEAD~1...HEAD",
        )
        self.assertIn("injected 1/1", result.stdout)
        return self.walkthrough.read_text(encoding="utf-8")

    def test_mixed_case_script_close_is_base64_encoded_and_round_trips(self) -> None:
        rendered = self.inject()
        self.assertNotIn("</ScRiPt>", rendered)
        match = re.search(
            r'data-diff="payload\.txt" data-encoding="base64">([A-Za-z0-9+/=]+)</script>',
            rendered,
        )
        self.assertIsNotNone(match)
        decoded = base64.b64decode(match.group(1)).decode("utf-8")
        self.assertIn("</ScRiPt><script>alert('not executable')</script>", decoded)

        reinjected = self.inject()
        self.assertEqual(rendered, reinjected)
        self.assertEqual(reinjected.count("inject-walkthrough-diffs:start"), 1)

    def test_bundled_template_ignores_commented_examples_and_updates_live_stash(self) -> None:
        document = TEMPLATE.read_text(encoding="utf-8")
        for placeholder in (
            "path/to/new-file.ts",
            "path/to/rewritten-file.ts",
            "path/to/modified-file.ts",
            "path/to/deleted-file.ts",
        ):
            document = document.replace(placeholder, "payload.txt")
        self.walkthrough.write_text(document, encoding="utf-8")

        live_open = '<div id="diffs" hidden>'
        prefix_before, tail_before = document.rsplit(live_open, 1)
        suffix_before = tail_before.split("</div>", 1)[1]
        rendered = self.inject()
        prefix_after, live_tail = rendered.rsplit(live_open, 1)
        live_stash, suffix_after = live_tail.split("</div>", 1)

        self.assertEqual(prefix_after, prefix_before)
        self.assertEqual(suffix_after, suffix_before)
        self.assertIn('data-diff="payload.txt" data-encoding="base64"', live_stash)
        self.assertNotIn('data-diff="path/to/x.ts"', live_stash)
        self.assertNotIn('data-diff="path/to/file.ts"', live_stash)
        self.assertEqual(live_stash.count("data-encoding=\"base64\""), 1)

    def test_pathspec_magic_filename_is_treated_as_one_literal_path(self) -> None:
        literal_path = ":(glob)**"
        unrelated_path = "unrelated.txt"
        (self.root / literal_path).write_text("literal before\n", encoding="utf-8")
        (self.root / unrelated_path).write_text("unrelated before\n", encoding="utf-8")
        self.command("git", "--literal-pathspecs", "add", "--", literal_path, unrelated_path)
        self.command("git", "commit", "-qm", "add literal path fixture")

        (self.root / literal_path).write_text("literal after\n", encoding="utf-8")
        (self.root / unrelated_path).write_text("unrelated after\n", encoding="utf-8")
        self.command("git", "--literal-pathspecs", "add", "--", literal_path, unrelated_path)
        self.command("git", "commit", "-qm", "change literal path fixture")
        self.walkthrough.write_text(
            '<!doctype html>\n<div id="diffs" hidden>\n</div>\n'
            f'<script>const NODES = [{{ diffFile: "{literal_path}" }}];</script>\n',
            encoding="utf-8",
        )

        rendered = self.inject()
        match = re.search(
            r'data-diff=":\(glob\)\*\*" data-encoding="base64">([A-Za-z0-9+/=]+)</script>',
            rendered,
        )
        self.assertIsNotNone(match)
        decoded = base64.b64decode(match.group(1)).decode("utf-8")
        self.assertIn("literal after", decoded)
        self.assertIn(literal_path, decoded)
        self.assertNotIn(unrelated_path, decoded)
        self.assertNotIn("unrelated after", decoded)


if __name__ == "__main__":
    unittest.main()
