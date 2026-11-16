"""Integration tests for ExtHawk's real Chromium harness.

These tests need a Chromium build that honors --load-extension. Set
CHROME_BIN to that binary. Set EXTHAWK_SKIP_DYNAMIC=1 to skip them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import exthawk  # noqa: E402

LAB = ROOT / "lab" / "extension-vuln"
PATCHED = ROOT / "lab" / "extension-patched"
PAYLOADS = ROOT / "lab" / "payloads.json"
TOOL = ROOT / "exthawk.py"


def _chrome() -> str | None:
    if os.environ.get("EXTHAWK_SKIP_DYNAMIC"):
        return None
    chrome = exthawk.find_chrome()
    if not chrome or exthawk.chrome_load_warning(chrome):
        return None
    return chrome


CHROME = _chrome()
SKIP = "no Chromium with --load-extension support"


def _run(*args: str, timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))


@unittest.skipUnless(CHROME, SKIP)
class DynamicExploitTests(unittest.TestCase):
    def test_vulnerable_lab_confirms_all_payloads(self):
        proc = _run("exploit", "-e", str(LAB), "--payloads", str(PAYLOADS),
                    "--chrome", CHROME or "", "--timeout", "25", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(sorted(data["confirmed"]),
                         ["cookie-theft", "dom-xss", "page-injection",
                          "ping", "ssrf"])
        for result in data["results"]:
            self.assertTrue(result["confirmed"], result)

    def test_patched_lab_confirms_nothing(self):
        proc = _run("exploit", "-e", str(PATCHED), "--payloads", str(PAYLOADS),
                    "--chrome", CHROME or "", "--timeout", "25", "--json")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["confirmed"], [])


class StaticCliTests(unittest.TestCase):
    def test_scan_json_cli(self):
        proc = _run("scan", "-e", str(LAB), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["grade"], "CRITICAL")
        self.assertEqual(data["id"], "nmfikiipecbppmhonpohidnkihhfkhog")

    def test_fail_on_gate(self):
        vuln = _run("scan", "-e", str(LAB), "--fail-on", "critical")
        clean = _run("scan", "-e", str(PATCHED), "--fail-on", "critical")
        self.assertEqual(vuln.returncode, 1)
        self.assertEqual(clean.returncode, 0)

    def test_poc_writes_standalone_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "poc"
            proc = _run("poc", "-e", str(LAB), "--payloads", str(PAYLOADS),
                        "--out", str(out))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            for name in ("attacker.html", "payloads.json", "run.py",
                         "run.sh", "README.md"):
                self.assertTrue((out / name).is_file(), name)
            self.assertTrue((out / "extension" / "manifest.json").is_file())
            self.assertIn("__EXTHAWK_CALLBACK__",
                          (out / "attacker.html").read_text())


if __name__ == "__main__":
    unittest.main()
