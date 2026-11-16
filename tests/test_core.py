"""Unit tests for ExtHawk. Standard library only."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import exthawk  # noqa: E402

LAB = ROOT / "lab" / "extension-vuln"
PATCHED = ROOT / "lab" / "extension-patched"


def _load(testcase: unittest.TestCase, path: Path | str) -> exthawk.Extension:
    ext = exthawk.load_extension(str(path))
    testcase.addCleanup(ext.close)
    return ext


def _varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def _field(num: int, wire: int, payload: bytes) -> bytes:
    if wire == 2:
        return _varint((num << 3) | wire) + _varint(len(payload)) + payload
    return _varint((num << 3) | wire) + payload


def _zip_bytes(root: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(root).as_posix())
    return buf.getvalue()


class ExtensionIdTests(unittest.TestCase):
    def test_known_der_matches_lab_id(self):
        der = base64.b64decode((ROOT / "lab" / "public-key.b64").read_text().strip())
        self.assertEqual(exthawk.extension_id_from_der(der),
                         "nmfikiipecbppmhonpohidnkihhfkhog")

    def test_manifest_key_matches_lab_id(self):
        manifest = json.loads((LAB / "manifest.json").read_text())
        self.assertEqual(exthawk.extension_id_from_key(manifest["key"]),
                         "nmfikiipecbppmhonpohidnkihhfkhog")

    def test_invalid_key_returns_none(self):
        self.assertIsNone(exthawk.extension_id_from_key("not-base64!!"))

    def test_id_is_32_letters_a_to_p(self):
        ext = _load(self, LAB)
        self.assertRegex(ext.id, r"^[a-p]{32}$")


class CrxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.pub = base64.b64decode(
            (ROOT / "lab" / "public-key.b64").read_text().strip())
        self.zip_bytes = _zip_bytes(LAB)

    def tearDown(self):
        self.tmp.cleanup()

    def _crx2(self) -> Path:
        sig = b"\x00" * 256
        data = (b"Cr24" + struct.pack("<I", 2) +
                struct.pack("<I", len(self.pub)) +
                struct.pack("<I", len(sig)) + self.pub + sig + self.zip_bytes)
        path = self.root / "lab.crx"
        path.write_bytes(data)
        return path

    def _crx3(self) -> Path:
        inner = _field(1, 2, self.pub) + _field(2, 2, b"0" * 256)
        header = _field(2, 2, inner)
        data = (b"Cr24" + struct.pack("<I", 3) +
                struct.pack("<I", len(header)) + header + self.zip_bytes)
        path = self.root / "lab3.crx"
        path.write_bytes(data)
        return path

    def test_crx2(self):
        ext = _load(self, self._crx2())
        self.assertEqual(ext.source, "crx")
        self.assertEqual(ext.crx_version, 2)
        self.assertEqual(ext.id, "nmfikiipecbppmhonpohidnkihhfkhog")

    def test_crx3(self):
        ext = _load(self, self._crx3())
        self.assertEqual(ext.source, "crx")
        self.assertEqual(ext.crx_version, 3)
        self.assertEqual(ext.id, "nmfikiipecbppmhonpohidnkihhfkhog")

    def test_bad_magic(self):
        path = self.root / "bad.crx"
        path.write_bytes(b"NOPE" + b"\x00" * 20)
        with self.assertRaises(ValueError):
            exthawk.load_extension(str(path))


class ArchiveSafetyTests(unittest.TestCase):
    def test_zip_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evil.zip"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("../escape.txt", "owned")
                zf.writestr("manifest.json",
                            json.dumps({"manifest_version": 3, "name": "x",
                                        "version": "1"}))
            with self.assertRaises(ValueError):
                exthawk.load_extension(str(path))
            self.assertFalse((Path(tmp).parent / "escape.txt").exists())

    def test_normal_zip_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lab.zip"
            path.write_bytes(_zip_bytes(LAB))
            ext = _load(self, path)
            self.assertEqual(ext.source, "zip")
            self.assertEqual(ext.id, "nmfikiipecbppmhonpohidnkihhfkhog")


class ScanTests(unittest.TestCase):
    def test_vulnerable_lab_is_critical(self):
        ext = _load(self, LAB)
        findings, score, grade = exthawk.analyze(ext)
        rules = {f.rule for f in findings}
        self.assertEqual(grade, "CRITICAL")
        self.assertEqual(score, 100)
        for rule in ("CORR_EXTERNAL_API_COOKIES",
                     "CORR_EXTERNAL_API_SCRIPTING",
                     "CORR_EXTERNAL_SINK_EVAL",
                     "CORR_POSTMESSAGE_HTML",
                     "CORR_WAR_HTML",
                     "MANIFEST_EXTERNAL"):
            self.assertIn(rule, rules)

    def test_patched_lab_is_clean(self):
        ext = _load(self, PATCHED)
        findings, score, grade = exthawk.analyze(ext)
        self.assertEqual(findings, [])
        self.assertEqual(score, 0)
        self.assertEqual(grade, "CLEAN")

    def test_correlation_uses_listener_file(self):
        ext = _load(self, LAB)
        findings, _, _ = exthawk.analyze(ext)
        corr = next(f for f in findings if f.rule == "CORR_POSTMESSAGE_HTML")
        self.assertEqual(corr.file, "content.js")

    def test_correlation_uses_war_file(self):
        ext = _load(self, LAB)
        findings, _, _ = exthawk.analyze(ext)
        corr = next(f for f in findings if f.rule == "CORR_WAR_HTML")
        self.assertEqual(corr.file, "panel.html")

    def test_json_output_shape(self):
        ext = _load(self, LAB)
        findings, score, grade = exthawk.analyze(ext)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            import contextlib
            with path.open("w") as fh, contextlib.redirect_stdout(fh):
                exthawk.print_scan(ext, findings, score, grade, as_json=True)
            data = json.loads(path.read_text())
        self.assertEqual(data["id"], "nmfikiipecbppmhonpohidnkihhfkhog")
        self.assertEqual(data["grade"], "CRITICAL")
        self.assertTrue(data["findings"])
        self.assertEqual(data["summary"]["critical"], 3)


class PayloadTests(unittest.TestCase):
    def test_script_close_is_escaped(self):
        page = exthawk.build_attacker_html(
            "a" * 32,
            {"external": [{"name": "x", "message": {"x": "</script><b>pwn"}}],
             "postMessage": []},
            "http://127.0.0.1:1/cb")
        self.assertNotIn("</script><b>pwn", page)
        self.assertIn("<\\/script>", page)

    def test_evaluate_markers_and_events(self):
        dom = (
            '<html><head><title>ExtHawk</title></head><body>'
            '<div id="exthawk-inject" hidden="">EXTHAWK_INJECT</div>'
            '<div id="exthawk-dom" hidden="">EXTHAWK_DOM</div>'
            '<pre id="out">ping: {"ok":true,"version":"1"}</pre>'
            '</body></html>'
        )
        events = [
            "/cb?ssrf=1",
            "/cb?cookies=" + base64.b64encode(
                json.dumps([{"name": "sid", "value": "x"}]).encode()).decode(),
        ]
        payloads = {
            "external": [
                {"name": "ping", "message": {"action": "ping"}},
                {"name": "cookie-theft", "message": {}},
                {"name": "ssrf", "message": {}},
                {"name": "page-injection", "message": {}},
            ],
            "postMessage": [{"name": "dom-xss", "data": {}}],
        }
        results = {r["name"]: r for r in exthawk.evaluate(payloads, dom, events)}
        self.assertTrue(results["ping"]["confirmed"])
        self.assertTrue(results["cookie-theft"]["confirmed"])
        self.assertIn("sid", results["cookie-theft"]["evidence"])
        self.assertTrue(results["ssrf"]["confirmed"])
        self.assertTrue(results["page-injection"]["confirmed"])
        self.assertTrue(results["dom-xss"]["confirmed"])

    def test_marker_in_payload_source_is_not_enough(self):
        dom = (
            '<html><body><script>const X = "EXTHAWK_INJECT";</script>'
            '<div id="exthawk-inject" hidden=""></div></body></html>'
        )
        payloads = {"external": [{"name": "page-injection", "message": {}}],
                    "postMessage": []}
        results = exthawk.evaluate(payloads, dom, [])
        self.assertFalse(results[0]["confirmed"])

    def test_invalid_payload_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps({"external": "nope"}))
            with self.assertRaises(ValueError):
                exthawk.load_payloads(str(path))


if __name__ == "__main__":
    unittest.main()
