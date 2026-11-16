#!/usr/bin/env python3
"""ExtHawk - attack-surface scanner and exploit harness for browser extensions.

Reads an unpacked extension or a .crx, maps the manifest and the code, computes
the extension id, and can prove exploitability by loading the extension in
headless Chromium and sending real messages from a web page.

Standard library only. Dynamic mode needs Chromium or Chrome for Testing with
--load-extension support.

Authorized testing only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

__version__ = "0.1.0"
TOOL = "ExtHawk"
TAGLINE = "browser extension attack surface"
UA = f"{TOOL}/{__version__}"

# --------------------------------------------------------------------------
# terminal
# --------------------------------------------------------------------------
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def cyan(t: str) -> str:
    return _c("36", t)


def violet(t: str) -> str:
    return _c("35", t)


def red(t: str) -> str:
    return _c("31", t)


def amber(t: str) -> str:
    return _c("33", t)


def green(t: str) -> str:
    return _c("32", t)


def log(msg: str) -> None:
    sys.stderr.write(msg + "\n")


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"critical": 40, "high": 18, "medium": 7, "low": 2, "info": 0}
SEV_COLOR = {"critical": red, "high": amber, "medium": violet,
             "low": cyan, "info": dim}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str
    why: str
    fix: str
    confidence: str = "potential"

    def key(self) -> tuple:
        return (self.rule, self.file, self.line, self.title)


@dataclass
class Rule:
    rule: str
    severity: str
    title: str
    pattern: str
    why: str
    fix: str
    flags: int = re.IGNORECASE


RULES = [
    Rule("EXT_MSG_EXTERNAL", "high", "External message handler",
         r"\bonMessageExternal\b|\bonConnectExternal\b",
         "The extension accepts messages from web pages or other extensions.",
         "Validate sender.origin and sender.id, or remove externally_connectable."),
    Rule("SINK_EVAL", "high", "Dynamic code evaluation",
         r"\beval\s*\(|\bnew\s+Function\s*\(",
         "A string is turned into code. If a message reaches it, the sender controls execution.",
         "Remove eval/new Function. Use a fixed function and structured arguments."),
    Rule("SINK_INNERHTML", "medium", "HTML sink",
         r"\.innerHTML\s*=(?!=)|insertAdjacentHTML\s*\(|document\.write\s*\(",
         "Markup is written into the DOM. Unsanitized input becomes DOM XSS.",
         "Use textContent or a sanitizer such as DOMPurify."),
    Rule("SINK_OUTERHTML", "medium", "HTML sink (outerHTML)",
         r"\.outerHTML\s*=(?!=)",
         "Markup is written into the DOM. Unsanitized input becomes DOM XSS.",
         "Use textContent or a sanitizer such as DOMPurify."),
    Rule("SINK_POSTMESSAGE", "medium", "postMessage with wildcard origin",
         r"postMessage\s*\([^;]*?,\s*['\"]\*['\"]",
         "A message is sent to any origin. A hostile frame can read it.",
         "Use an explicit target origin and check event.origin on the receiver."),
    Rule("MSG_LISTENER", "medium", "Window message listener",
         r"addEventListener\s*\(\s*['\"]message['\"]|\.onmessage\s*=",
         "The page accepts window messages. Without an origin check, any frame can send them.",
         "Check event.origin and event.source before using the data."),
    Rule("API_COOKIES", "high", "Cookie access",
         r"chrome\.cookies\.",
         "The extension can read cookies for every host it can access.",
         "Request only the hosts you need, and never send cookies to a page-supplied URL."),
    Rule("API_SCRIPTING", "high", "Script injection into pages",
         r"chrome\.scripting\.executeScript|chrome\.tabs\.executeScript",
         "The extension can run code in a tab. A message-driven path turns that into page compromise.",
         "Never pass message data into injected code; validate the target tab and the caller."),
    Rule("API_DEBUGGER", "high", "Debugger API",
         r"chrome\.debugger\.",
         "The debugger API can read and modify any tab, including authenticated sessions.",
         "Remove the debugger permission unless it is the core product feature."),
    Rule("API_NATIVE", "high", "Native messaging",
         r"\bconnectNative\b|\bsendNativeMessage\b",
         "Native messaging launches a local process outside the browser sandbox.",
         "Validate the native host name and every message before it reaches the host."),
    Rule("API_DOWNLOADS", "medium", "Download API",
         r"chrome\.downloads\.",
         "The extension can write files to the user's download directory.",
         "Constrain URLs and filenames; never let a message choose the target."),
    Rule("API_WEBREQUEST", "medium", "Request interception",
         r"chrome\.webRequest\.|declarativeNetRequest",
         "The extension can observe or rewrite HTTP traffic.",
         "Limit the URL patterns and never forward credentials to third parties."),
    Rule("API_HISTORY", "medium", "History access",
         r"chrome\.history\.",
         "Browsing history is sensitive and can be used for profiling.",
         "Remove the history permission unless it is essential."),
    Rule("API_MANAGEMENT", "medium", "Extension management",
         r"chrome\.management\.",
         "The extension can enumerate, enable, or disable other extensions.",
         "Remove the management permission unless it is essential."),
    Rule("API_PROXY", "high", "Proxy control",
         r"chrome\.proxy\.",
         "The extension can route traffic through an attacker-controlled proxy.",
         "Remove the proxy permission; if required, pin the proxy configuration."),
    Rule("API_TABS", "low", "Tab metadata access",
         r"chrome\.tabs\.",
         "Tab URLs and titles are visible with the tabs permission.",
         "Use activeTab instead of broad tabs access where possible."),
    Rule("SECRET_AWS", "high", "AWS access key",
         r"AKIA[0-9A-Z]{16}",
         "A long-lived AWS key in extension code is readable by anyone who unpacks it.",
         "Revoke the key and move signing to a backend."),
    Rule("SECRET_GOOGLE", "high", "Google API key",
         r"AIza[0-9A-Za-z_\-]{35}",
         "An API key in client code is public. Restrict it by referrer and API.",
         "Restrict the key, or move the call behind your backend."),
    Rule("SECRET_GITHUB", "high", "GitHub token",
         r"gh[pousr]_[A-Za-z0-9]{36,}",
         "A GitHub token in an extension can be lifted from the package.",
         "Revoke the token and never ship one in client code."),
    Rule("SECRET_SLACK", "high", "Slack token",
         r"xox[abprs]-[A-Za-z0-9-]{10,}",
         "A Slack token gives access to the workspace it was issued for.",
         "Revoke the token and use a backend with scoped credentials."),
    Rule("SECRET_STRIPE", "high", "Stripe live key",
         r"sk_live_[0-9a-zA-Z]{24,}",
         "A live Stripe secret key can move money.",
         "Revoke the key immediately and rotate it."),
    Rule("SECRET_JWT", "medium", "Embedded JWT",
         r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
         "A JWT in the package may still be valid and may carry broad scopes.",
         "Treat it as public, rotate it, and use short-lived tokens."),
    Rule("SECRET_PRIVATE_KEY", "high", "Private key",
         r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
         "A private key in a distributed extension is compromised.",
         "Revoke the key pair and generate a new one."),
    Rule("REMOTE_SCRIPT", "high", "Remote script",
         r"<script[^>]+src\s*=\s*['\"]https?://",
         "Remote code breaks the review boundary and can change after install.",
         "Ship the code in the package and use a strict CSP."),
    Rule("REMOTE_IMPORT", "high", "Remote importScripts",
         r"importScripts\s*\(\s*['\"]https?://",
         "A service worker that imports remote code can be rewritten by the host.",
         "Bundle the dependency and load it locally."),
]

_COMPILED = [(r, re.compile(r.pattern, r.flags)) for r in RULES]


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 12:
        return value[:2] + "..."
    return value[:4] + "..." + value[-4:]


# --------------------------------------------------------------------------
# extension loading
# --------------------------------------------------------------------------
def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _pb_fields(buf: bytes):
    i = 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        field_no, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _read_varint(buf, i)
            yield field_no, wire, value
        elif wire == 2:
            length, i = _read_varint(buf, i)
            value = buf[i:i + length]
            i += length
            yield field_no, wire, value
        elif wire == 1:
            i += 8
            yield field_no, wire, None
        elif wire == 5:
            i += 4
            yield field_no, wire, None
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")


def _crx3_pubkey(header: bytes) -> Optional[bytes]:
    """Return the first public key in a CRX3 CrxFileHeader protobuf."""
    for field_no, wire, value in _pb_fields(header):
        if field_no in (2, 3) and wire == 2 and value:
            for inner_no, inner_wire, inner in _pb_fields(value):
                if inner_no == 1 and inner_wire == 2 and inner:
                    return inner
    return None


def parse_crx(path: Path) -> tuple[bytes, Optional[bytes], int]:
    data = path.read_bytes()
    if data[:4] != b"Cr24":
        raise ValueError("not a CRX file (missing Cr24 magic)")
    version = int.from_bytes(data[4:8], "little")
    if version == 2:
        if len(data) < 16:
            raise ValueError("truncated CRX2 header")
        key_len = int.from_bytes(data[8:12], "little")
        sig_len = int.from_bytes(data[12:16], "little")
        pubkey = data[16:16 + key_len]
        zip_start = 16 + key_len + sig_len
        return data[zip_start:], pubkey or None, 2
    if version == 3:
        if len(data) < 12:
            raise ValueError("truncated CRX3 header")
        header_len = int.from_bytes(data[8:12], "little")
        header = data[12:12 + header_len]
        zip_start = 12 + header_len
        return data[zip_start:], _crx3_pubkey(header), 3
    raise ValueError(f"unsupported CRX version {version}")


def extension_id_from_der(der: bytes) -> str:
    digest = hashlib.sha256(der).digest()[:16]
    alphabet = "abcdefghijklmnop"
    return "".join(alphabet[b >> 4] + alphabet[b & 0x0F] for b in digest)


def _safe_extract(zf: zipfile.ZipFile, root: Path,
                  max_bytes: int = 200 * 1024 * 1024,
                  max_entries: int = 20000) -> None:
    """Extract an archive without allowing path traversal or zip bombs."""
    root_resolved = root.resolve()
    total = 0
    for count, info in enumerate(zf.infolist(), 1):
        if count > max_entries:
            raise ValueError("archive has too many entries")
        name = info.filename
        if not name or name.startswith(("/", "\\")):
            raise ValueError(f"unsafe archive path: {name!r}")
        target = (root / name).resolve()
        try:
            target.relative_to(root_resolved)
        except ValueError:
            raise ValueError(f"archive path escapes the extension root: {name!r}") from None
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        total += info.file_size
        if total > max_bytes:
            raise ValueError("archive is too large after extraction")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)


def extension_id_from_key(key_b64: str) -> Optional[str]:
    try:
        der = base64.b64decode(key_b64, validate=True)
    except Exception:
        return None
    if not der:
        return None
    return extension_id_from_der(der)


@dataclass
class Extension:
    root: Path
    manifest: dict
    manifest_raw: str
    source: str
    source_path: str = ""
    id: Optional[str] = None
    crx_version: Optional[int] = None
    _temp: Any = field(default=None, repr=False)

    def close(self) -> None:
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None

    def __enter__(self) -> "Extension":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @property
    def name(self) -> str:
        return str(self.manifest.get("name") or "(unnamed)")

    @property
    def version(self) -> str:
        return str(self.manifest.get("version") or "?")

    @property
    def mv(self) -> str:
        return f"MV{self.manifest.get('manifest_version', '?')}"


def load_extension(path: str, explicit_id: Optional[str] = None) -> Extension:
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"no such extension: {path}")
    source_path = str(p.resolve())

    temp = None
    crx_version = None
    source = "directory"
    pubkey = None

    try:
        if p.is_dir():
            root = p.resolve()
        elif p.suffix.lower() in (".crx", ".zip"):
            temp = tempfile.TemporaryDirectory(prefix="exthawk-ext-")
            root = Path(temp.name)
            if p.suffix.lower() == ".crx":
                source = "crx"
                zip_bytes, pubkey, crx_version = parse_crx(p)
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    _safe_extract(zf, root)
            else:
                source = "zip"
                with zipfile.ZipFile(p) as zf:
                    _safe_extract(zf, root)
        else:
            raise ValueError("extension must be a directory, .crx, or .zip")

        manifest_path = root / "manifest.json"
        if not manifest_path.exists():
            raise ValueError("no manifest.json in the extension root")
        raw = manifest_path.read_text(encoding="utf-8", errors="replace")
        try:
            manifest = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid manifest.json: {exc}") from exc
        if not isinstance(manifest, dict):
            raise ValueError("manifest.json is not an object")

        ext_id = explicit_id
        if not ext_id:
            key = manifest.get("key")
            if isinstance(key, str):
                ext_id = extension_id_from_key(key)
        if not ext_id and pubkey:
            ext_id = extension_id_from_der(pubkey)

        return Extension(root=root, manifest=manifest, manifest_raw=raw,
                         source=source, source_path=source_path, id=ext_id,
                         crx_version=crx_version, _temp=temp)
    except Exception:
        if temp is not None:
            temp.cleanup()
        raise


def walk_files(root: Path):
    skip = {".git", "node_modules", "__pycache__", ".svn"}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            p = Path(base) / name
            if p.suffix.lower() in (".js", ".mjs", ".cjs", ".html", ".htm",
                                    ".json", ".css", ".ts"):
                yield p


def rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------
# static analysis
# --------------------------------------------------------------------------
def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _manifest_finding(rule: str, severity: str, title: str, evidence: str,
                      why: str, fix: str, line: int = 1) -> Finding:
    return Finding(rule=rule, severity=severity, title=title,
                   file="manifest.json", line=line, evidence=evidence,
                   why=why, fix=fix)


def scan_manifest(ext: Extension) -> list[Finding]:
    m = ext.manifest
    raw = ext.manifest_raw
    out: list[Finding] = []

    perms = [p for p in (m.get("permissions") or []) if isinstance(p, str)]
    hosts = [p for p in (m.get("host_permissions") or []) if isinstance(p, str)]
    mv2_hosts = [p for p in perms if "://" in p or p == "<all_urls>"]
    all_urls = any(p in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")
                   for p in hosts + mv2_hosts)

    if all_urls:
        out.append(_manifest_finding(
            "MANIFEST_ALL_URLS", "high", "All-site host access",
            "host_permissions includes <all_urls> or *://*/*",
            "The extension can read and modify every site the user visits.",
            "Request only the origins the product needs.",
            _line_of(raw, "host_permissions")))

    if "cookies" in perms:
        out.append(_manifest_finding(
            "MANIFEST_COOKIES", "high", "Cookie permission",
            "permissions includes cookies",
            "Session cookies for every permitted host are readable.",
            "Drop the cookies permission unless it is the core feature.",
            _line_of(raw, "cookies")))

    if "scripting" in perms:
        out.append(_manifest_finding(
            "MANIFEST_SCRIPTING", "high", "Scripting permission",
            "permissions includes scripting",
            "The extension can inject code into pages.",
            "Use activeTab and a fixed function; never inject message data.",
            _line_of(raw, "scripting")))

    if "debugger" in perms:
        out.append(_manifest_finding(
            "MANIFEST_DEBUGGER", "high", "Debugger permission",
            "permissions includes debugger",
            "The extension can attach to tabs and read or modify traffic.",
            "Remove the debugger permission unless it is essential.",
            _line_of(raw, "debugger")))

    if "nativeMessaging" in perms:
        out.append(_manifest_finding(
            "MANIFEST_NATIVE", "high", "Native messaging permission",
            "permissions includes nativeMessaging",
            "Messages can reach a local process outside the browser sandbox.",
            "Validate every message and the native host name.",
            _line_of(raw, "nativeMessaging")))

    if "proxy" in perms:
        out.append(_manifest_finding(
            "MANIFEST_PROXY", "high", "Proxy permission",
            "permissions includes proxy",
            "Traffic can be routed through a host chosen by the extension.",
            "Remove the proxy permission; pin the configuration if required.",
            _line_of(raw, "proxy")))

    for perm, sev, title, why in (
        ("downloads", "medium", "Download permission",
         "The extension can write files to the download directory."),
        ("webRequest", "medium", "WebRequest permission",
         "The extension can observe or rewrite HTTP traffic."),
        ("declarativeNetRequest", "medium", "DeclarativeNetRequest permission",
         "The extension can rewrite requests and responses."),
        ("history", "medium", "History permission",
         "Browsing history is readable."),
        ("management", "medium", "Management permission",
         "Other extensions can be enumerated or disabled."),
        ("tabs", "low", "Tabs permission",
         "Tab URLs and titles are readable."),
    ):
        if perm in perms:
            out.append(_manifest_finding(
                "MANIFEST_" + perm.upper(), sev, title,
                f"permissions includes {perm}", why,
                "Use the narrowest permission that still ships the feature.",
                _line_of(raw, perm)))

    ec = m.get("externally_connectable")
    if isinstance(ec, dict):
        matches = [x for x in (ec.get("matches") or []) if isinstance(x, str)]
        if matches:
            out.append(_manifest_finding(
                "MANIFEST_EXTERNAL", "high", "Web pages can message this extension",
                "externally_connectable.matches = " + ", ".join(matches[:4]),
                "Any page matching those patterns can call the external message handlers.",
                "Remove externally_connectable, or restrict it to one origin you control.",
                _line_of(raw, "externally_connectable")))
        ids = [x for x in (ec.get("ids") or []) if isinstance(x, str)]
        if ids and not matches:
            out.append(_manifest_finding(
                "MANIFEST_EXTERNAL_IDS", "info", "Other extensions can message this extension",
                "externally_connectable.ids = " + ", ".join(ids[:4]),
                "Only the listed extension ids can connect.", "Keep the list short and audited.",
                _line_of(raw, "externally_connectable")))

    content = m.get("content_scripts") or []
    if isinstance(content, list):
        for cs in content:
            if not isinstance(cs, dict):
                continue
            matches = [x for x in (cs.get("matches") or []) if isinstance(x, str)]
            if any(x in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")
                   for x in matches):
                out.append(_manifest_finding(
                    "MANIFEST_CONTENT_ALL", "medium", "Content script on every page",
                    "content_scripts.matches includes <all_urls>",
                    "The script runs in every page and sees every DOM it touches.",
                    "Restrict matches to the sites the product actually supports.",
                    _line_of(raw, "content_scripts")))
                break

    war = m.get("web_accessible_resources") or []
    if war:
        resources: list[str] = []
        if isinstance(war, list):
            for item in war:
                if isinstance(item, str):
                    resources.append(item)
                elif isinstance(item, dict):
                    resources.extend(str(x) for x in (item.get("resources") or []))
        if resources:
            sev = "medium" if any(r.lower().endswith((".html", ".htm")) for r in resources) else "low"
            out.append(_manifest_finding(
                "MANIFEST_WAR", sev, "Web-accessible resources",
                "resources = " + ", ".join(resources[:5]),
                "Any matching page can load these files. HTML resources are a DOM XSS surface.",
                "Expose only the files a page must load, and keep them free of DOM sinks.",
                _line_of(raw, "web_accessible_resources")))

    csp = m.get("content_security_policy")
    if not csp:
        out.append(_manifest_finding(
            "MANIFEST_NO_CSP", "low", "No explicit extension CSP",
            "content_security_policy is absent",
            "The default policy is safer than a permissive one, but an explicit policy is easier to review.",
            "Set a strict extension_pages CSP.",
            _line_of(raw, "manifest_version")))
    else:
        blob = json.dumps(csp).lower()
        if "unsafe-eval" in blob or "unsafe-inline" in blob:
            out.append(_manifest_finding(
                "MANIFEST_WEAK_CSP", "high", "Weak extension CSP",
                "content_security_policy allows unsafe-eval or unsafe-inline",
                "The policy defeats the main defense against injected code.",
                "Remove unsafe-eval and unsafe-inline.",
                _line_of(raw, "content_security_policy")))

    update = m.get("update_url")
    if isinstance(update, str) and update.lower().startswith("http://"):
        out.append(_manifest_finding(
            "MANIFEST_UPDATE_HTTP", "medium", "Insecure update URL",
            "update_url = " + update,
            "An HTTP update feed can be rewritten in transit.",
            "Serve updates over HTTPS and verify signatures.",
            _line_of(raw, "update_url")))

    if m.get("manifest_version") == 2:
        out.append(_manifest_finding(
            "MANIFEST_MV2", "low", "Manifest V2 is deprecated",
            "manifest_version = 2",
            "Chrome no longer loads MV2 extensions in current builds.",
            "Migrate to Manifest V3.",
            _line_of(raw, "manifest_version")))

    return out


def scan_code(ext: Extension) -> list[Finding]:
    out: list[Finding] = []
    for path in walk_files(ext.root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > 2_000_000:
            continue
        relpath = rel(ext.root, path)
        lines = text.splitlines()
        for rule, rx in _COMPILED:
            hits = 0
            for lineno, line in enumerate(lines, 1):
                if not rx.search(line):
                    continue
                evidence = line.strip()[:180]
                if rule.rule.startswith("SECRET_"):
                    m = rx.search(line)
                    if m:
                        evidence = evidence.replace(m.group(0), _mask(m.group(0)))
                out.append(Finding(
                    rule=rule.rule, severity=rule.severity, title=rule.title,
                    file=relpath, line=lineno, evidence=evidence,
                    why=rule.why, fix=rule.fix))
                hits += 1
                if hits >= 5:
                    break
    return out


def correlate(ext: Extension, findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule, []).append(f)

    external = by_rule.get("EXT_MSG_EXTERNAL")
    if external:
        handler_files = {f.file for f in external}
        dangerous = [
            ("API_COOKIES", "cookie access"),
            ("API_SCRIPTING", "script injection"),
            ("API_NATIVE", "native messaging"),
            ("API_DEBUGGER", "debugger access"),
            ("SINK_EVAL", "dynamic code evaluation"),
            ("SINK_INNERHTML", "HTML injection"),
            ("SINK_OUTERHTML", "HTML injection"),
        ]
        for rule, label in dangerous:
            candidates = [f for f in by_rule.get(rule, []) if f.file in handler_files]
            if not candidates:
                continue
            src = candidates[0]
            out.append(Finding(
                rule="CORR_EXTERNAL_" + rule,
                severity="critical",
                title=f"External message handler reaches {label}",
                file=src.file, line=src.line,
                evidence=f"onMessageExternal + {src.evidence[:120]}",
                why="A web page that matches externally_connectable can drive this capability.",
                fix="Validate sender.origin and sender.id, or remove externally_connectable.",
                confidence="potential"))

        # sender validation is a string check; treat absence as a lead, not proof
        handlers = handler_files
        validated = False
        for path in walk_files(ext.root):
            if rel(ext.root, path) not in handlers:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r"sender\.(?:origin|id|url)|event\.origin", text):
                validated = True
                break
        if not validated:
            src = external[0]
            out.append(Finding(
                rule="CORR_NO_SENDER_CHECK",
                severity="high",
                title="No sender validation near the external handler",
                file=src.file, line=src.line,
                evidence="onMessageExternal without sender.origin / sender.id / event.origin",
                why="Any matching page can call the handler; the handler does not check who called.",
                fix="Compare sender.origin to an allowlist and sender.id to your own id.",
                confidence="potential"))

    listeners = {f.file for f in by_rule.get("MSG_LISTENER", [])}
    message_sinks = [f for f in by_rule.get("SINK_INNERHTML", []) if f.file in listeners]
    if message_sinks:
        src = message_sinks[0]
        out.append(Finding(
            rule="CORR_POSTMESSAGE_HTML",
            severity="high",
            title="Content script writes HTML from postMessage",
            file=src.file, line=src.line,
            evidence="message listener + " + src.evidence[:120],
            why="Any page can post a message; the content script writes it as markup.",
            fix="Use textContent or a sanitizer, and check event.origin.",
            confidence="potential"))

    if "API_COOKIES" in by_rule and "MANIFEST_ALL_URLS" in by_rule:
        src = by_rule["API_COOKIES"][0]
        out.append(Finding(
            rule="CORR_COOKIES_ALL_URLS",
            severity="high",
            title="Cookie access with all-site permissions",
            file=src.file, line=src.line,
            evidence="chrome.cookies + <all_urls>",
            why="Every site's cookies are in scope, including authenticated sessions.",
            fix="Limit host permissions and never forward cookies to a page-supplied URL.",
            confidence="potential"))

    # Web-accessible HTML with a DOM sink
    war_resources: list[str] = []
    war = ext.manifest.get("web_accessible_resources") or []
    if isinstance(war, list):
        for item in war:
            if isinstance(item, str):
                war_resources.append(item)
            elif isinstance(item, dict):
                war_resources.extend(str(x) for x in (item.get("resources") or []))
    war_html = [r for r in war_resources if r.lower().endswith((".html", ".htm"))]
    war_sinks = [f for f in by_rule.get("SINK_INNERHTML", []) if f.file in war_html]
    if war_html and war_sinks:
        src = war_sinks[0]
        out.append(Finding(
            rule="CORR_WAR_HTML",
            severity="high",
            title="DOM XSS in a web-accessible page",
            file=src.file, line=src.line,
            evidence="web_accessible_resources + " + src.evidence[:120],
            why="Any matching page can load this HTML; the sink runs in the extension origin.",
            fix="Remove the page from web_accessible_resources or sanitize the input.",
            confidence="potential"))

    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        k = f.key()
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    score = min(100, sum(SEV_WEIGHT[f.severity] for f in findings))
    grade = "CLEAN"
    for sev in SEVERITIES:
        if any(f.severity == sev for f in findings):
            grade = sev.upper()
            break
    if grade == "CRITICAL":
        score = max(score, 80)
    return score, grade


def analyze(ext: Extension) -> tuple[list[Finding], int, str]:
    findings = scan_manifest(ext) + scan_code(ext)
    findings = dedupe(findings + correlate(ext, findings))
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.file, f.line, f.title))
    score, grade = score_findings(findings)
    return findings, score, grade


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------
def finding_json(f: Finding) -> dict:
    return asdict(f)


def print_scan(ext: Extension, findings: list[Finding], score: int,
               grade: str, as_json: bool = False, min_sev: str = "info") -> None:
    visible = [f for f in findings if SEV_RANK[f.severity] <= SEV_RANK[min_sev]]
    if as_json:
        print(json.dumps({
            "tool": TOOL, "version": __version__, "target": ext.source_path,
            "name": ext.name, "extension_version": ext.version,
            "manifest_version": ext.manifest.get("manifest_version"),
            "id": ext.id, "source": ext.source, "score": score,
            "grade": grade, "findings": [finding_json(f) for f in visible],
            "summary": {s: sum(1 for f in visible if f.severity == s)
                        for s in SEVERITIES},
        }, indent=2))
        return

    print(bold(f"{TOOL}") + dim(f" v{__version__}  ({TAGLINE})"))
    print(dim("authorized testing only"))
    print()
    print(f"  {bold('target')}  {ext.source_path or ext.root}")
    print(f"  {bold('name')}    {ext.name} {ext.version}  ({ext.mv})")
    if ext.id:
        print(f"  {bold('id')}      {ext.id}")
    print(f"  {bold('source')}  {ext.source}")
    color = SEV_COLOR.get(grade.lower(), dim)
    print(f"  {bold('grade')}   {color(grade)}  (score {score}/100)")
    print()
    for f in visible:
        c = SEV_COLOR.get(f.severity, dim)
        print(f"  {c('[' + f.severity.upper() + ']')} {bold(f.title)}")
        print(f"    {dim(f.file + ':' + str(f.line))}  {f.evidence}")
        print(f"    {dim('why:')} {f.why}")
        print(f"    {dim('fix:')} {f.fix}")
        print()
    counts = {s: sum(1 for f in visible if f.severity == s) for s in SEVERITIES}
    summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
    print(bold("summary") + f": {summary or 'no findings'}")


# --------------------------------------------------------------------------
# payloads / page builder
# --------------------------------------------------------------------------
DEFAULT_PAYLOADS = {
    "external": [
        {"name": "ping", "message": {"action": "ping"}},
        {"name": "ping-alt", "message": {"type": "ping"}},
        {"name": "empty", "message": {}},
        {"name": "fetch-probe", "message": {"url": "{{CALLBACK}}?probe=fetch"}},
        {"name": "collect-probe", "message": {"action": "collect", "callback": "{{CALLBACK}}"}},
    ],
    "postMessage": [
        {"name": "postmessage-probe", "data": {"type": "ping"}},
    ],
}


def load_payloads(path: Optional[str]) -> dict:
    if not path:
        return DEFAULT_PAYLOADS
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("payload file must be a JSON object")
    data.setdefault("external", [])
    data.setdefault("postMessage", [])
    for key in ("external", "postMessage"):
        if not isinstance(data[key], list):
            raise ValueError(f"payloads.{key} must be a list")
        for index, item in enumerate(data[key]):
            if not isinstance(item, dict):
                raise ValueError(f"payloads.{key}[{index}] must be an object")
    return data


def substitute(value: Any, mapping: dict) -> Any:
    if isinstance(value, str):
        for key, replacement in mapping.items():
            value = value.replace("{{" + key + "}}", replacement)
        return value
    if isinstance(value, list):
        return [substitute(x, mapping) for x in value]
    if isinstance(value, dict):
        return {k: substitute(v, mapping) for k, v in value.items()}
    return value


def _js_json(value: Any) -> str:
    """JSON that is safe to place inside a <script> element."""
    return (json.dumps(value, ensure_ascii=False)
            .replace("</", "<\\/")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def build_attacker_html(ext_id: str, payloads: dict, callback: str) -> str:
    data = substitute(payloads, {"CALLBACK": callback, "EXT_ID": ext_id})
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ExtHawk</title>
<style>
  body {{ background:#07080d; color:#e7e2d8; font:14px/1.5 ui-monospace,Menlo,monospace; margin:24px; }}
  h1 {{ color:#35d0c0; font-size:18px; }}
  pre {{ white-space:pre-wrap; border:1px solid #253040; padding:12px; background:#0b0d14; }}
</style>
</head>
<body>
<h1>ExtHawk payload runner</h1>
<div id="exthawk-inject" hidden></div>
<div id="exthawk-dom" hidden></div>
<pre id="out"></pre>
<script>
const EXT_ID = {_js_json(ext_id)};
const PAYLOADS = {_js_json(data)};
const out = document.getElementById("out");
function log(s) {{ out.textContent += s + "\\n"; }}
function send(name, msg) {{
  return new Promise((resolve) => {{
    try {{
      chrome.runtime.sendMessage(EXT_ID, msg, (resp) => {{
        const err = chrome.runtime.lastError;
        log(name + ": " + (err ? "error " + err.message : JSON.stringify(resp)));
        resolve();
      }});
    }} catch (e) {{
      log(name + ": throw " + e);
      resolve();
    }}
  }});
}}
function run() {{
  document.cookie = "exthawk_session=poc";
  for (const p of (PAYLOADS.external || [])) {{
    send(p.name, p.message);
  }}
  for (const p of (PAYLOADS.postMessage || [])) {{
    for (const t of [400, 1200, 2200]) {{
      setTimeout(() => window.postMessage(p.data, "*"), t);
    }}
  }}
}}
window.addEventListener("load", run);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# dynamic harness
# --------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = UA

    def _send(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/cb"):
            self.server.events.append(self.path)  # type: ignore[attr-defined]
            self._send(200, b"ok")
        elif self.path == "/attacker.html":
            page = self.server.page.encode("utf-8")  # type: ignore[attr-defined]
            self._send(200, page, "text/html; charset=utf-8")
        elif self.path == "/victim":
            self._send(200, b"<html><body>victim</body></html>", "text/html")
        else:
            self._send(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/cb"):
            self.server.events.append(  # type: ignore[attr-defined]
                self.path + " " + body.decode("utf-8", "replace"))
        self._send(200, b"ok")

    def log_message(self, *_args) -> None:
        pass


class Harness:
    def __init__(self, page: str):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.page = page  # type: ignore[attr-defined]
        self.httpd.events = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def events(self) -> list[str]:
        return self.httpd.events  # type: ignore[attr-defined]

    def start(self) -> "Harness":
        self.thread.start()
        return self

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def find_chrome(explicit: Optional[str] = None) -> Optional[str]:
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("CHROME_BIN")
    if env:
        candidates.append(env)
    candidates += ["chromium", "chromium-browser", "google-chrome",
                   "google-chrome-stable", "chrome"]
    candidates += [
        "/usr/bin/chromium", "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
        "/opt/google/chrome/chrome",
    ]
    for c in candidates:
        if not c:
            continue
        if os.path.sep in c:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        else:
            found = shutil.which(c)
            if found:
                return found
    return None


def chrome_load_warning(chrome: str) -> Optional[str]:
    base = os.path.basename(chrome).lower()
    path = chrome.lower()
    if "chromium" in base or "chrome-for-testing" in path or "chrome-linux64" in path:
        return None
    if "chrome" in base:
        return "branded Chrome may ignore --load-extension; use Chromium or Chrome for Testing"
    return None


def launch_chrome(chrome: str, ext_root: Path, url: str, profile: Path,
                  timeout: int, virtual_ms: int) -> tuple[str, str, int]:
    base = [
        chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
        "--disable-dev-shm-usage", "--no-first-run",
        "--no-default-browser-check", "--disable-background-networking",
        "--disable-sync", "--metrics-recording-only", "--mute-audio",
        f"--user-data-dir={profile}", f"--load-extension={ext_root}",
        f"--virtual-time-budget={virtual_ms}", "--dump-dom", url,
    ]
    try:
        proc = subprocess.run(base, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "", "chromium timed out", 124
    if proc.returncode == 0:
        return proc.stdout, proc.stderr, 0
    # older builds reject --headless=new
    if "headless=new" in proc.stderr or "unknown flag" in proc.stderr.lower():
        base[1] = "--headless"
        try:
            proc = subprocess.run(base, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "", "chromium timed out", 124
    return proc.stdout, proc.stderr, proc.returncode


def _decode_cookie_evidence(path: str) -> str:
    try:
        query = urllib.parse.urlparse(path).query
        values = urllib.parse.parse_qs(query).get("cookies", [])
        if not values:
            return ""
        raw = base64.b64decode(values[0])
        data = json.loads(raw.decode("utf-8", "replace"))
        if isinstance(data, list):
            names = [c.get("name", "?") for c in data if isinstance(c, dict)]
            return f"{len(data)} cookie(s): " + ", ".join(names[:6])
    except Exception:
        return ""
    return ""


def _dom_region(dom: str, element_id: str) -> str:
    m = re.search(
        r'<[a-zA-Z0-9]+[^>]*\bid=["\']' + re.escape(element_id) + r'["\'][^>]*>(.*?)</',
        dom, re.S | re.I)
    return html.unescape(m.group(1)) if m else ""


def _dom_title(dom: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", dom, re.S | re.I)
    return html.unescape(m.group(1)) if m else ""


def evaluate(payloads: dict, dom: str, events: list[str]) -> list[dict]:
    results = []
    joined_events = "\n".join(events)
    live = _dom_region(dom, "out") + "\n" + _dom_title(dom)
    inject_marker = _dom_region(dom, "exthawk-inject")
    dom_marker = _dom_region(dom, "exthawk-dom")
    for p in payloads.get("external", []):
        name = str(p.get("name") or "payload")
        marker = str(p.get("marker") or "")
        confirmed = False
        evidence = ""
        if marker and marker in live:
            confirmed = True
            evidence = f"marker {marker}"
        if name == "cookie-theft" and "cookies=" in joined_events:
            confirmed = True
            detail = ""
            for ev in events:
                if "cookies=" in ev:
                    detail = _decode_cookie_evidence(ev)
                    break
            evidence = "callback with cookies" + (f" ({detail})" if detail else "")
        if name == "ssrf" and "ssrf=1" in joined_events:
            confirmed = True
            evidence = "callback /cb?ssrf=1"
        if name == "page-injection" and "EXTHAWK_INJECT" in inject_marker:
            confirmed = True
            evidence = "live marker EXTHAWK_INJECT"
        if name == "ping" and '"version"' in live:
            confirmed = True
            evidence = "response with version"
        if not confirmed and name not in ("page-injection", "dom-xss", "cookie-theft", "ssrf"):
            # generic: look for the payload name in the page log followed by ok
            m = re.search(re.escape(name) + r":\s*(\{.*?\})", live, re.S)
            if m and '"ok"' in m.group(1):
                confirmed = True
                evidence = "response " + m.group(1)[:120]
        results.append({"name": name, "confirmed": confirmed,
                        "evidence": evidence, "kind": "external"})
    for p in payloads.get("postMessage", []):
        name = str(p.get("name") or "payload")
        marker = str(p.get("marker") or "")
        confirmed = bool(marker and marker in live)
        if name == "dom-xss" and "EXTHAWK_DOM" in dom_marker:
            confirmed = True
            marker = "EXTHAWK_DOM"
        results.append({"name": name, "confirmed": confirmed,
                        "evidence": f"live marker {marker}" if confirmed else "",
                        "kind": "postMessage"})
    return results


def print_exploit(ext: Extension, ext_id: str, results: list[dict],
                  as_json: bool) -> int:
    confirmed = [r for r in results if r["confirmed"]]
    if as_json:
        print(json.dumps({
            "tool": TOOL, "version": __version__, "target": ext.source_path,
            "id": ext_id, "confirmed": [r["name"] for r in confirmed],
            "results": results,
        }, indent=2))
        return 0 if confirmed else 1

    print(bold(f"{TOOL}") + dim(f" v{__version__}  ({TAGLINE})"))
    print(dim("authorized testing only"))
    print()
    print(f"  {bold('target')}  {ext.source_path or ext.root}")
    print(f"  {bold('id')}      {ext_id}")
    print()
    for r in results:
        mark = green("CONFIRMED") if r["confirmed"] else dim("no")
        print(f"  {r['name']:<20} {mark}  {dim(r['evidence'])}")
    print()
    if confirmed:
        print(green(f"[+] {len(confirmed)}/{len(results)} payloads confirmed"))
        return 0
    print(red(f"[!] 0/{len(results)} payloads confirmed"))
    return 1


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_scan(args) -> int:
    try:
        ext = load_extension(args.extension, args.id)
    except Exception as exc:
        log(red("[!] ") + str(exc))
        return 2
    findings, score, grade = analyze(ext)
    print_scan(ext, findings, score, grade, args.json, args.min_severity)
    if args.fail_on:
        threshold = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] <= threshold for f in findings):
            return 1
    return 0


def cmd_poc(args) -> int:
    try:
        ext = load_extension(args.extension, args.id)
    except Exception as exc:
        log(red("[!] ") + str(exc))
        return 2
    if not ext.id:
        log(red("[!] ") + "extension id unknown; pass --id (the 32-letter id from chrome://extensions)")
        return 2
    try:
        payloads = load_payloads(args.payloads)
    except Exception as exc:
        log(red("[!] ") + f"payloads: {exc}")
        return 2
    out = Path(args.out).expanduser().resolve()
    if out == ext.root or ext.root in out.parents:
        log(red("[!] ") + "output directory must not be inside the extension")
        return 2
    out.mkdir(parents=True, exist_ok=True)
    ext_copy = out / "extension"
    if ext_copy.exists():
        shutil.rmtree(ext_copy)
    shutil.copytree(ext.root, ext_copy)
    if args.origin == "auto":
        callback = "__EXTHAWK_CALLBACK__"
    else:
        callback = args.origin.rstrip("/") + "/cb"
    page = build_attacker_html(ext.id, payloads, callback)
    (out / "attacker.html").write_text(page, encoding="utf-8")
    (out / "payloads.json").write_text(json.dumps(payloads, indent=2) + "\n", encoding="utf-8")
    chrome = find_chrome(args.chrome)
    if chrome:
        warning = chrome_load_warning(chrome)
        if warning:
            log(amber("[!] ") + warning)
    chrome = chrome or "chromium"
    runner = f'''#!/usr/bin/env python3
"""Standalone ExtHawk PoC runner. Standard library only."""
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = (HERE / "attacker.html").read_text(encoding="utf-8")
EXTENSION = HERE / "extension"
TOKEN = "__EXTHAWK_CALLBACK__"
DEFAULT_CHROME = {chrome!r}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/cb"):
            print("CALLBACK", self.path, file=sys.stderr, flush=True)
            body = b"ok"
        else:
            port = self.server.server_address[1]
            callback = "http://127.0.0.1:%d/cb" % port
            body = TEMPLATE.replace(TOKEN, callback).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = "http://127.0.0.1:%d/attacker.html" % server.server_address[1]
chrome = os.environ.get("CHROME_BIN") or DEFAULT_CHROME
profile = tempfile.mkdtemp(prefix="exthawk-poc-")
try:
    cmd = [
        chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
        "--disable-dev-shm-usage", "--no-first-run",
        "--no-default-browser-check", "--user-data-dir=" + profile,
        "--load-extension=" + str(EXTENSION),
        "--virtual-time-budget=9000", "--dump-dom", url,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-2000:])
finally:
    server.shutdown()
    server.server_close()
    shutil.rmtree(profile, ignore_errors=True)
'''
    (out / "run.py").write_text(runner, encoding="utf-8")
    run = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cd \"$(dirname \"$0\")\"\n"
        "exec python3 run.py\n"
    )
    (out / "run.sh").write_text(run, encoding="utf-8")
    os.chmod(out / "run.sh", 0o755)
    os.chmod(out / "run.py", 0o755)
    (out / "README.md").write_text(
        f"# ExtHawk PoC - {ext.name}\n\n"
        f"Extension id: `{ext.id}`\n\n"
        "```bash\n./run.sh\n```\n\n"
        "The runner serves `attacker.html` on a free local port, rewrites the "
        "callback, loads the copied extension in headless Chromium, and prints "
        "the DOM. Callback lines go to stderr.\n\n"
        "The extension is copied into `extension/`, so this directory is standalone.\n"
        "Set `CHROME_BIN` if Chromium is not on PATH.\n\n"
        "Authorized testing only.\n",
        encoding="utf-8")
    print(bold("ExtHawk PoC") + dim(f"  {ext.name}"))
    print(f"  wrote  {out}")
    print(f"  id     {ext.id}")
    print(f"  run    cd {out} && ./run.sh")
    return 0


def cmd_exploit(args) -> int:
    try:
        ext = load_extension(args.extension, args.id)
    except Exception as exc:
        log(red("[!] ") + str(exc))
        return 2
    if not ext.id:
        log(red("[!] ") + "extension id unknown; pass --id (the 32-letter id from chrome://extensions)")
        return 2
    try:
        payloads = load_payloads(args.payloads)
    except Exception as exc:
        log(red("[!] ") + f"payloads: {exc}")
        return 2
    chrome = find_chrome(args.chrome)
    if not chrome:
        log(red("[!] ") + "no Chromium found; set CHROME_BIN or pass --chrome")
        return 2
    if args.timeout < 5:
        log(red("[!] ") + "--timeout must be at least 5 seconds")
        return 2
    warning = chrome_load_warning(chrome)
    if warning:
        log(amber("[!] ") + warning)

    harness = Harness("").start()
    callback = f"http://127.0.0.1:{harness.port}/cb"
    harness.httpd.page = build_attacker_html(ext.id, payloads, callback)  # type: ignore[attr-defined]
    url = f"http://127.0.0.1:{harness.port}/attacker.html"
    profile = Path(tempfile.mkdtemp(prefix="exthawk-profile-"))
    virtual_ms = max(4000, min(9000, int(args.timeout * 1000) - 2000))
    log(violet("[*] ") + f"extension {ext.name}  id {ext.id}")
    log(dim(f"    chrome   {chrome}"))
    log(dim(f"    page     {url}"))
    log(dim(f"    callback {callback}"))
    try:
        dom, stderr, rc = launch_chrome(chrome, ext.root, url, profile,
                                        args.timeout, virtual_ms)
        time.sleep(0.4)
        events = list(harness.events)
        if args.save_dom:
            Path(args.save_dom).expanduser().write_text(dom, encoding="utf-8")
        results = evaluate(payloads, dom, events)
        if args.verbose and stderr:
            log(dim(stderr[-2000:]))
        if rc not in (0, 124) and not dom:
            log(red("[!] ") + f"chromium exited {rc}")
            return 2
        return print_exploit(ext, ext.id, results, args.json)
    finally:
        harness.close()
        if args.keep:
            log(dim(f"    profile kept at {profile}"))
        else:
            shutil.rmtree(profile, ignore_errors=True)


def cmd_info(_args) -> int:
    print(bold(f"{TOOL}") + dim(f" v{__version__}"))
    print()
    print(bold("browser extension attack surface") + dim("  -  static + dynamic"))
    print("  Reads an unpacked extension or .crx, maps permissions, external")
    print("  messaging, dangerous APIs and sinks, computes the extension id,")
    print("  and can prove exploitability in headless Chromium.")
    print()
    print(bold("commands") + ": scan, poc, exploit")
    print(bold("lab") + ":      lab/extension-vuln vs lab/extension-patched")
    print(bold("scope") + ":    extensions you own or have written permission to test")
    print()
    print(dim("  no external Python dependencies; dynamic mode needs Chromium"))
    return 0


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exthawk.py",
        description="ExtHawk - browser extension attack surface scanner and exploit harness",
        epilog="Authorized testing only. Example: python3 exthawk.py scan -e ./extension")
    p.add_argument("--version", action="version", version=f"{TOOL} {__version__}")
    sub = p.add_subparsers(dest="command")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-e", "--extension", required=True,
                        help="extension directory, .crx, or .zip")
    common.add_argument("--id", help="extension id if the manifest has no key")

    sc = sub.add_parser("scan", parents=[common], help="static attack-surface scan")
    sc.add_argument("--json", action="store_true", help="machine-readable output")
    sc.add_argument("--min-severity", choices=SEVERITIES, default="info",
                    help="hide findings below this severity (default: info)")
    sc.add_argument("--fail-on", choices=SEVERITIES, default=None,
                    help="exit 1 if a finding at or above this severity exists")
    sc.set_defaults(func=cmd_scan)

    po = sub.add_parser("poc", parents=[common], help="write a standalone PoC page")
    po.add_argument("--out", default="exthawk-poc", help="output directory")
    po.add_argument("--origin", default="auto",
                    help="callback origin, or 'auto' for a free local port (default: auto)")
    po.add_argument("--payloads", help="JSON payload file (default: built-in guesses)")
    po.add_argument("--chrome", help="Chromium binary for run.sh")
    po.set_defaults(func=cmd_poc)

    ex = sub.add_parser("exploit", parents=[common], help="run payloads in headless Chromium")
    ex.add_argument("--payloads", help="JSON payload file (default: built-in guesses)")
    ex.add_argument("--chrome", help="Chromium binary")
    ex.add_argument("--timeout", type=int, default=30, help="seconds (default: 30)")
    ex.add_argument("--json", action="store_true", help="machine-readable output")
    ex.add_argument("--keep", action="store_true", help="keep the temporary profile")
    ex.add_argument("--save-dom", help="write the dumped DOM to this path")
    ex.add_argument("--verbose", action="store_true", help="show Chromium stderr")
    ex.set_defaults(func=cmd_exploit)

    inf = sub.add_parser("info", help="what this is")
    inf.set_defaults(func=cmd_info)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
