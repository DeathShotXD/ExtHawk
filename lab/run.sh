#!/usr/bin/env bash
# ExtHawk lab runner.
#
# A/B test: the vulnerable extension proves the chain, the patched extension
# refuses every payload. Dynamic mode needs Chromium or Chrome for Testing,
# because branded Chrome ignores --load-extension.
set -euo pipefail

cd "$(dirname "$0")"

CHROME="${CHROME_BIN:-}"
if [ -z "$CHROME" ]; then
  for c in chromium chromium-browser /usr/bin/chromium \
           "$HOME/.cache/chrome-testing/chrome-linux64/chrome"; do
    if command -v "$c" >/dev/null 2>&1; then CHROME="$(command -v "$c")"; break; fi
    if [ -x "$c" ]; then CHROME="$c"; break; fi
  done
fi
if [ -z "$CHROME" ]; then
  echo "[-] no Chromium found; set CHROME_BIN" >&2
  exit 2
fi

echo "[*] chromium: $CHROME"
echo

run() {
  local name="$1" ext="$2" expected="$3"
  echo "=== $name ==="
  set +e
  python3 ../exthawk.py exploit -e "$ext" --payloads payloads.json \
    --chrome "$CHROME" --timeout 25 2>/dev/null
  local rc=$?
  set -e
  echo
  if [ "$expected" = "pass" ] && [ "$rc" -eq 0 ]; then
    echo "[+] $name: exploit confirmed (expected)"
  elif [ "$expected" = "fail" ] && [ "$rc" -eq 1 ]; then
    echo "[+] $name: no exploit (expected)"
  else
    echo "[!] $name: unexpected exit $rc (expected $expected)" >&2
    return 1
  fi
  echo
}

run "vulnerable extension" extension-vuln pass
run "patched extension" extension-patched fail
echo "[+] A/B lab complete"
