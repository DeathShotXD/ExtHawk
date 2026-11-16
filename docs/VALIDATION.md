# Validation plan

ExtHawk is pre-release. The synthetic HawkNotes lab proves that the harness can
drive a known-vulnerable extension and that the patched build refuses the same
payloads. It does **not** prove that ExtHawk finds real bugs in real extensions,
or that its severity grades match reality.

This document is the gate between "works on our lab" and "safe to publish."

## 1. Authorization boundary

Real-world validation only happens inside one of these buckets:

| Bucket | Allowed | Evidence required |
| --- | --- | --- |
| Our own extensions | Static and dynamic testing | Repository ownership |
| Synthetic corpus | Static and dynamic testing | Case lives in `corpus/` |
| Open-source extension, static review | Read the published source under its license | License and source URL |
| Open-source extension, dynamic testing | Install and drive the extension | Written permission from a maintainer |
| Bug bounty program | Test only what the program explicitly lists | Program URL, scope text, date |
| Vendor engagement | Test the agreed build and actions | Signed scope or written approval |

Explicitly out of bounds:

- mass-scanning or mass-installing Chrome Web Store extensions;
- driving a third-party extension's privileged APIs without permission;
- using real user profiles, cookies, tokens, or production accounts;
- bypassing the store, install prompts, enterprise policy, or authentication;
- publishing a finding before the vendor's disclosure window closes;
- naming a target in public material without permission.

A static scan of public source is not the same as exploiting a running
extension. The first may be allowed by the license; the second needs permission.
When in doubt, ask the maintainer or leave it alone.

Every engagement gets a scope record before any command runs:

```text
target:        name, version, source URL
permission:    program URL / maintainer email / signed scope
allowed:       static only, or static + dynamic
accounts:      dedicated test account, never a real user
data:          what may be collected and where it is stored
disclosure:    security contact, deadline, credit preference
```

## 2. What "validated" means

A case counts only when all three layers agree:

1. **Static** — the expected rule fires on the vulnerable build and does not
   fire on the patched build or the negative control.
2. **Dynamic** — a live callback or live DOM marker proves execution. The
   payload source text appearing in the page is not proof.
3. **Reproducible** — a clean checkout, the documented Chrome build, and the
   documented command reproduce the result.

A real-world finding additionally needs vendor acknowledgement, or a documented
negative result after a good-faith review. "The scanner said CRITICAL" is not a
finding.

## 3. Corpus

The current lab covers one chain. The validation corpus needs at least one
vulnerable/patched pair per bug class, plus a negative control that uses the
same APIs correctly.

| ID | Bug class | Vulnerable behavior | Patched behavior |
| --- | --- | --- | --- |
| C01 | External message bridge | `externally_connectable` + `onMessageExternal` reaches cookies/scripting | No external bridge; explicit sender check |
| C02 | Sender validation | Handler trusts message content but never checks `sender.id` / `sender.origin` | Allowlist of extension IDs and origins |
| C03 | `postMessage` DOM XSS | Wildcard `postMessage` into `innerHTML` | `textContent` + origin check |
| C04 | Web-accessible resource | Page-controlled hash reaches `innerHTML` in a WAR | No WAR, or `textContent` + strict CSP |
| C05 | Content-script DOM XSS | Page data reaches a sink in the content script | Validated data, `textContent` |
| C06 | Script injection | `chrome.scripting.executeScript` with page-supplied code | Fixed function, no page-supplied code |
| C07 | Debugger abuse | External message reaches `chrome.debugger` | Permission removed, no external handler |
| C08 | Native messaging | Page-controlled message reaches a native host | Fixed command allowlist, no page input |
| C09 | Proxy / DNR | Page-controlled rules change traffic | No page-controlled rules |
| C10 | Identity theft | External message reaches `chrome.identity` tokens | No external handler, no token exposure |
| C11 | Downloads | Page-controlled filename/URL writes files | Fixed path, user confirmation |
| C12 | Management | Page-controlled message can disable/launch extensions | No external handler, explicit confirmation |
| C13 | Cookie access | Handler returns HttpOnly/session cookies | No cookie permission, no external handler |
| C14 | History / tabs / bookmarks | Handler returns browsing data | No external handler, minimal permissions |
| C15 | Remote code / CSP | Remote `script` or `importScripts`, weak CSP | Local code, strict CSP |

Each case is a directory:

```text
corpus/C01-external-bridge/
  vuln/                 intentionally vulnerable extension
  patched/              same id, fixed behavior
  negative/             clean extension using the same APIs correctly
  payloads.json         exact payloads
  expected.json         expected static rules and dynamic results
  README.md             what the case teaches and how to run it
```

`expected.json` is the oracle, not the scanner output:

```json
{
  "case": "C01-external-bridge",
  "static": {
    "vuln": ["EXT_BRIDGE", "EXT_COOKIES"],
    "patched": [],
    "negative": []
  },
  "dynamic": {
    "vuln": ["cookie-theft", "page-injection"],
    "patched": [],
    "negative": []
  },
  "severity": "critical"
}
```

The corpus runner scans every build, runs the dynamic harness where authorized,
and compares the result with `expected.json`. A mismatch fails the run.

## 4. Detection quality

The corpus gives us numbers instead of adjectives:

- per-rule precision, recall, and F1 against `expected.json`;
- dynamic confirmation rate on vulnerable builds;
- false-positive rate on patched builds and negative controls;
- false-negative rate per bug class;
- time from scan to first confirmed proof;
- flakiness: how often a case needs a retry or a longer timeout;
- coverage: which bug classes have a case, a negative control, and a proof.

Initial release targets:

| Metric | Target |
| --- | --- |
| Precision on labeled corpus | >= 0.90 |
| Recall on covered bug classes | >= 0.80 |
| False positives on negative controls | 0 |
| Dynamic confirmation on vulnerable builds | 100% |
| Dynamic confirmation on patched builds | 0% |
| Reproducibility from clean checkout | 100% |

These are internal gates. If the numbers are bad, the tool is not ready,
regardless of how good the lab looks.

## 5. Real-world validation

The goal is not "scan as many extensions as possible." The goal is a small
number of authorized engagements with evidence strong enough to survive vendor
review.

Target selection:

1. **Programs with explicit extension scope.** Read the program policy and
   confirm the extension, version, and actions are in scope. If the policy is
   ambiguous, ask the program before testing.
2. **Open-source maintainers.** Start with a static review, then ask for
   permission before installing or driving the extension. Offer the report and
   a fix.
3. **Our own extensions.** Build realistic variants with the same permissions
   and frameworks as production extensions, not just the lab.
4. **Friendly vendors.** Written scope, test account, and a named contact.

For each engagement:

- record the scope and permission before the first command;
- run static analysis, then triage by hand;
- only run dynamic proof on high-confidence chains;
- use a dedicated test account and an isolated browser profile;
- collect the minimum evidence needed to prove impact;
- never read or retain real user data;
- report privately, follow the program's disclosure timeline, and credit the
  vendor's fix.

Success is not "we found a critical." Success is "we can show what we tested,
under what permission, with reproducible evidence, and the vendor agrees."

## 6. Tool hardening before release

Planned changes driven by the validation work:

- **Scope enforcement.** `exploit` accepts a scope file and refuses targets that
  are not listed. Lab mode is an explicit exemption, not the default.
- **Authorization acknowledgement.** Dynamic mode requires an explicit flag
  documenting the permission source.
- **Evidence directory.** `--evidence-dir` writes the manifest hash, payload,
  callback log, DOM snapshot, and a redacted report.
- **Structured reports.** `--report` emits Markdown/JSON with the code path,
  observed behavior, impact, and remediation, not just a severity label.
- **Audit log.** Every run records target, command, time, result, and scope
  reference.
- **Static-only default.** The scan path never launches a browser or touches the
  network. Dynamic mode stays opt-in.
- **No store automation.** ExtHawk does not download, install, or bypass store
  policy for third-party extensions.
- **Secret handling.** Reports mask secret values; evidence directories are
  treated as sensitive.

## 7. Release gate

The repository stays private until all of these are true:

- [ ] At least 3 authorized real-world targets tested, with scope records.
- [ ] At least 1 high/critical finding acknowledged by a vendor, **or** 5+
      authorized targets with documented negative results and no false alarms.
- [ ] Corpus covers at least 10 bug classes with vulnerable, patched, and
      negative builds.
- [ ] Precision >= 0.90 and recall >= 0.80 on the labeled corpus.
- [ ] Zero false positives on negative controls.
- [ ] Dynamic A/B is 100% / 0% on the full corpus.
- [ ] CI is green on Python 3.9-3.13 and the Chrome for Testing job.
- [ ] README states exactly what was validated, on how many authorized targets,
      with what results; no implied coverage of untested extensions.
- [ ] `SECURITY.md`, the authorization boundary, and the disclosure policy are
      published with the tool.
- [ ] A final review confirms no unauthorized testing, no real user data, and no
      undisclosed finding in the repository.

Only then does the repository go public and get announced.

## 8. Immediate sequence

1. Make the GitHub repository private.
2. Keep the synthetic lab as the only public evidence until the gate passes.
3. Build the corpus harness and the first five cases (C01-C05).
4. Add scope enforcement and evidence capture to `exthawk.py`.
5. Select 2-3 authorized targets; record scope before testing.
6. Run the validation, fix the tool, and update the README with real numbers.
7. Re-run the release gate and decide.
