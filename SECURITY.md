# Security

## The boundary

ExtHawk is offensive tooling for browser extensions. It exists so researchers,
red teams, and defenders can audit extensions they own or are authorized to
test: your own build, an engagement scope, or a program that explicitly covers
browser extensions.

Do not point it at third-party extensions, extension stores, or users without
written permission. Installing someone else's extension in a test browser and
driving its privileged APIs is still testing someone else's software. If you
find a vulnerable extension in the wild, report it to the developer or the
store's security contact. Do not exploit it to "prove" the finding.

The included HawkNotes lab is synthetic and ships with the repository so the
tool can be validated without touching anyone else's code.

## Reporting a bug in ExtHawk

Use GitHub's private vulnerability reporting on this repository
(Security -> Report a vulnerability). Please do not open a public issue for a
bug that could crash a user's browser, escape the temporary profile, or write
outside the extraction directory.

Useful reports include:

- a crash, hang, or incorrect parse in `exthawk.py`
- a CRX or ZIP extraction that writes outside the temporary directory
- a path traversal, symlink, or decompression-bomb case in package handling
- a false positive or false negative in a static rule, with the input
- a dynamic harness bug that leaves a browser or callback server running
- documentation that could lead someone to test an extension they do not own

## Supported versions

0.1.x on Python 3.9 and newer. The scanner has no runtime dependencies. The
demo renderer in `scripts/` needs Pillow, but it is not part of the scan or
exploit path.
