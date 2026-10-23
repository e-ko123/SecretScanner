# Release notes

## 0.1.0 — 2026-10-23

First release of SecretScanner, a Python command-line tool for finding possible
credentials in files and preventing accidental Git commits containing them.

### Included

- Provider-specific detection for AWS, GitHub, Slack, Stripe live/test, Google,
  OpenAI, and Anthropic keys, plus supported private-key blocks.
- Hard-coded password detection, including weak passwords, supported unquoted
  configuration values, and passwords in URLs. Broader secret assignments use
  a length and Shannon entropy heuristic.
- Masked reports, stable finding IDs, strict ignore-file validation, interactive
  review, and optional inline dismissals.
- BOM-marked UTF-16/32 text, ASCII JSON Unicode escapes, and supported adjacent
  split-string provider keys. Escaped quotes/newlines preserve password values.
- Staged scanning reads Git objects and the staged ignore file, including initial
  and partial commits. Changes to multiline findings are checked with context.
- A pre-commit hook installer that preserves existing hooks unless explicitly
  replaced with `--force`; scan errors also block commits.
- Masked JSON output and terminal colors. Redirected output, JSON, `NO_COLOR`,
  and `TERM=dumb` remain plain.
- Python 3.9+ support, no runtime dependencies, and GitHub Actions tests on
  Python 3.9–3.14 on Linux plus selected macOS versions.

### Detection corrections included

- YAML null/boolean exclusions apply only to unquoted YAML mapping scalars.
  Literal strings such as false/null in env and properties files are checked.
- Angle-bracket passwords require explicit review rather than being hidden.
- JSON Unicode escapes inside values cannot erase a detected password.
- A login URL assigned to a password variable produces one URL-password finding.

### Installation

Download the source archive, extract it, and run `python3 -m pip install .`
inside the extracted directory, preferably in a virtual environment. Alternatively,
install the wheel with `python3 -m pip install secretscan-0.1.0-py3-none-any.whl`.
Git is needed for `--staged` and `install-hook`. See the README for setup and use.
This release is distributed on GitHub; it is not a claim of publication on PyPI.

### Known limitations

Detection is offline and pattern-based: it cannot confirm that credentials are
active, distinguish convincing fake keys from real ones, or find every secret.
History scanning, arbitrary expression reconstruction, and custom user rules
are outside this release. Heuristics and exclusions can cause missed findings
or false alarms; review the README's exact supported syntax and limitations.

Binary files and excluded paths are reported rather than scanned; file reads
are limited to 1 MB. Staged oversized files and changed submodules block commits
with an incomplete-scan error. Git hooks can be bypassed and must be installed
per repository. Reinstall a hook if its Python environment moves. Linux and
macOS are covered by CI; Windows is not yet validated by the CI matrix.
