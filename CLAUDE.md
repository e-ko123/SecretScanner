# secretscan

## What this project is

`secretscan` is a command-line tool that scans code for accidentally leaked secrets (passwords, API keys, private keys) and can block a git commit if it finds one. It's a simpler, from-scratch version of real tools like gitleaks and GitGuardian.

The repo and project title are **SecretScanner**; the command and Python package are **secretscan**.

## Why I'm building it

This is a portfolio project to show employers on GitHub. That means:

- Code quality, clear structure, tests, and a strong README matter as much as features.
- I want to understand and explain every part in an interview, so favor simple, readable code over clever code.
- Keep commits small, each with a clear message (e.g. "Add AWS key detection").

## How to work with me

I'm still learning. When you explain things:

- Use plain language and avoid jargon, or explain a term the first time you use it.
- Tell me why you made a choice, not just what you did.
- Before a big change, briefly say what you're about to do.
- Leave room for me to write parts myself. If I ask, guide me instead of writing it all. Good candidates: the entropy check, some rules, some tests, README sections in my own words. Offer when we reach one.
- Claude makes the commits; I review and push.
- **Comment code heavily.** Whenever writing code (including tests), add plenty of comments explaining what each part does and why, in plain language, so I can read any file top to bottom and understand it. Explain regex patterns piece by piece, and explain any Python feature a beginner might not know the first time it appears in a file.

## Tech decisions

- **Language:** Python 3.9+ (my Mac has 3.9.6, so no `match` statements or `X | Y` type hints; use `from __future__ import annotations` if needed).
- **Dependencies:** only Python's standard library for the tool itself (argparse, re, pathlib, subprocess, json, math). This keeps it easy to install.
- **Tests:** pytest (dev dependency only).
- **Packaging:** `pyproject.toml` with a `secretscan` console command, installable with `pip install .` and later publishable to PyPI.

## Layout

```text
SecretScanner/
├── src/secretscan/
│   ├── __init__.py
│   ├── rules.py      # patterns that describe what each kind of secret looks like
│   ├── scanner.py    # finds files, reads them, applies the rules
│   ├── hook.py       # installs the git pre-commit hook
│   └── cli.py        # handles command-line arguments and prints results
├── tests/
├── .github/workflows/ci.yml
├── pyproject.toml
├── README.md
└── LICENSE
```

Files are added when there's real code to put in them.

## Build plan (in order)

### Phase 1: Core CLI tool

- `secretscan <path>` scans a file or folder (default: current folder).
- Detect, using regular expressions: AWS access key IDs, GitHub tokens, Slack tokens, Stripe secret keys (live and test), Google API keys, OpenAI and Anthropic API keys, private key blocks (`-----BEGIN ... PRIVATE KEY-----`), and generic hard-coded passwords/secrets like `password = "..."` or `api_key: "..."`.
- The generic rule uses a Shannon entropy (randomness) check to skip obvious placeholders like "changeme".
- Skip folders: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`. (`dist` and `build` ARE scanned: build output often has keys baked in, and if it's committed, those keys leak.)
- Skip binary files and files over ~1 MB.
- Output shows file, line number, and type of secret.
- Mask secrets in output, showing only the first 4 characters (e.g. `AKIA************`). Never print a full secret.
- Exit codes: 0 = nothing found, 1 = secrets found.
- A `secretscan:ignore` comment on a line skips that line.

### Phase 2: Git integration (the main selling point)

- `--staged`: scan only the **added lines** in staged changes (`git diff --cached`), reading the staged version of each file, not the version on disk.
- `secretscan install-hook`: sets up a git pre-commit hook. If a hook already exists, refuse with a clear message; `--force` replaces it.
- Clear, friendly message when a commit is blocked, explaining how to fix it.

### Phase 3: Polish

- `--json` output option.
- Colored output when printing to a terminal (plain text otherwise).
- GitHub Actions workflow running the tests on every push.
- Optional: a reusable GitHub Action for other repos.

### Ideas for later

Scan full git history; custom rules in a config file; publish to PyPI.

## Important: fake secrets in tests

GitHub blocks pushes that contain real-looking secrets. Test, demo, and example files must never contain a complete fake key as plain text. Build them in code instead, e.g. `"AKIA" + "X" * 16`.

## README expectations

One-line pitch and "Why I built this"; demo GIF of a blocked commit; install and usage; what it detects; how it works in plain language; known limitations and what's next. Keep the "Project status" checklist up to date.

## Definition of done for each feature

1. It works when run by hand.
2. It has tests, and `pytest` passes.
3. The README is updated if anything user-facing changed.

## Dev setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
