# SecretScanner

**`secretscan` finds passwords, API keys, and private keys accidentally left in your code — and can stop you from committing them to git.**

It's a small, dependency-free command-line tool written in Python, inspired by professional tools like [gitleaks](https://github.com/gitleaks/gitleaks) and [GitGuardian](https://www.gitguardian.com/).

<!-- TODO: replace with a GIF of a commit being blocked -->
> 📸 *Demo GIF coming soon: a `git commit` being blocked because it contained an API key.*

---

## Table of contents

- [Project status](#project-status)
- [Why I built this](#why-i-built-this)
- [What problem does this solve?](#what-problem-does-this-solve)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [What it detects](#what-it-detects)
- [How it works](#how-it-works)
- [What to do if you find a real secret](#what-to-do-if-you-find-a-real-secret)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [What I'd add next](#what-id-add-next)
- [Running the tests (for contributors)](#running-the-tests-for-contributors)
- [License](#license)

---

## Project status

🚧 **Work in progress.** This README describes how the finished tool will work. Features are checked off as they are built and tested.

- [ ] **Phase 1: Core scanner.** Scan files and folders, detect secrets, mask output, exit codes, ignore comments.
- [ ] **Phase 2: Git integration.** `--staged` scanning and the `install-hook` command.
- [ ] **Phase 3: Polish.** JSON output, colored output, GitHub Actions CI.

---

## Why I built this

Leaking a secret is one of the most common and most expensive mistakes a developer can make. A single API key pushed to a public GitHub repo can be found by automated bots within minutes and used to run up huge bills or steal data.

I wanted to understand how tools that prevent this actually work, so I built a simpler version from scratch. Along the way I learned about regular expressions, measuring randomness with Shannon entropy, how git stores staged changes, and how git hooks work. I kept the code small and readable on purpose, so every part can be understood and explained.

---

## What problem does this solve?

When you write code, it's easy to paste a password or API key directly into a file "just for testing":

```python
api_key = "sk-..."   # I'll remove this later
```

Then you forget, run `git commit`, and push. Now your key is on GitHub, and **deleting it later doesn't help**, because git keeps the full history of every file.

`secretscan` helps in two ways:

1. **On demand:** run `secretscan` on any folder to find secrets that are already there.
2. **Automatically:** install it as a *git hook* (a script git runs for you at certain moments). It then checks every commit before it's created, and **blocks the commit** if it finds a secret.

---

## Installation

### What you need first

| Requirement | How to check | Where to get it |
|---|---|---|
| **Python 3.9 or newer** | Run `python3 --version` | [python.org/downloads](https://www.python.org/downloads/) |
| **git** | Run `git --version` | [git-scm.com/downloads](https://git-scm.com/downloads) |

> 💡 On macOS and Linux the command is usually `python3`. On Windows it is usually `python` or `py`. This guide uses `python3`; swap in whichever works on your machine.

`secretscan` uses **only Python's built-in standard library**, so there are no extra packages to download.

### Step 1: Download the code

Open a terminal and run:

```bash
git clone https://github.com/e-ko123/SecretScanner.git
cd SecretScanner
```

This copies the project to your computer and moves you into its folder.

### Step 2: Create a virtual environment (recommended)

A *virtual environment* is a private, isolated space for a project's Python packages, so installing this tool can't interfere with anything else on your computer.

```bash
python3 -m venv .venv
```

Then **activate** it (you do this every time you open a new terminal):

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

You'll know it worked when you see `(.venv)` at the start of your terminal prompt.

### Step 3: Install secretscan

From inside the `SecretScanner` folder:

```bash
pip install .
```

The `.` means "install the project in this folder". This adds a new command, `secretscan`, to your terminal.

### Step 4: Check that it worked

```bash
secretscan --help
```

If you see a help message listing the available options, you're done. 🎉

> **Installing it everywhere (optional):** if you want `secretscan` available in every terminal without activating a virtual environment, install it with [pipx](https://pipx.pypa.io/): `pipx install .`

---

## Quick start

```bash
# Scan the folder you're currently in
secretscan

# Protect a git repository so commits with secrets are blocked
cd path/to/your/repo
secretscan install-hook
```

That's it. From now on, every `git commit` in that repository is checked automatically.

---

## Usage

### Scan a folder or file

```bash
secretscan                   # scan the current folder (and everything inside it)
secretscan path/to/project   # scan a specific folder
secretscan config.py         # scan a single file
```

**Example output:**

```text
config.py:12    AWS Access Key ID         AKIA****************
src/app.js:40   Generic Secret            sup3*************
keys/id_rsa:1   Private Key               ----***********************

Found 3 possible secrets in 2 files.
```

Each line shows:

- **Where:** the file and line number (`config.py:12` means line 12 of `config.py`).
- **What:** the type of secret it looks like.
- **A masked preview:** only the first 4 characters are shown. The rest are replaced with `*`, so **secretscan never prints a full secret to your screen** (where it could end up in logs, screenshots, or screen shares).

### Scan only what you're about to commit

```bash
secretscan --staged
```

When you run `git add`, your changes are *staged*: they're queued up for the next commit. `--staged` checks **only the lines you added** in those staged changes, not your whole project.

Two details make this accurate:

- It reads the **staged version** of each file (exactly what will be committed), not the version on your disk, which you may have edited since running `git add`.
- It only looks at **lines you added**, so a secret that was already in the file before doesn't block every future commit.

This is the mode the git hook uses.

### Block commits automatically (git hook)

```bash
cd path/to/your/repo
secretscan install-hook
```

This creates a **pre-commit hook**: a small script at `.git/hooks/pre-commit` that git runs right before every commit. The hook runs `secretscan --staged`, and if anything is found, the commit is cancelled:

```text
$ git commit -m "Add payment code"

🚫 Commit blocked: secretscan found 1 possible secret.

  payments.py:8   Stripe Live Secret Key   sk_l********************

How to fix this:
  1. Remove the secret from the file. Load it from an environment
     variable or a config file that is listed in .gitignore instead.
  2. Run `git add` on the file again.
  3. Commit again.

If this is a false alarm, add a `secretscan:ignore` comment to that line.
```

**If a pre-commit hook already exists**, `install-hook` won't touch it. It prints a message and stops, so it never destroys someone's existing setup by accident. To replace the existing hook anyway:

```bash
secretscan install-hook --force
```

> ⚠️ Anyone can skip git hooks with `git commit --no-verify`. The hook is a safety net against accidents, not a security barrier. For a check that can't be skipped, also run `secretscan` in CI (see [What I'd add next](#what-id-add-next)).

### Ignore a line on purpose

Sometimes a line *looks* like a secret but isn't, like a fake key in documentation. Add a `secretscan:ignore` comment to that line, and secretscan will skip it:

```python
EXAMPLE_TOKEN = "this-is-just-documentation"  # secretscan:ignore
```

```javascript
const demoKey = "not-a-real-key"; // secretscan:ignore
```

It works with any comment style, because secretscan just looks for the text `secretscan:ignore` anywhere on the line.

### JSON output (for other programs)

```bash
secretscan --json
```

This prints results as [JSON](https://www.json.org/), a structured format that scripts and other tools can read easily:

```json
[
  {
    "file": "config.py",
    "line": 12,
    "rule": "AWS Access Key ID",
    "match": "AKIA****************"
  }
]
```

Secrets are masked in JSON output too.

### Colors

When you run secretscan in a terminal, output is colored to make findings easy to spot. When the output goes somewhere else (a file, another program, a CI log), it automatically switches to plain text so no strange color codes end up in your files.

### Exit codes

Every command-line program finishes with an *exit code*: a number that tells whatever ran it whether things went well. secretscan uses:

| Exit code | Meaning |
|---|---|
| `0` | No secrets found ✅ |
| `1` | One or more secrets found 🚫 |
| `2` | The command was used incorrectly (for example, a file that doesn't exist) ⚠️ |

This is what makes automation possible: git cancels the commit when a pre-commit hook exits with `1`, and CI systems mark a build as failed the same way.

---

## What it detects

| Secret type | What it looks like (masked) | Notes |
|---|---|---|
| **AWS Access Key ID** | `AKIA****************` | Starts with `AKIA`, followed by 16 capital letters and digits |
| **GitHub token** | `ghp_************************************` | Prefixes `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, and `github_pat_` |
| **Slack token** | `xoxb-***********` | Prefixes such as `xoxb-`, `xoxp-`, `xoxa-` |
| **Stripe live secret key** | `sk_l*****************` | Only **live** keys (`sk_live_`). Test keys can't move real money |
| **Google API key** | `AIza***********************************` | Starts with `AIza`, 39 characters total |
| **OpenAI API key** | `sk-p****************` | Starts with `sk-` (including `sk-proj-`) |
| **Anthropic API key** | `sk-a****************` | Starts with `sk-ant-` |
| **Private key** | `----************************` | Any `-----BEGIN ... PRIVATE KEY-----` block (RSA, EC, OpenSSH, etc.) |
| **Generic password / secret** | `password = "****"` | Assignments like `password = "..."`, `api_key: "..."`, `secret = '...'`, but **only if the value looks random** (see below) |

### What it skips

To stay fast and avoid noise, secretscan does **not** scan:

- **Folders** that hold tools, dependencies, or generated files rather than your code: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `build`
- **Binary files** such as images, PDFs, and compiled programs
- **Very large files** (over about 1 MB), which are almost always generated data rather than code a person wrote

---

## How it works

secretscan does three main things. None of them is magic, and the whole tool is a few hundred lines of plain Python.

### 1. Rules: pattern matching with regular expressions

Many secrets have a recognizable *shape*. For example, AWS access keys always start with `AKIA` followed by exactly 16 capital letters or digits.

A **regular expression** (or *regex*) is a mini-language for describing text patterns like that. The AWS rule is:

```text
AKIA[0-9A-Z]{16}
```

Read it as: "the letters `AKIA`, then exactly 16 characters that are each a digit or a capital letter."

Each kind of secret has its own rule in [`src/secretscan/rules.py`](src/secretscan/rules.py). secretscan reads each file line by line and checks every line against every rule.

### 2. The randomness check: telling real passwords from placeholders

Some secrets don't have a fixed shape, like a database password in `password = "..."`. A rule that flagged *every* `password = "..."` would raise false alarms all the time:

```python
password = "changeme"           # obviously a placeholder
password = "your-password-here" # also a placeholder
password = "q8#Lz!v2Wm@9xR"     # this one looks real
```

The difference is **randomness**. Real secrets are usually random-looking; placeholders are made of ordinary words. secretscan measures randomness using **Shannon entropy**, a score from information theory that roughly answers: *"how unpredictable is each character in this text?"*

- `"aaaaaaaa"` → entropy **0**: every character is the same, totally predictable.
- `"changeme"` → **low** entropy: few distinct letters, repeated.
- `"q8#Lz!v2Wm@9xR"` → **high** entropy: many different characters, no pattern.

The generic rule only reports a value if its entropy is above a threshold, which filters out most placeholders while still catching real passwords.

### 3. The git hook: catching secrets before they're committed

Git lets you run your own scripts at certain moments, called **hooks**. A **pre-commit hook** runs right after you type `git commit` but *before* the commit is actually created. If the hook fails (exits with a code other than `0`), git cancels the commit.

`secretscan install-hook` writes a tiny pre-commit hook that runs `secretscan --staged`. To get exactly what's about to be committed, secretscan asks git directly:

- `git diff --cached` lists the changes that are staged.
- secretscan reads the **staged** copy of each file from git, not the copy on disk, so it checks precisely what will end up in the commit.

### Putting it together

```text
          ┌────────────────────┐
          │  files or staged   │
          │      changes       │
          └─────────┬──────────┘
                    │  skip ignored folders, binary files, huge files
                    ▼
          ┌────────────────────┐
          │  read line by line │
          └─────────┬──────────┘
                    │  skip lines containing "secretscan:ignore"
                    ▼
          ┌────────────────────┐
          │  check each rule   │──── generic rule? → randomness check
          └─────────┬──────────┘
                    ▼
          ┌────────────────────┐
          │ print masked report│
          │  exit 0 or exit 1  │
          └────────────────────┘
```

---

## What to do if you find a real secret

If secretscan finds a **real** secret that has already been committed or pushed:

1. **Revoke (cancel) the key immediately** on the service that issued it (AWS, GitHub, Stripe, etc.) and create a new one. This is the only step that truly makes you safe. Assume the old key has been seen.
2. **Remove it from your code.** Store secrets in environment variables or in a config file listed in `.gitignore`, instead of writing them directly in the code.
3. **Optionally, clean your git history** with a tool like [git-filter-repo](https://github.com/newren/git-filter-repo). This doesn't replace step 1: copies of the old history may already exist elsewhere.

---

## Troubleshooting

**`secretscan: command not found`**
Your virtual environment probably isn't active. Run `source .venv/bin/activate` (macOS/Linux) or `.venv\Scripts\Activate.ps1` (Windows) and try again.

**`pip: command not found`**
Try `python3 -m pip install .` instead.

**The hook isn't running when I commit.**
Make sure you ran `secretscan install-hook` *inside* the repository you want to protect, and check that `.git/hooks/pre-commit` exists. The hook calls the `secretscan` command, so it must be installed where git can find it. Installing with `pipx` is the most reliable option.

**It flagged something that isn't a secret.**
Add `secretscan:ignore` in a comment on that line. If it happens often for the same kind of value, please open an issue.

---

## Known limitations

secretscan is a learning project, and it's honest to say what it *doesn't* do:

- **It only knows the patterns it was given.** A secret from a service with no rule, or a password with low randomness, can slip through.
- **The randomness check is a trade-off.** A truly random-looking non-secret (like a hash) can be flagged, and a weak real password (like `summer2024`) can be missed.
- **It doesn't scan git history.** It checks your files as they are now, or your staged changes, but not secrets buried in old commits.
- **Git hooks can be skipped** with `git commit --no-verify`, and each person has to install the hook on their own machine.
- **It can't confirm a key is live.** It reports things that *look* like secrets; it doesn't contact AWS or GitHub to check whether a key actually works.

---

## What I'd add next

- **Scan full git history** to find old leaks still hiding in past commits.
- **Custom rules in a config file**, so teams can add patterns for their own internal secrets.
- **A reusable GitHub Action**, so any repository can run secretscan on every push and pull request (which also covers people who skip the local hook).
- **Publish to PyPI**, so installation becomes a single `pip install secretscan`.

---

## Running the tests (for contributors)

Tests use [pytest](https://pytest.org/), which is only needed for development, not for using the tool.

```bash
pip install -e ".[dev]"   # -e = "editable": code changes take effect without reinstalling
pytest                    # [dev] = also install the development tools (pytest)
```

> **Note on fake secrets in tests:** GitHub automatically blocks pushes that contain real-looking secrets. To avoid this, tests never contain a complete fake key as plain text. They build it in code instead, for example `"AKIA" + "X" * 16`, so the full string never appears in any file.

---

## License

[MIT](LICENSE) © 2026 Ethan Ko
