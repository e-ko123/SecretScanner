# SecretScanner

**`secretscan` finds API keys, hard-coded passwords/secrets, and private keys accidentally left in your code.** It can block git commits containing detected secrets.

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
- [Handling false alarms](#handling-false-alarms)
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

🚧 **Work in progress.** Features are checked off as they are built and tested. Anything marked ***(planned)*** in this README is **not built yet**; it describes how that part will work once it is.

- [x] **Phase 1: Core scanner.** Scan files and folders, detect provider keys, private keys, and generic secrets using entropy; mask output, filter placeholders, and review false alarms.
- [x] **Phase 2: Git integration.** `--staged` scanning and the `install-hook` command.
- [ ] **Phase 3: Polish.** JSON output, colored output, GitHub Actions CI.

---

## Why I built this

Leaking a secret is one of the most common and most expensive mistakes a developer can make. A single API key pushed to a public GitHub repo can be found by automated bots within minutes and used to run up huge bills or steal data.

I wanted to understand how tools that prevent this actually work, so I built a simpler version from scratch. Along the way I'm learning about regular expressions, measuring randomness with Shannon entropy, how git stores staged changes, and how git hooks work (some of these parts are still being built). I kept the code small and readable on purpose, so every part can be understood and explained.

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
```

You don't need to change your code or add special comments first: common placeholder keys are skipped automatically, and any remaining false alarm can be dismissed in a separate file (see [Handling false alarms](#handling-false-alarms)).

To protect a git repository so commits with secrets are blocked:

```bash
cd path/to/your/repo
secretscan install-hook
```

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
config.py:12    AWS Access Key ID   AKIA****************
src/app.js:40   GitHub Token        ghp_************************************
keys/id_rsa:1   Private Key         ----***************************

Found 3 possible secrets in 3 files.
Suppressed 2 recognized placeholders (use --include-placeholders to see).
```

Each line shows:

- **Where:** the file and line number (`config.py:12` means line 12 of `config.py`).
- **What:** the type of secret it looks like.
- **A masked preview:** only the first 4 characters are shown. The rest are replaced with `*`, so **secretscan never prints a full secret to your screen** (where it could end up in logs, screenshots, or screen shares). Short secrets (8 characters or fewer) are hidden completely, since showing 4 characters would give most of them away. Very long secrets show at most 40 stars plus their length, e.g. `sk-p****…(5000 chars)`. File names and error messages are masked the same way, in case a file is named after a key.

After the findings comes a summary. If anything was hidden (recognized placeholders, or findings you dismissed), a line says how many and how to see them. If nothing is found at all, the summary is the only line you'll see:

```text
No secrets found.
```

If nothing is left to report but some matches were hidden, it says **"No reportable secrets found."** instead, because something *was* matched; secretscan just judged it not worth reporting.

### All options

| Option | What it does |
|---|---|
| `path` | The file or folder to scan (default: the current folder) |
| `--include-placeholders` | Also report recognized placeholder keys instead of hiding them |
| `--review` | Go through the findings one by one and choose which to ignore from now on |
| `--show-ids` | Show each finding's ID, for dismissing it in `.secretscanignore` |
| `--json` | Print the results as JSON (secrets still masked), for other programs |
| `--ignore-file PATH` | Use this ignore file instead of `.secretscanignore` in the scanned folder |
| `--no-ignore` | Don't use any ignore file. Can't be combined with `--ignore-file` |
| `--version`, `--help` | Show the version or the help text |

### Scan only what you're about to commit

```bash
secretscan --staged
```

When you run `git add`, your changes are *staged*: they're queued up for the next commit. `--staged` checks **only the lines you added** in those staged changes, not your whole project.

Two details make this accurate:

- It reads the **staged version** of each file (exactly what will be committed), not the version on your disk, which you may have edited since running `git add`.
- It only looks at **lines you added**, so a secret that was already in the file before doesn't block every future commit.

This is the mode the git hook uses. Run it from any folder inside the repository.
It compares the index with the current commit; new repositories work too. It
reads complete staged files for context, then reports matches touching added
or replaced lines. This catches a split key or private-key block even when only
its later lines changed. Renamed/copied files are treated as new paths and
scanned in full. Repeated lines can make line matching conservative.

The default `.secretscanignore` also comes from the **index**. After reviewing
false alarms with `secretscan --review`, run `git add .secretscanignore` to make
those dismissals apply to the next commit. `--staged --show-ids` prints IDs for
manual dismissals. `--ignore-file PATH` explicitly uses a config on disk;
`--no-ignore` disables the ignore file. Placeholder and inline-marker switches
work as usual. `--review` and path filtering cannot be combined with `--staged`.

Staged scanning checks tracked dependency/build folders too. Binary files are
skipped with a warning. Changed files over 1 MB, changed submodules, unresolved
merges, unreadable Git objects, and invalid ignore files return code `2`, which
blocks the hook. Deleted files need no scan. Symlinks are scanned as the link
text Git stores; their targets are not followed. If the previous version is
over 1 MB, all lines in the smaller staged replacement are checked.

### Block commits automatically (git hook)

```bash
cd path/to/your/repo
secretscan install-hook
```

This creates a **pre-commit hook**: a small script at `.git/hooks/pre-commit` that git runs right before every commit. The hook runs `secretscan --staged`, and if anything is found, the commit is cancelled:

```text
$ git commit -m "Add payment code"

payments.py:8   Stripe Live Secret Key   sk_l********************
Found 1 possible secret in 1 file.
Commit blocked: secretscan found possible secrets.
Remove the secrets, run git add on the corrected files, then commit again.
For false alarms, run secretscan --review and git add .secretscanignore.
```

**If a pre-commit hook already exists**, `install-hook` won't touch it. It prints a message and stops, so it never destroys someone's existing setup by accident. To replace the existing hook anyway:

```bash
secretscan install-hook --force
```

The installer honors `core.hooksPath` and linked worktrees. A configured shared
hook directory affects every repository using it. The hook remembers the
installing Python interpreter, so activating its virtual environment later is
unnecessary. Install the package first (`pip install .` or `pip install -e .`),
and reinstall the hook if you move or remove that Python environment. Scanning
errors also block commits, with a separate message explaining that the scan
could not finish.

> ⚠️ Anyone can skip git hooks with `git commit --no-verify`. The hook is a safety net against accidents, not a security barrier. For a check that can't be skipped, also run `secretscan` in CI (see [What I'd add next](#what-id-add-next)).

### JSON output (for other programs)

```bash
secretscan --json
secretscan --staged --json
```

This prints the results as [JSON](https://www.json.org/), a structured format that scripts, CI systems, and other tools can read reliably:

```json
{
  "version": 1,
  "findings": [
    {
      "file": "config.py",
      "line": 12,
      "end_line": 12,
      "rule": "AWS Access Key ID",
      "rule_id": "aws-access-key-id",
      "match": "AKIA****************",
      "id": "ca9aab23320c6c2a2680248fb6f4140873aba772489ba573945359a64a3178ab",
      "placeholder": null
    }
  ],
  "summary": {"findings": 1, "files": 1, "suppressed": 0, "skipped": 0},
  "skipped": []
}
```

- **`match` is always masked**, exactly like the normal output. File names that look like keys are masked too.
- `id` is the same ID that `--show-ids` prints and `.secretscanignore` uses.
- `end_line` differs from `line` for keys that span several lines (private keys, keys split over two lines).
- `placeholder` is the reason a finding is a recognized placeholder (only with `--include-placeholders`), otherwise `null`.
- `summary.suppressed` counts findings hidden as placeholders, by the ignore file, or by `secretscan:ignore` comments.
- `skipped` lists paths that weren't scanned, and why. `error: true` means something went wrong (the exit code is then `2`).
- `version` is the layout's version number. It only changes if the layout changes in a way that could break programs reading it.

The normal output contains the JSON document and nothing else; notices go to stderr. The exit codes are the same as without `--json`. On an error (exit code `2`, for example a broken ignore file), nothing is printed on the normal output, only the error message on stderr. `--json` can't be combined with `--review`.

### Colors *(planned)*

When you run secretscan in a terminal, output is colored to make findings easy to spot. When the output goes somewhere else (a file, another program, a CI log), it automatically switches to plain text so no strange color codes end up in your files.

### Exit codes

Every command-line program finishes with an *exit code*: a number that tells whatever ran it whether things went well. secretscan uses:

| Exit code | Meaning |
|---|---|
| `0` | Nothing left to report ✅ (hidden placeholders and dismissed findings don't count) |
| `1` | One or more secrets found 🚫 |
| `2` | The command was used incorrectly (for example, a file that doesn't exist), or the ignore file is broken ⚠️ |

This is what makes automation possible: git cancels the commit when a pre-commit hook exits with `1`, and CI systems mark a build as failed the same way.

---

## Handling false alarms

Some text has the exact *shape* of a key without being one, like an example in documentation. secretscan handles this in three layers, so you can use it on an existing project without changing that project's code.

### 1. Recognized placeholders are skipped automatically

**Password assignments are an exception:** nonempty values assigned to
`password`, `passwd`, `pwd`, or prefixed forms such as `DATABASE_PASSWORD` are
reported even when they look like placeholders. `changeme` can be someone's
actual password. Confirmed examples can be dismissed through `--review`.

secretscan recognizes a **small, deliberately narrow** set of obvious placeholders and hides them by default:

- **Published example values.** Exact example keys that a provider publishes in its own documentation. Currently this is one value: the example access key ID from [AWS's IAM documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds-programmatic-access.html) (the one ending in `EXAMPLE`). It must match exactly, including capital letters.
- **Filler-only keys.** A key whose variable part (everything after its fixed prefix, like `AKIA`) is made **entirely** of one filler character: `X`, `x`, or `0`, at least 16 characters long. Example: `AKIA` followed by sixteen `X`s. This applies only to rules where that variable part is one simple run of characters: **AWS access key IDs, GitHub tokens (`ghp_` etc.), Stripe live keys, Google API keys, and OpenAI keys.** Other keys with several parts (Slack, Anthropic, GitHub fine-grained tokens) and private key headers are never treated as filler.

- **Exact instructional Slack placeholders:** `xoxb-your-token-goes-here`, and the refresh-token placeholder from Slack's own token-rotation guide. Other tokens containing words like "test" are still reported.

That's the whole list. In particular, secretscan does **not** hide a key because:

- it's in a **comment**. Commenting out a key doesn't remove it from the file, and people often "disable" a real key that way without revoking it. A key in a comment is still leaked.
- it's in a **tests, docs, or examples folder**. Real keys get pasted into those too.
- nearby text says **"example", "fake", "test", "demo", or "placeholder"**. A comment is not proof.
- the key merely **contains** a run of `X`s, or words like `TEST`. Only an *entire* filler body counts.

The filler check is a sensible guess, not proof: a real key that happened to be all `0`s would be hidden. To see everything hidden this way, add `--include-placeholders`. Hidden placeholders are counted in the summary, and each one shows its reason when you include them:

```text
docs/setup.md:4   AWS Access Key ID   AKIA****************   (recognized placeholder: token body is all 'X' filler)
```

### 2. Dismiss a reviewed finding in `.secretscanignore`

For anything else that you've checked and know is harmless, like a realistic-looking fake key in a test, you can dismiss that one finding **without editing the file it's in**.

**The easy way: `--review`.** secretscan goes through the findings one at a time and asks about each:

```text
$ secretscan --review
Reviewing 2 findings. Open each file at the line shown to check it.
Answer y to ignore a finding from now on, Enter to keep it, q to stop.

[1/2] tests/test_api.py:12   AWS Access Key ID   AKIA****************
Ignore this finding from now on? [y/N/q] y
Reason (press Enter to use a default): Fake key used in API client tests

[2/2] src/config.py:3   GitHub Token   ghp_************************************
Ignore this finding from now on? [y/N/q]

Added 1 finding to .secretscanignore.
```

- **y** ignores the finding from now on and asks for a short reason (press Enter to use a default one). The answer is saved to `.secretscanignore`, which is created if it doesn't exist yet.
- **Enter** (or anything other than `y`) keeps reporting it. "No" is the default, so a stray keypress never hides a possible secret.
- **q** stops reviewing. Answers you already gave are saved.
- **Ctrl-C** cancels the whole review and saves nothing, in case you just answered `y` by mistake.

The secret is masked in the questions too, so open the file at the line shown to see it. `--review` only runs in a terminal: in CI, a git hook, or with piped input or redirected output, nobody can answer, so it stops with an error instead of waiting forever. It can't be combined with `--no-ignore`, and with `--ignore-file PATH` answers are saved to that file instead.

Before asking questions, review checks that the destination directory is writable. If saving later fails, it attempts to preserve the answers in a temporary recovery file and prints its location. Saves use a unique temporary file that is cleaned up after handled failures or interruptions.

**The manual way.** You can also edit the ignore file yourself:

1. Run `secretscan` as usual.
2. Run it again with `--show-ids` to see each finding's ID (a long string of letters and digits):

   ```text
   tests/test_api.py:12   AWS Access Key ID   AKIA****************   ca9aab23320c6c2a2680248fb6f4140873aba772489ba573945359a64a3178ab
   ```

3. **Review the finding.** Make sure it really isn't a secret.
4. Add its ID and a short reason to a file named `.secretscanignore` in the folder you scan:

   ```json
   {
     "version": 1,
     "findings": [
       {
         "id": "ca9aab23320c6c2a2680248fb6f4140873aba772489ba573945359a64a3178ab",
         "reason": "Fake key used in API client tests"
       }
     ]
   }
   ```

5. Run `secretscan` again. The finding is gone, and the summary says how many were ignored.

There's deliberately no "ignore all" option, in `--review` or anywhere else: a first scan can contain real leaked keys, and each one deserves a look.

**The ignore file format** is strict, so typos are caught instead of silently doing nothing:

- The top level is an object with exactly two fields: `"version"` (must be the number `1`) and `"findings"` (a list).
- Each entry in `"findings"` has exactly two fields: `"id"`, a full 64-character ID in lowercase letters and digits, copied from `--show-ids`; and `"reason"`, a non-empty explanation.
- The same ID or JSON field cannot be listed twice. UTF-8 files with a byte-order mark (BOM) are accepted.

If the file breaks any of these rules, or isn't valid JSON, secretscan stops with an error and exit code `2`. It never quietly treats a broken ignore file as empty. Error messages say where the problem is, but never print the file's contents.

**Which ignore file is used:**

- By default, `.secretscanignore` in the project root. Starting at the scanned directory (or a file's parent), the nearest ancestor containing `.git` or `.secretscanignore` defines that root. Otherwise, the current working directory is used if it contains the target; for external targets, the scanned directory or file's parent is used. Single-file reviews and folder scans within the same project therefore share IDs and decisions.
- `--ignore-file PATH` uses a different file. If that file doesn't exist, that's an error (exit code `2`).
- `--no-ignore` uses no ignore file at all. It doesn't turn off placeholder hiding or `secretscan:ignore` comments.
- When you scan a folder, the active ignore file itself isn't scanned (it's settings, not code). Naming it directly (`secretscan .secretscanignore`) does scan it.
- The ignore file must be a normal file under 1 MB. If `.secretscanignore` is a shortcut (symlink) to a shared file, `--review` updates the shared file.
- Only the project root's ignore file is used. If a scan finds another `.secretscanignore` in a subfolder, it prints a notice saying it isn't used.

**How IDs work, and their limits.** An ID is a *fingerprint*: a SHA-256 hash of the rule that matched, the file's path relative to the project root, and the matched text. That means:

- Adding or removing lines above a finding **doesn't** change its ID (the line number isn't included).
- Changing the key, moving it to another file, or renaming the file **does** change the ID, so the dismissal no longer applies and the finding is reported again.
- Checking out the project in a different place on disk keeps the same IDs.
- IDs are relative to the discovered project root: the folder containing `.git` if there is one, otherwise the nearest folder with a `.secretscanignore`. Scanning a file or subfolder in that project keeps the same IDs, and so does reaching the project through a folder shortcut. Changing project boundaries can change IDs; old dismissals then need review. For a project without Git, run commands from its root or create its `.secretscanignore` there first.
- If the exact same key appears more than once in one file, every copy has the same ID, and dismissing it dismisses all of them in that file.
- **Private keys** are identified by their key data, not just their header line, so dismissing one key never hides a different key in the same file. A header mentioned in documentation, with no key data under it, isn't reported at all. `secretscan:ignore` comments don't apply to private keys.
- `--review` reads the ignore file again just before saving, so edits made elsewhere during a review are kept. If files change while you're answering, it exits with code `2` and asks you to scan again.
- A fingerprint keeps the ignore file free of plain-text keys, but it's **not encryption**: for a short or guessable value, someone could find it by trying candidates until one produces the same hash.

### 3. Ignore a line with a comment

If you'd rather mark a line in the code itself, add a `secretscan:ignore` comment to it, at the end of a line containing exactly one token match. The `#` or `//` must have a space before it (or start the line), so text like a URL ending in `#secretscan:ignore` doesn't count. Private keys and lines with multiple matches remain reportable:

```python
EXAMPLE_TOKEN = "this-is-just-documentation"  # secretscan:ignore
```

```javascript
const demoKey = "not-a-real-key"; // secretscan:ignore
```

Use a trailing `# secretscan:ignore` or `// secretscan:ignore` with no further text. Bare markers elsewhere on a line have no effect. Suppressed matches are counted; `--include-inline-ignored` reports them again. Placeholder and external-ignore filtering still apply independently.

### Seeing everything that was hidden

```bash
secretscan path/to/project --include-placeholders --no-ignore --include-inline-ignored --show-ids
```

This shows recognized placeholders, external dismissals, and inline dismissals with their IDs. A complete scan of the project's normal scan scope also notes ignore entries that did not match; it never deletes them automatically.

---

## What it detects

| Secret type | What it looks like (masked) | Notes |
|---|---|---|
| **AWS Access Key ID** | `AKIA****************` | Starts with `AKIA` or `ASIA`, followed by 16 capital letters and digits |
| **GitHub token** | `ghp_************************************` | Prefixes `ghp_`, `gho_`, `ghu_`, `ghs_` followed by 36 letters and digits; refresh tokens (`ghr_`) with 36 or more |
| **GitHub App installation token** | `ghs_****************************************...(520 chars)` | The newer `ghs_<app id>_<JWT>` format |
| **GitHub fine-grained token** | `gith*************************…` | Starts with `github_pat_`, GitHub's newer kind of token |
| **Slack token** | `xoxb**************************` | Prefixes `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, refresh tokens `xoxe-`, workflow tokens `xwfp-`, app tokens `xapp-`, and rotated tokens starting `xoxe.` |
| **Stripe live secret key** | `sk_l************************` | Live secret and restricted keys (`sk_live_`, `rk_live_`) |
| **Stripe test secret key** | `sk_t************************` | Test-mode secret and restricted keys (`sk_test_`, `rk_test_`). They can't move real money, but [Stripe says not to expose them](https://docs.stripe.com/keys) |
| **Google API key** | `AIza***********************************` | Starts with `AIza`, 39 characters total |
| **OpenAI API key** | `sk-p****************************…` | Legacy `sk-` plus 48 alphanumeric characters, or `sk-proj-` / `sk-svcacct-` plus a token body |
| **Anthropic API key** | `sk-a****************************…` | Starts with `sk-ant-` |
| **Private key** | `----**********************` | A `-----BEGIN ... PRIVATE KEY-----` block (RSA, EC, DSA, OpenSSH, encrypted, PGP) or a PuTTY v2/v3 key file, when key data follows the header |
| **Generic password / secret** | `q8#L********` | Nonempty quoted password assignments; broader secret names require at least 12 characters and entropy of at least 3.5 bits per character (see below) |

### What it skips

For ordinary file/folder scans, secretscan does **not** scan the following. Staged scanning has the separate rules described above:

- **Folders** that hold tools, dependencies, or generated files rather than your code: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`
- **Binary files** such as images, PDFs, and compiled programs
- **Very large files** (over about 1 MB), which are almost always generated data rather than code a person wrote

Skipped paths and reasons are printed to stderr; the summary does not claim a complete all-clear. Read/traversal failures and a directly requested file that cannot be scanned exit with code `2`. Expected exclusions during a directory scan do not by themselves change the exit code. Symlinked subdirectories and symlinked files are reported and not followed, so a scan never reads files outside the folder you chose (naming a symlinked file directly still scans it). `dist/` and `build/` are scanned, subject to the same size limit.

BOM-marked UTF-16 and UTF-32 text is decoded and scanned. JSON-style `\u0041` escapes for plain characters are decoded before matching, so they can't disguise a key. Unmarked encodings are not guessed. Filenames use ASCII escapes for control and non-ASCII characters so they cannot inject terminal commands or misalign report columns.

Comments, documentation, tests, and example files **are** scanned. See [Handling false alarms](#handling-false-alarms) for why, and for how placeholders are handled.

---

## How it works

The tool uses plain Python and the standard library, with Git providing staged file contents. Parts marked *(planned)* aren't built yet.

### 1. Rules: pattern matching with regular expressions

Many secrets have a recognizable *shape*. For example, AWS access keys always start with `AKIA` followed by exactly 16 capital letters or digits.

A **regular expression** (or *regex*) is a mini-language for describing text patterns like that. The AWS rule is:

```text
AKIA[0-9A-Z]{16}
```

Read it as: "the letters `AKIA`, then exactly 16 characters that are each a digit or a capital letter."

Each kind of secret has its own rule in [`src/secretscan/rules.py`](src/secretscan/rules.py). secretscan reads each file line by line and checks every line against every rule.

### 2. Placeholder recognition

Each match is then checked on its own by [`src/secretscan/placeholders.py`](src/secretscan/placeholders.py): is it an exact published example, or is its variable part entirely filler? If so, it's set aside (but counted) instead of reported. Two matches on the same line are judged separately, so a placeholder next to a real-looking key never hides the real one. See [Handling false alarms](#handling-false-alarms) for the exact rules.

### 3. Fingerprints and the ignore file

Every remaining finding gets an ID: a SHA-256 hash of the rule, the file's relative path, and the matched text ([`src/secretscan/ignores.py`](src/secretscan/ignores.py)). Findings whose ID is listed in `.secretscanignore` are dropped. Everything left is printed (masked) and decides the exit code.

### 4. Generic passwords and the entropy check

Provider keys have recognizable prefixes. Other passwords and secrets do not,
so the generic rule combines an assignment name with character variety.

It recognizes `password`, `passwd`, `pwd`, `secret`, `api_key`, `access_token`,
`auth_token`, and `client_secret`, ignoring letter case. `apiKey`, `accessToken`,
`authToken`, and `clientSecret` work too. API/key and token names also accept
hyphens; underscore/hyphen prefixes allow names such as `DATABASE_PASSWORD`
and `service_client_secret`.

The name may be quoted (JSON/YAML properties) or unquoted (variables). The
operator must be `=` or `:`, and the value must be a **single- or double-quoted
literal on the same line**. Unquoted `.env` values, type annotations between
the name and operator, triple-quoted strings, interpolated strings, and
arbitrary expressions are not supported. This is pattern matching, not a
language parser; quoted fragments in expressions may still be reported.

Only the **value** is scored, fingerprinted, and masked. Detection uses two paths:

- **Password context:** `password`, `passwd`, `pwd`, and their prefixed forms
  report every **nonempty quoted literal**, regardless of length or entropy.
  Short/low-entropy values and known instructional values are labeled
  **Possible Weak Password or Placeholder**. Other values use **Hard-coded
  Password**. The label is a warning, not a password-strength verdict.
- **Broader secret context:** `secret`, `api_key`, `access_token`, `auth_token`,
  and `client_secret` require at least **12 characters** and **Shannon entropy
  of at least 3.5 bits per character**. Provider detection works independently.

Empty strings and complete environment references are excluded from both paths.
Passwords consisting of whitespace are nonempty and are reported. Password
findings retain the same rule ID and fingerprint scheme as earlier generic
findings, so existing review dismissals continue to work.

[`entropy.py`](src/secretscan/entropy.py) counts each character, divides its
count by the total length to obtain `p`, then calculates `-sum(p * log2(p))`.
An empty string scores 0. Repeated identical characters score 0, two equally
common characters score 1, and four equally common characters score 2.

This measures frequencies, **not password strength**: an ordered sequence of
eight different characters and a random-looking sequence of eight different
characters both score 3. The thresholds are starting heuristics, not proof of
a secret. High-variety prose can be flagged, and low-entropy values under the
broader secret names can be missed. Password names bypass these thresholds.
There is no requirement to contain digits or punctuation.

For broader secret names, an explicit list of instructional values, such as
`changeme` and `your-password-here`, is classified as placeholders and can be
shown with `--include-placeholders`. Matching is against the whole value, so
including "example" inside another value does not automatically hide it.
Other short or low-entropy values under broader secret names are not candidates,
even with that switch. **Password assignments are never automatically hidden by
this placeholder list.** Use review or an explicit inline marker for examples.

Complete quoted references such as `${DATABASE_PASSWORD}`, `$DATABASE_PASSWORD`,
`{{ secrets.DATABASE_PASSWORD }}`, and `%DATABASE_PASSWORD%` are excluded.
Assignments to calls such as `os.getenv(...)` are not quoted literals and do
not match. Provider-specific rules never depend on the entropy threshold;
when they overlap a generic candidate, only the provider finding is reported.

Generic findings support `--review`, ignore-file IDs, inline markers, normal
file scans, and staged commit protection through the same existing pipeline.
Generic split-string reconstruction is not implemented.

### 5. The git hook: catching secrets before they're committed

Git lets you run your own scripts at certain moments, called **hooks**. A **pre-commit hook** runs right after you type `git commit` but *before* the commit is actually created. If the hook fails (exits with a code other than `0`), git cancels the commit.

`secretscan install-hook` writes a tiny pre-commit hook that runs `secretscan --staged`. To get exactly what's about to be committed, secretscan asks git directly:

- `git ls-files --stage -z` snapshots the staged object IDs; `git ls-tree` reads the previous commit for comparison.
- `git cat-file` reads those exact staged objects. Python compares decoded lines with the previous commit and scans added or replaced text, retaining full-file context for multiline matches.

### Putting it together

```text
          ┌────────────────────┐
          │ files or staged    │
          │      changes       │
          └─────────┬──────────┘
                    │  skip ignored folders, binary files, huge files,
                    │  and the ignore file itself
                    ▼
          ┌────────────────────┐
          │  read line by line │
          └─────────┬──────────┘
                    │  skip lines containing "secretscan:ignore"
                    ▼
          ┌────────────────────┐
          │  check each rule   │
          └─────────┬──────────┘
                    │  set aside recognized placeholders
                    │  (unless --include-placeholders)
                    ▼
          ┌────────────────────┐
          │ fingerprint each   │
          │ finding            │
          └─────────┬──────────┘
                    │  drop IDs listed in .secretscanignore
                    │  (unless --no-ignore)
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
Run `secretscan install-hook` inside the repository you want to protect. Check
`git rev-parse --git-path hooks/pre-commit` for its location (it may differ from
`.git/hooks/pre-commit`). If the installing Python environment moved, reinstall
with `secretscan install-hook --force`. Use `git commit` without `--no-verify`.

**It flagged something that isn't a secret.**
Check it carefully first. If it really is harmless, run `secretscan --review` and answer `y` for it, or add its ID to `.secretscanignore` by hand (see [Handling false alarms](#handling-false-alarms)), or add a `secretscan:ignore` comment to that line. If it happens often for the same kind of value, please open an issue.

**`secretscan: error: ignore file ...`**
The ignore file is broken or doesn't match the expected format, and the message says which part. Fix it, or run with `--no-ignore` to scan without it.

---

## Known limitations

secretscan is a learning project, and it's honest to say what it *doesn't* do:

- **It only knows the patterns it was given.** A secret from an unsupported service can slip through unless it matches a supported password assignment or passes the broader secret length/entropy checks.
- **It can't tell a realistic fake key from a real one.** Scanning offline, a well-made fake key looks exactly like a real key. Only a few obvious placeholders are recognized automatically; the rest need a person to review and dismiss them.
- **Placeholder recognition is a guess.** A real key whose variable part happened to be all `X`s or `0`s would be hidden. `--include-placeholders` shows them.
- **Finding IDs depend on the project root.** Without a `.git` folder, run commands from the project's top folder (or create its `.secretscanignore` there first) so every scan agrees on the root.
- **Split-key detection is limited to two quoted fragments on neighboring lines**, joined by a `+` (at the end of the first line or the start of the second), a backslash, or by being inside open brackets. Same-line concatenation, three or more fragments, variables, and other expressions are not reconstructed. The bracket check is a rough count, not a real parser.
- **The entropy check is a trade-off.** A high-variety non-secret assigned to a broader secret name can be flagged, and low-entropy secrets under those names can be missed. Password assignments bypass entropy, so examples need explicit review. Unquoted values, unsupported assignment names, and complex expressions are not reconstructed.
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
