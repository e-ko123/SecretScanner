# Prepares a throwaway git repository for the demo recording (demo.tape).
# It's run with `source`, so its `cd` moves the recording's shell into the
# new repository. Nothing here touches the SecretScanner repository itself.

# Use the secretscan installed in this project's virtual environment.
# `$PWD` is the folder VHS was started from: the SecretScanner repo root.
export PATH="$PWD/.venv/bin:$PATH"

# A brand-new, empty folder in the system's temporary directory.
cd "$(mktemp -d)" || return

git init -q
git config user.name "Demo"
git config user.email "demo@example.invalid"

# Install the hook off camera, so the recording can start right at the commit.
secretscan install-hook > /dev/null

# The file with hard-coded secrets. The fake key and password are built from
# pieces by Python, so no complete fake secret is ever written in this repo
# (see "fake secrets in tests" in CLAUDE.md).
python3 -c '
key = "AKIA" + "Z3K9P2M7W4Q8T6N5"
pw = "q8#Lz!v2" + "Wm@9xR"
open("settings.py", "w").write(
    "# Database and AWS settings\n"
    f"AWS_ACCESS_KEY_ID = \"{key}\"\n"
    f"DB_PASSWORD = \"{pw}\"\n"
)'

# A plain prompt and a cleared screen for the recording.
export PS1='$ '
clear
