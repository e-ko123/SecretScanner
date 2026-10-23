"""Check an installed release in a temporary repository (Python standard library).

Run with the Python environment containing the installed wheel or source build:
    python scripts/smoke_test.py

Every scanner command uses -I so it cannot import this checkout accidentally.
Only synthetic credentials are used, and failed command output is not echoed:
raw Git diffs or a regression could otherwise disclose the sample credential.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile


def run(arguments, directory, expected=0):
    """Run a command and require its documented status without echoing content."""
    # Do not let a user's global hook directory or alternate index change which
    # repository is being tested. All changes stay inside the temporary folder.
    environment = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        environment.pop(name, None)
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    result = subprocess.run(arguments, cwd=directory, env=environment,
                            capture_output=True, text=True, timeout=30)
    if result.returncode != expected:
        raise RuntimeError(f"release check failed: {arguments[0]} exited {result.returncode}, expected {expected}")
    return result


def main():
    scanner = [sys.executable, "-I", "-m", "secretscan"]
    with tempfile.TemporaryDirectory(prefix="secretscan-release-check-") as folder:
        root = Path(folder)
        run(scanner + ["--version"], root)
        run(scanner + ["--help"], root)
        run(["git", "init", "-q"], root)
        run(["git", "config", "user.name", "Release Check"], root)
        run(["git", "config", "user.email", "release-check@example.invalid"], root)
        path = root / "settings.py"
        # Build the sample at runtime so source archives contain no full token.
        value = "AKIA" + "Z3K9P2M7W4Q8T6N5"
        path.write_text('api_key = "' + value + '"\n', encoding="utf-8")
        found = run(scanner + [".", "--json"], root, expected=1)
        report = json.loads(found.stdout)
        assert report["summary"]["findings"] == 1
        assert value not in found.stdout + found.stderr
        assert "\x1b[" not in found.stdout
        run(["git", "add", "settings.py"], root)
        run(scanner + ["install-hook"], root)
        # Refuse an existing hook until its replacement is explicitly requested.
        run(scanner + ["install-hook"], root, expected=2)
        run(scanner + ["install-hook", "--force"], root)
        # Cleaning the working file does not clean the index. The hook must
        # block until the fixed contents have also been staged.
        path.write_text('import os\napi_key = os.environ["API_KEY"]\n', encoding="utf-8")
        run(scanner + ["--staged"], root, expected=1)
        blocked = run(["git", "commit", "-m", "blocked sample"], root, expected=1)
        assert "Commit blocked" in blocked.stderr
        assert value not in blocked.stdout + blocked.stderr
        run(["git", "add", "settings.py"], root)
        run(scanner + ["--staged"], root)
        run(["git", "commit", "-qm", "corrected sample"], root)
        # Scan source files directly; scanning the repository would also scan
        # the generated hook's stored Python path, which is not a source file.
        run(scanner + ["settings.py"], root)
    print("Installed-release smoke check passed: masked scans, staged contents, hook blocking, and corrected commit.")


if __name__ == "__main__":
    main()
