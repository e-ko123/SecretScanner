"""Install a small Git hook that calls the Python environment installing it."""
from __future__ import annotations

import os
import shlex
import sys
import tempfile
from pathlib import Path

from secretscan.staged import GitError, git, repository_root


def hook_script() -> str:
    """Keep using this interpreter even when the virtualenv isn't activated.

    -I isolates Python from the repository's import names and PYTHONPATH.
    That stops a local secretscan.py from accidentally replacing our scanner.
    The package must therefore be installed (pip install . or pip install -e .).
    """
    command = shlex.quote(sys.executable) + " -I -m secretscan --staged"
    return f'''#!/bin/sh
# Installed by secretscan. Reinstall if its Python environment moves.
{command}
status=$?
if [ "$status" -eq 1 ]; then
    echo "Commit blocked: secretscan found possible secrets." >&2
    echo "Remove the secrets, run git add on the corrected files, then commit again." >&2
    echo "For false alarms, run secretscan --review and git add .secretscanignore." >&2
elif [ "$status" -ne 0 ]; then
    echo "Commit blocked: secretscan could not complete the scan." >&2
    echo "Fix the reported error before committing; reinstall the hook if its Python moved." >&2
fi
exit "$status"
'''


def install_command(argv: list[str]) -> int:
    """Honor Git's hook path, refusing to overwrite a hook without --force."""
    from secretscan.cli import SafeArgumentParser, config_error, display

    parser = SafeArgumentParser(prog="secretscan install-hook")
    parser.add_argument("--force", action="store_true", help="replace an existing pre-commit hook")
    args = parser.parse_args(argv)
    temporary = None
    try:
        root = repository_root()
        # Git handles both linked worktrees and core.hooksPath here. Relative
        # results are relative to root because that is where our Git call ran.
        raw = git(root, "rev-parse", "--git-path", "hooks/pre-commit").stdout
        destination = Path(os.fsdecode(raw.removesuffix(b"\n")))
        if not destination.is_absolute():
            destination = root / destination
        if os.path.lexists(destination) and not args.force:
            return config_error("a pre-commit hook already exists; use --force to replace it")
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Write completely before publishing it. A failed write must not leave
        # a half-installed hook or damage an existing one.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(hook_script())
        temporary.chmod(0o755)
        if args.force:
            # Replace a symlink itself, never write through it to its target.
            os.replace(temporary, destination)
        else:
            # A hard link fails if another installer created a hook meanwhile.
            os.link(temporary, destination)
        print(f"Installed pre-commit hook: {display(destination)}")
        return 0
    except (GitError, OSError) as error:
        if isinstance(error, GitError):
            return config_error(str(error))
        return config_error("could not install the hook; check its path and permissions")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
