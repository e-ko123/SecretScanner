"""Lets the tool run as `python -m secretscan`, not only as `secretscan`.

When Python is given `-m <package>`, it runs the package's __main__.py
file. This one just calls the same `main` function the `secretscan`
command uses.
"""

from secretscan.cli import main

# `main()` returns the exit code (0, 1, or 2). Raising SystemExit with it
# ends the program with that code, the same as `sys.exit(main())`.
raise SystemExit(main())
