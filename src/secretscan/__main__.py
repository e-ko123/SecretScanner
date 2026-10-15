"""Allow the same CLI through python -m secretscan."""

from secretscan.cli import main

raise SystemExit(main())
