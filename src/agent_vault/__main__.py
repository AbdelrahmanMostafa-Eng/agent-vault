"""Allow ``python -m agent_vault`` to invoke the CLI."""

from .cli import main

raise SystemExit(main())  # pragma: no cover
