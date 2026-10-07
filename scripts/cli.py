"""Installed command entry points for the existing script-based application."""

import sys
from pathlib import Path


def _bootstrap() -> None:
    """Resolve legacy absolute imports from this installation's module directory."""
    directory = str(Path(__file__).resolve().parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)


def scan_main() -> None:
    _bootstrap()
    from hybrid.cli import main

    main()


def audit_main() -> None:
    _bootstrap()
    from run_ai_audit import build_config, parse_args, run_audit

    args = parse_args()
    run_audit(args.repo_path, build_config(args), args.review_type)


def gate_main() -> None:
    _bootstrap()
    from gate import main

    main()
