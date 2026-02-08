"""CLI entry point for Argus MCP Server.

Usage:
    python scripts/mcp_server_runner.py --repo-path /path/to/repo
    python scripts/mcp_server_runner.py --repo-path /path/to/repo --profile standard
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure scripts/ is on the path so sibling imports work
scripts_dir = Path(__file__).resolve().parent
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from mcp_server import MCP_AVAILABLE, create_argus_mcp_server

logger = logging.getLogger(__name__)


def main() -> None:
    """Parse arguments and start the Argus MCP server."""
    if not MCP_AVAILABLE:
        print(
            "Error: MCP package not installed. "
            "Install with: pip install 'mcp>=1.0.0'",
            file=sys.stderr,
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Argus Security MCP Server",
        epilog="Exposes Argus pipeline capabilities as MCP tools for Claude Code.",
    )
    parser.add_argument(
        "--repo-path",
        required=True,
        help="Absolute path to the repository to scan",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Optional Argus config profile name (e.g. 'standard', 'ci')",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Load config if a profile was specified
    config = {}
    if args.profile:
        try:
            from config_loader import build_unified_config

            config = build_unified_config(
                profile=args.profile, repo_path=args.repo_path
            )
            logger.info("Loaded config profile '%s'", args.profile)
        except Exception as exc:
            logger.warning("Could not load profile '%s': %s", args.profile, exc)

    server = create_argus_mcp_server(args.repo_path, config=config)
    if server is None:
        print("Error: Failed to create MCP server.", file=sys.stderr)
        sys.exit(1)

    logger.info("Starting Argus MCP server for repo: %s", args.repo_path)
    server.run()


if __name__ == "__main__":
    main()
