"""CLI entry point for Argus Temporal Worker.

Starts a Temporal worker process that listens for pipeline workflow tasks.

Usage:
    python scripts/temporal_worker.py --mode production
    python scripts/temporal_worker.py --mode testing --server localhost:7233

Requires: temporalio>=1.7.0 (optional dependency)
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Ensure scripts directory is importable
scripts_dir = Path(__file__).resolve().parent
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

logger = logging.getLogger(__name__)


def main() -> None:
    """Parse arguments and start the Temporal worker."""
    try:
        from temporal_orchestrator import (
            RETRY_POLICIES,
            TEMPORAL_AVAILABLE,
            create_temporal_client,
            start_temporal_worker,
        )
    except ImportError:
        print("Error: Could not import temporal_orchestrator module")
        sys.exit(1)

    if not TEMPORAL_AVAILABLE:
        print(
            "Error: temporalio package not installed. "
            "Install with: pip install temporalio>=1.7.0"
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Argus Security Temporal Worker"
    )
    parser.add_argument(
        "--mode",
        choices=list(RETRY_POLICIES.keys()),
        default="production",
        help="Retry policy mode (default: production)",
    )
    parser.add_argument(
        "--server",
        default="localhost:7233",
        help="Temporal server address (default: localhost:7233)",
    )
    parser.add_argument(
        "--namespace",
        default="argus",
        help="Temporal namespace (default: argus)",
    )
    parser.add_argument(
        "--task-queue",
        default="argus-pipeline",
        help="Temporal task queue name (default: argus-pipeline)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    logger.info(
        "Starting Argus Temporal Worker (mode=%s, server=%s)",
        args.mode,
        args.server,
    )
    logger.info(
        "Namespace: %s, Task Queue: %s", args.namespace, args.task_queue
    )

    async def _run_worker() -> None:
        client = await create_temporal_client(args.server)
        worker = await start_temporal_worker(
            client, task_queue=args.task_queue, mode=args.mode
        )
        logger.info("Worker started, listening on task queue: %s", args.task_queue)
        await worker.run()

    try:
        asyncio.run(_run_worker())
    except KeyboardInterrupt:
        logger.info("Worker shutdown requested")
    except Exception as exc:
        logger.error("Worker failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
