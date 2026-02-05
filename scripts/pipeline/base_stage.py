"""
Base Stage - Convenience base class for pipeline stages.

While the ``PipelineStage`` protocol allows any object with the right
interface, this ABC provides a convenient base with sensible defaults
for ``rollback`` and timing boilerplate.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from .protocol import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class BaseStage(ABC):
    """Abstract base class that satisfies the ``PipelineStage`` protocol.

    Subclasses must implement:
    - ``name``, ``display_name``, ``phase_number`` (as properties or class attrs)
    - ``_execute(ctx)`` -- the core logic

    Optional overrides:
    - ``required_stages`` -- defaults to ``[]``
    - ``should_run(ctx)`` -- defaults to ``True``
    - ``rollback(ctx)`` -- defaults to no-op
    """

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        ...

    @property
    @abstractmethod
    def phase_number(self) -> float:
        ...

    @property
    def required_stages(self) -> List[str]:
        """Override to declare stage dependencies."""
        return []

    def should_run(self, ctx: PipelineContext) -> bool:
        """Override to add precondition checks.  Defaults to True."""
        return True

    @abstractmethod
    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        """Core stage logic.

        Mutate ``ctx`` as needed (append findings, set metadata, etc.)
        and return a dict of stage-specific metadata.

        Raises
        ------
        Exception
            Any exception is caught by ``execute()`` and converted to a
            failed ``StageResult``.
        """
        ...

    def execute(self, ctx: PipelineContext) -> StageResult:
        """Run the stage with timing and error handling.

        Delegates to ``_execute`` and wraps the result in a ``StageResult``.
        """
        findings_before = len(ctx.findings)
        start = time.time()

        try:
            metadata = self._execute(ctx) or {}
            duration = time.time() - start
            return StageResult(
                success=True,
                stage_name=self.name,
                duration_seconds=duration,
                findings_before=findings_before,
                findings_after=len(ctx.findings),
                metadata=metadata,
            )
        except Exception as exc:
            duration = time.time() - start
            logger.error(
                "%s failed: %s", self.display_name, exc, exc_info=True
            )
            return StageResult(
                success=False,
                stage_name=self.name,
                duration_seconds=duration,
                findings_before=findings_before,
                findings_after=len(ctx.findings),
                error=f"{type(exc).__name__}: {exc}",
            )

    def rollback(self, ctx: PipelineContext) -> None:
        """No-op rollback.  Override if the stage needs cleanup."""
        pass
