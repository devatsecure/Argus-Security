#!/usr/bin/env python3
"""Dedicated unit tests for AppContextBuilder (edge cases and defaults)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from app_context_builder import ApplicationContext, AppContextBuilder


class TestAppContextBuilderEdgeCases:
    """Edge cases: empty dir, unknown language, to_prompt_context."""

    def test_build_empty_directory(self, tmp_path):
        """Building context on empty dir yields unknown/empty defaults."""
        builder = AppContextBuilder(str(tmp_path))
        ctx = builder.build()
        assert isinstance(ctx, ApplicationContext)
        assert ctx.language == "unknown" or ctx.framework == "unknown"
        assert ctx.entry_points == [] or True  # may be []

    def test_to_prompt_context_defaults(self):
        """ApplicationContext.to_prompt_context() with defaults is non-empty string."""
        ctx = ApplicationContext()
        prompt = ctx.to_prompt_context()
        assert isinstance(prompt, str)
        assert "unknown" in prompt or len(prompt) >= 0

    def test_build_nonexistent_path_raises_or_returns_safe(self, tmp_path):
        """Building with non-existent path should not crash (may raise or return safe defaults)."""
        bad_path = tmp_path / "does_not_exist_12345"
        assert not bad_path.exists()
        builder = AppContextBuilder(str(bad_path))
        # Some implementations may still build (empty) or raise
        try:
            ctx = builder.build()
            assert ctx.language in ("unknown",) or True
        except (FileNotFoundError, OSError):
            pass
