"""Regression tests for action.yml security — ensures no shell injection vectors."""

import re
from pathlib import Path

import pytest

ACTION_YML = Path(__file__).resolve().parents[1] / "action.yml"


@pytest.fixture(scope="module")
def action_content():
    return ACTION_YML.read_text(encoding="utf-8")


class TestNoEval:
    """Ensure eval is never used in action.yml."""

    def test_no_eval_in_run_blocks(self, action_content):
        run_blocks = re.findall(
            r"run:\s*\|\n((?:\s{4,}.*\n)*)", action_content
        )
        for i, block in enumerate(run_blocks):
            assert "eval " not in block and "eval\t" not in block, (
                f"run block #{i+1} contains 'eval' — "
                "use direct command execution instead"
            )


class TestNoUnsafeShellInterpolation:
    """${{ inputs.* }} must not appear directly in run: blocks."""

    INPUT_PATTERN = re.compile(r'\$\{\{\s*inputs\.[^}]+\}\}')

    def test_no_inputs_in_run_blocks(self, action_content):
        lines = action_content.splitlines()
        in_run_block = False
        indent_level = 0
        violations = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("run:"):
                in_run_block = True
                indent_level = len(line) - len(line.lstrip())
                continue
            if in_run_block:
                current_indent = len(line) - len(line.lstrip()) if stripped else indent_level + 1
                if stripped and current_indent <= indent_level:
                    in_run_block = False
                    continue
                if self.INPUT_PATTERN.search(line):
                    violations.append(f"  Line {line_num}: {stripped}")
        assert not violations, (
            "Found ${{ inputs.* }} in shell run: blocks (injection risk):\n"
            + "\n".join(violations)
            + "\n\nUse env: block variables instead."
        )


class TestNoUnsafeJSInterpolation:
    """Step outputs must not be directly assigned in JS."""

    def test_no_direct_step_output_assignment(self, action_content):
        script_blocks = re.findall(
            r"script:\s*\|\n((?:\s{4,}.*\n)*)", action_content
        )
        violations = []
        for i, block in enumerate(script_blocks):
            matches = re.findall(
                r'(?:const|let|var)\s+\w+\s*=\s*\$\{\{',
                block,
            )
            if matches:
                violations.append(
                    f"script block #{i+1}: assigns ${{{{ }}}} directly to JS variable"
                )
        assert not violations, (
            "Found direct ${{ }} assignment in JS:\n"
            + "\n".join(violations)
            + "\n\nUse env vars and process.env.* instead."
        )
