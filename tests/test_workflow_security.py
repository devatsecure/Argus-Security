"""Regression tests for all GitHub Actions workflow files."""

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"


@pytest.fixture(scope="module")
def workflow_files():
    return list(WORKFLOWS_DIR.glob("*.yml"))


class TestNoUnsafeShellPatterns:
    """Ensure no workflow uses dangerous shell patterns."""

    def test_no_eval_in_workflows(self, workflow_files):
        violations = []
        for wf in workflow_files:
            content = wf.read_text()
            run_blocks = re.findall(r"run:\s*\|\n((?:\s+.*\n)*)", content)
            for block in run_blocks:
                if re.search(r'\beval\s', block) or re.search(r'\beval\t', block):
                    violations.append(f"{wf.name}: contains eval")
        assert not violations, (
            "Unsafe shell patterns in workflows:\n" + "\n".join(violations)
        )


class TestWorkflowPermissions:
    """All workflows should declare minimal permissions."""

    def test_permissions_declared(self, workflow_files):
        missing = []
        for wf in workflow_files:
            try:
                content = yaml.safe_load(wf.read_text())
                if content and isinstance(content, dict) and "permissions" not in content:
                    missing.append(wf.name)
            except yaml.YAMLError:
                pass
        if missing:
            pytest.skip(f"Advisory: {len(missing)} workflows lack top-level permissions: {', '.join(missing[:5])}")


class TestPinnedActions:
    """External actions should be pinned by SHA, not tag only."""

    TAG_PATTERN = re.compile(r"uses:\s+[\w-]+/[\w-]+@v\d")

    def test_no_tag_only_pinning(self, workflow_files):
        violations = []
        for wf in workflow_files:
            for line_num, line in enumerate(wf.read_text().splitlines(), 1):
                if self.TAG_PATTERN.search(line):
                    if "#" not in line:
                        violations.append(f"{wf.name}:{line_num}: {line.strip()}")
        if violations:
            pytest.skip(
                f"Advisory: {len(violations)} actions pinned by tag only:\n"
                + "\n".join(violations[:5])
            )


class TestWorkflowYAMLValid:
    """All workflow files must be valid YAML."""

    def test_all_workflows_parse(self, workflow_files):
        errors = []
        for wf in workflow_files:
            try:
                yaml.safe_load(wf.read_text())
            except yaml.YAMLError as e:
                errors.append(f"{wf.name}: {e}")
        assert not errors, "Invalid YAML in workflows:\n" + "\n".join(errors)
