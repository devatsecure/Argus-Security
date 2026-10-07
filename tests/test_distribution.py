"""Build the public artifact and exercise it away from the source tree."""

import os
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest


@pytest.fixture(scope="module")
def installed_wheel(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    work = tmp_path_factory.mktemp("distribution")
    result = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(work), str(root)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    installed = work / "installed"
    with ZipFile(next(work.glob("*.whl"))) as wheel:
        wheel.extractall(installed)
    return installed, work


@pytest.mark.parametrize("entry", ["scan_main", "audit_main", "gate_main"])
def test_wheel_commands_work_outside_checkout(installed_wheel, entry):
    installed, work = installed_wheel
    code = (
        f"import sys; sys.path.insert(0, {str(installed)!r}); "
        f"from scripts.cli import {entry}; sys.argv=['argus', '--help']; {entry}()"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], cwd=work, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "usage:" in result.stdout.lower()


def test_wheel_contains_usable_builtin_resources(installed_wheel):
    installed, work = installed_wheel
    code = f"""import sys
sys.path.insert(0, {str(installed)!r})
from scripts.cli import _bootstrap
_bootstrap()
from resource_paths import resource_root
from config_loader import load_profile
assert (resource_root() / 'policy/rego/pr.rego').is_file()
assert (resource_root() / 'rules/custom').is_dir()
assert load_profile('standard')
from orchestrator.agent_runner import load_agent_prompt
assert len(load_agent_prompt('security')) > 500
"""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], cwd=work, env=env, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stdout + result.stderr
