"""Execute the composite Action's shell with a controlled scanner process."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("jq") is None, reason="Action shell requires jq")
@pytest.mark.parametrize(
    "exit_code,expected,completed", [(0, 0, "true"), (1, 0, "true"), (2, 2, "false"), (137, 2, "false")]
)
def test_action_preserves_scan_execution_failure(tmp_path, exit_code, expected, completed):
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    step = next(step for step in action["runs"]["steps"] if step.get("id") == "run-pipeline")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scanner = bin_dir / "python3"
    scanner.write_text("""#!/bin/bash
test -f "$1" || exit 2
test -f "$(dirname "$1")/../policy/rego/pr.rego" || exit 2
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-dir" ]; then
    shift
    cp "$SCAN_REPORT" "$1/hybrid-scan-current.json"
    echo '{"overall_passed":true}' > "$1/quality-report-current.json"
    break
  fi
  shift
done
exit "$SCAN_EXIT"
""")
    scanner.chmod(0o755)
    report_dir = tmp_path / ".argus/hybrid-results"
    report_dir.mkdir(parents=True)
    report = report_dir / "hybrid-scan-20261007.json"
    report.write_text(
        json.dumps(
            {
                "total_findings": 1,
                "findings_by_severity": {"high": 1},
                "tools_used": ["Semgrep"],
                "scan_status": "complete",
                "policy_gate_result": {"decision": "pass"},
            }
        )
    )
    quality = report_dir / "quality-report-20261007.json"
    quality.write_text('{"overall_passed": true}')
    os.utime(quality, (report.stat().st_mtime + 10,) * 2)
    output = tmp_path / "outputs"
    env = dict(
        os.environ,
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        INPUT_PROJECT_PATH=str(tmp_path),
        GITHUB_ACTION_PATH=str(ROOT),
        SCAN_EXIT=str(exit_code),
        SCAN_REPORT=str(report),
        GITHUB_OUTPUT=str(output),
    )
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert outputs["completed"] == completed
    assert outputs["blockers"] == "1"
    assert outputs["scanners-used"] == "Semgrep"
    assert outputs["pipeline-exit-code"] == str(exit_code)


@pytest.mark.skipif(shutil.which("jq") is None, reason="Action shell requires jq")
def test_action_does_not_reuse_a_report_after_crash(tmp_path):
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    step = next(step for step in action["runs"]["steps"] if step.get("id") == "run-pipeline")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scanner = bin_dir / "python3"
    scanner.write_text('#!/bin/bash\necho "Traceback: crash" >&2\nexit 1\n')
    scanner.chmod(0o755)
    reports = tmp_path / ".argus/hybrid-results"
    reports.mkdir(parents=True)
    (reports / "hybrid-scan-old.json").write_text(
        json.dumps(
            {
                "scan_status": "complete",
                "policy_gate_result": {"decision": "pass"},
                "total_findings": 0,
                "findings_by_severity": {},
            }
        )
    )
    output = tmp_path / "outputs"
    env = dict(
        os.environ,
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        INPUT_PROJECT_PATH=str(tmp_path),
        GITHUB_ACTION_PATH=str(ROOT),
        GITHUB_OUTPUT=str(output),
    )
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "completed=false" in output.read_text()
