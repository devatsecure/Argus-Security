"""Tests for SBOM (Software Bill of Materials) generator.

Tests SBOMGenerator and TrivyScanner.generate_sbom() without requiring
Trivy to be installed. All subprocess calls are mocked.
"""

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from scripts.sbom_generator import (
    CYCLONEDX_FILENAME,
    CYCLONEDX_FORMAT,
    SCAN_TYPE_FS,
    SCAN_TYPE_IMAGE,
    SPDX_FILENAME,
    SPDX_FORMAT,
    SBOMGenerationError,
    SBOMGenerator,
)


# ---------------------------------------------------------------------------
# Sample SBOM data fixtures
# ---------------------------------------------------------------------------

SAMPLE_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.28.0",
            "purl": "pkg:pypi/requests@2.28.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {
            "type": "library",
            "name": "flask",
            "version": "2.3.0",
            "purl": "pkg:pypi/flask@2.3.0",
            "licenses": [{"license": {"id": "BSD-3-Clause"}}],
        },
        {
            "type": "framework",
            "name": "react",
            "version": "18.2.0",
            "purl": "pkg:npm/react@18.2.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"name": "MIT"}}],
        },
    ],
}

SAMPLE_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "packages": [
        {
            "name": "requests",
            "versionInfo": "2.28.0",
            "primaryPackagePurpose": "LIBRARY",
            "licenseConcluded": "Apache-2.0",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/requests@2.28.0",
                }
            ],
        },
        {
            "name": "express",
            "versionInfo": "4.18.2",
            "primaryPackagePurpose": "FRAMEWORK",
            "licenseConcluded": "MIT",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/express@4.18.2",
                }
            ],
        },
        {
            "name": "go-chi",
            "versionInfo": "5.0.10",
            "primaryPackagePurpose": "LIBRARY",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:golang/github.com/go-chi/chi@5.0.10",
                }
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# SBOMGenerator unit tests
# ---------------------------------------------------------------------------


class TestSBOMGeneratorInit:
    """Test SBOMGenerator initialization."""

    def test_default_init(self):
        gen = SBOMGenerator()
        assert gen.trivy_path == "trivy"
        assert gen.output_dir == "."

    def test_custom_init(self):
        gen = SBOMGenerator(trivy_path="/usr/local/bin/trivy", output_dir="/tmp/sboms")
        assert gen.trivy_path == "/usr/local/bin/trivy"
        assert gen.output_dir == "/tmp/sboms"


class TestBuildCommand:
    """Test Trivy command construction."""

    def test_fs_cyclonedx_command(self):
        gen = SBOMGenerator()
        cmd = gen._build_command("/app", CYCLONEDX_FORMAT, "/out/sbom.json", SCAN_TYPE_FS)
        assert cmd == [
            "trivy", "fs", "--format", "cyclonedx",
            "--output", "/out/sbom.json", "--quiet", "/app",
        ]

    def test_image_spdx_command(self):
        gen = SBOMGenerator()
        cmd = gen._build_command(
            "nginx:latest", SPDX_FORMAT, "/out/sbom.json", SCAN_TYPE_IMAGE
        )
        assert cmd == [
            "trivy", "image", "--format", "spdx-json",
            "--output", "/out/sbom.json", "--quiet", "nginx:latest",
        ]

    def test_custom_trivy_path(self):
        gen = SBOMGenerator(trivy_path="/opt/trivy")
        cmd = gen._build_command("/app", CYCLONEDX_FORMAT, "/out/sbom.json", SCAN_TYPE_FS)
        assert cmd[0] == "/opt/trivy"

    def test_invalid_scan_type_raises(self):
        gen = SBOMGenerator()
        with pytest.raises(ValueError, match="Invalid scan_type"):
            gen._build_command("/app", CYCLONEDX_FORMAT, "/out/sbom.json", "repo")


class TestRunTrivy:
    """Test Trivy subprocess execution and error handling."""

    @patch("scripts.sbom_generator.subprocess.run")
    def test_successful_run(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        gen = SBOMGenerator()
        result = gen._run_trivy(["trivy", "fs", "--format", "cyclonedx", "."])
        assert result.returncode == 0
        mock_run.assert_called_once()
        # Verify TRIVY_NO_PROGRESS is set
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs["env"]["TRIVY_NO_PROGRESS"] == "true"

    @patch("scripts.sbom_generator.subprocess.run", side_effect=FileNotFoundError)
    def test_trivy_not_installed(self, mock_run):
        gen = SBOMGenerator()
        with pytest.raises(SBOMGenerationError, match="Trivy binary not found"):
            gen._run_trivy(["trivy", "fs", "."])

    @patch(
        "scripts.sbom_generator.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=300),
    )
    def test_trivy_timeout(self, mock_run):
        gen = SBOMGenerator()
        with pytest.raises(SBOMGenerationError, match="timed out"):
            gen._run_trivy(["trivy", "fs", "."])

    @patch(
        "scripts.sbom_generator.subprocess.run",
        side_effect=subprocess.SubprocessError("broken pipe"),
    )
    def test_subprocess_error(self, mock_run):
        gen = SBOMGenerator()
        with pytest.raises(SBOMGenerationError, match="subprocess error"):
            gen._run_trivy(["trivy", "fs", "."])

    @patch("scripts.sbom_generator.subprocess.run")
    def test_nonzero_exit_code(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="database error"
        )
        gen = SBOMGenerator()
        with pytest.raises(SBOMGenerationError, match="exited with code 1"):
            gen._run_trivy(["trivy", "fs", "."])

    @patch("scripts.sbom_generator.subprocess.run")
    def test_nonzero_exit_empty_stderr(self, mock_run):
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="")
        gen = SBOMGenerator()
        with pytest.raises(SBOMGenerationError, match="unknown error"):
            gen._run_trivy(["trivy", "fs", "."])


class TestGenerateCycloneDX:
    """Test CycloneDX SBOM generation."""

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_successful_generation(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = SAMPLE_CYCLONEDX

        gen = SBOMGenerator(output_dir="/tmp/sboms")
        result = gen.generate_cyclonedx("/app")

        assert result["success"] is True
        assert result["sbom_path"] == str(Path("/tmp/sboms") / CYCLONEDX_FILENAME)
        assert result["component_count"] == 4
        assert result["format"] == "CycloneDX 1.5"
        assert "error" not in result

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_correct_trivy_command(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = {"components": []}

        gen = SBOMGenerator(output_dir="/tmp/out")
        gen.generate_cyclonedx("/my/project", scan_type="fs")

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "trivy"
        assert cmd[1] == "fs"
        assert "--format" in cmd
        assert cmd[cmd.index("--format") + 1] == "cyclonedx"
        assert "/my/project" in cmd

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_image_scan_type(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = {"components": []}

        gen = SBOMGenerator(output_dir="/tmp/out")
        gen.generate_cyclonedx("nginx:latest", scan_type="image")

        cmd = mock_run.call_args[0][0]
        assert cmd[1] == "image"
        assert "nginx:latest" in cmd

    @patch(
        "scripts.sbom_generator.SBOMGenerator._run_trivy",
        side_effect=SBOMGenerationError("Trivy binary not found"),
    )
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_trivy_not_installed_returns_error(self, mock_mkdir, mock_run):
        gen = SBOMGenerator()
        result = gen.generate_cyclonedx("/app")

        assert result["success"] is False
        assert result["component_count"] == 0
        assert "error" in result
        assert "Trivy binary not found" in result["error"]

    @patch("scripts.sbom_generator.Path.mkdir")
    def test_invalid_scan_type_returns_error(self, mock_mkdir):
        gen = SBOMGenerator()
        result = gen.generate_cyclonedx("/app", scan_type="invalid")

        assert result["success"] is False
        assert "error" in result
        assert "Invalid scan_type" in result["error"]


class TestGenerateSPDX:
    """Test SPDX SBOM generation."""

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_successful_generation(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = SAMPLE_SPDX

        gen = SBOMGenerator(output_dir="/tmp/sboms")
        result = gen.generate_spdx("/app")

        assert result["success"] is True
        assert result["sbom_path"] == str(Path("/tmp/sboms") / SPDX_FILENAME)
        assert result["component_count"] == 3
        assert result["format"] == "SPDX 2.3"
        assert "error" not in result

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_correct_trivy_command(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = {"packages": []}

        gen = SBOMGenerator(output_dir="/tmp/out")
        gen.generate_spdx("/my/project", scan_type="fs")

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "trivy"
        assert cmd[1] == "fs"
        assert cmd[cmd.index("--format") + 1] == "spdx-json"

    @patch(
        "scripts.sbom_generator.SBOMGenerator._run_trivy",
        side_effect=SBOMGenerationError("timed out"),
    )
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_timeout_returns_error(self, mock_mkdir, mock_run):
        gen = SBOMGenerator()
        result = gen.generate_spdx("/app")

        assert result["success"] is False
        assert "timed out" in result["error"]


class TestGenerateAll:
    """Test generating both CycloneDX and SPDX together."""

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_generates_both_formats(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        # First call returns CycloneDX, second returns SPDX
        mock_parse.side_effect = [SAMPLE_CYCLONEDX, SAMPLE_SPDX]

        gen = SBOMGenerator(output_dir="/tmp/sboms")
        result = gen.generate_all("/app")

        assert "cyclonedx" in result
        assert "spdx" in result
        assert result["cyclonedx"]["success"] is True
        assert result["spdx"]["success"] is True
        assert result["cyclonedx"]["format"] == "CycloneDX 1.5"
        assert result["spdx"]["format"] == "SPDX 2.3"

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_partial_failure(self, mock_mkdir, mock_run, mock_parse):
        """One format succeeds, the other fails."""
        mock_parse.return_value = SAMPLE_CYCLONEDX
        # First call succeeds, second raises
        mock_run.side_effect = [
            MagicMock(returncode=0),
            SBOMGenerationError("spdx failed"),
        ]

        gen = SBOMGenerator(output_dir="/tmp/sboms")
        result = gen.generate_all("/app")

        assert result["cyclonedx"]["success"] is True
        assert result["spdx"]["success"] is False

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_passes_scan_type(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = {"components": [], "packages": []}

        gen = SBOMGenerator(output_dir="/tmp/out")
        gen.generate_all("nginx:latest", scan_type="image")

        # Should have been called twice (cyclonedx + spdx)
        assert mock_run.call_count == 2
        for call in mock_run.call_args_list:
            cmd = call[0][0]
            assert cmd[1] == "image"


class TestGetComponentSummary:
    """Test SBOM component summary parsing."""

    def test_cyclonedx_summary(self, tmp_path):
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(SAMPLE_CYCLONEDX))

        gen = SBOMGenerator()
        summary = gen.get_component_summary(str(sbom_file))

        assert summary["total_components"] == 4
        assert summary["by_type"]["library"] == 3
        assert summary["by_type"]["framework"] == 1
        assert summary["by_ecosystem"]["pypi"] == 2
        assert summary["by_ecosystem"]["npm"] == 2
        assert "Apache-2.0" in summary["licenses"]
        assert "BSD-3-Clause" in summary["licenses"]
        assert "MIT" in summary["licenses"]

    def test_spdx_summary(self, tmp_path):
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(SAMPLE_SPDX))

        gen = SBOMGenerator()
        summary = gen.get_component_summary(str(sbom_file))

        assert summary["total_components"] == 3
        assert summary["by_type"]["library"] == 2
        assert summary["by_type"]["framework"] == 1
        assert summary["by_ecosystem"]["pypi"] == 1
        assert summary["by_ecosystem"]["npm"] == 1
        assert summary["by_ecosystem"]["golang"] == 1
        # NOASSERTION should be excluded
        assert "Apache-2.0" in summary["licenses"]
        assert "MIT" in summary["licenses"]
        assert len(summary["licenses"]) == 2

    def test_missing_file_returns_error(self):
        gen = SBOMGenerator()
        summary = gen.get_component_summary("/nonexistent/sbom.json")

        assert summary["total_components"] == 0
        assert "error" in summary

    def test_invalid_json_returns_error(self, tmp_path):
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text("not valid json {{{")

        gen = SBOMGenerator()
        summary = gen.get_component_summary(str(sbom_file))

        assert summary["total_components"] == 0
        assert "error" in summary

    def test_unrecognized_format_returns_error(self, tmp_path):
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps({"unknown": "format"}))

        gen = SBOMGenerator()
        summary = gen.get_component_summary(str(sbom_file))

        assert summary["total_components"] == 0
        assert "error" in summary
        assert "Unrecognized SBOM format" in summary["error"]

    def test_empty_components(self, tmp_path):
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps({"components": []}))

        gen = SBOMGenerator()
        summary = gen.get_component_summary(str(sbom_file))

        assert summary["total_components"] == 0
        assert summary["by_type"] == {}
        assert summary["by_ecosystem"] == {}
        assert summary["licenses"] == []

    def test_components_without_purl(self, tmp_path):
        sbom_data = {
            "components": [
                {"type": "library", "name": "foo", "version": "1.0"},
            ]
        }
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom_data))

        gen = SBOMGenerator()
        summary = gen.get_component_summary(str(sbom_file))

        assert summary["total_components"] == 1
        assert summary["by_type"]["library"] == 1
        assert summary["by_ecosystem"] == {}


class TestExtractEcosystem:
    """Test purl ecosystem extraction."""

    def test_pypi(self):
        assert SBOMGenerator._extract_ecosystem_from_purl("pkg:pypi/requests@2.28") == "pypi"

    def test_npm(self):
        assert SBOMGenerator._extract_ecosystem_from_purl("pkg:npm/lodash@4.17") == "npm"

    def test_golang(self):
        assert (
            SBOMGenerator._extract_ecosystem_from_purl(
                "pkg:golang/github.com/gin-gonic/gin@1.9"
            )
            == "golang"
        )

    def test_maven(self):
        assert (
            SBOMGenerator._extract_ecosystem_from_purl(
                "pkg:maven/org.apache/commons-lang3@3.12"
            )
            == "maven"
        )

    def test_empty_string(self):
        assert SBOMGenerator._extract_ecosystem_from_purl("") is None

    def test_none_value(self):
        assert SBOMGenerator._extract_ecosystem_from_purl(None) is None

    def test_invalid_purl(self):
        assert SBOMGenerator._extract_ecosystem_from_purl("not-a-purl") is None

    def test_purl_no_type(self):
        assert SBOMGenerator._extract_ecosystem_from_purl("pkg:/name@1.0") is None


class TestNoShellTrue:
    """Verify no shell=True in subprocess calls."""

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.subprocess.run")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_no_shell_true_in_cyclonedx(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = {"components": []}

        gen = SBOMGenerator()
        gen.generate_cyclonedx("/app")

        call_kwargs = mock_run.call_args.kwargs
        assert "shell" not in call_kwargs or call_kwargs["shell"] is not True

    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.subprocess.run")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_no_shell_true_in_spdx(self, mock_mkdir, mock_run, mock_parse):
        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = {"packages": []}

        gen = SBOMGenerator()
        gen.generate_spdx("/app")

        call_kwargs = mock_run.call_args.kwargs
        assert "shell" not in call_kwargs or call_kwargs["shell"] is not True


# ---------------------------------------------------------------------------
# TrivyScanner.generate_sbom() integration tests
# ---------------------------------------------------------------------------


class TestTrivyScannerGenerateSBOM:
    """Test the generate_sbom() method on TrivyScanner."""

    @patch("scripts.trivy_scanner.TrivyScanner._verify_trivy_installation")
    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_generate_sbom_both_formats(
        self, mock_mkdir, mock_run, mock_parse, mock_verify
    ):
        from scripts.trivy_scanner import TrivyScanner

        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.side_effect = [SAMPLE_CYCLONEDX, SAMPLE_SPDX]

        scanner = TrivyScanner()
        result = scanner.generate_sbom("/app", output_dir="/tmp/sboms")

        assert "cyclonedx" in result
        assert "spdx" in result
        assert result["cyclonedx"]["success"] is True
        assert result["spdx"]["success"] is True

    @patch("scripts.trivy_scanner.TrivyScanner._verify_trivy_installation")
    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_generate_sbom_single_format(
        self, mock_mkdir, mock_run, mock_parse, mock_verify
    ):
        from scripts.trivy_scanner import TrivyScanner

        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = SAMPLE_CYCLONEDX

        scanner = TrivyScanner()
        result = scanner.generate_sbom("/app", formats=["cyclonedx"])

        assert "cyclonedx" in result
        assert "spdx" not in result
        assert result["cyclonedx"]["success"] is True

    @patch("scripts.trivy_scanner.TrivyScanner._verify_trivy_installation")
    def test_generate_sbom_invalid_format(self, mock_verify):
        from scripts.trivy_scanner import TrivyScanner

        scanner = TrivyScanner()
        result = scanner.generate_sbom("/app", formats=["xml"])

        assert result["success"] is False
        assert "Unknown SBOM format" in result["error"]

    @patch("scripts.trivy_scanner.TrivyScanner._verify_trivy_installation")
    @patch(
        "scripts.sbom_generator.SBOMGenerator._run_trivy",
        side_effect=SBOMGenerationError("Trivy binary not found"),
    )
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_generate_sbom_trivy_not_installed(
        self, mock_mkdir, mock_run, mock_verify
    ):
        from scripts.trivy_scanner import TrivyScanner

        scanner = TrivyScanner()
        result = scanner.generate_sbom("/app")

        # Should still return results (with success=False per format)
        assert "cyclonedx" in result
        assert result["cyclonedx"]["success"] is False
        assert "Trivy binary not found" in result["cyclonedx"]["error"]

    @patch("scripts.trivy_scanner.TrivyScanner._verify_trivy_installation")
    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_generate_sbom_default_formats(
        self, mock_mkdir, mock_run, mock_parse, mock_verify
    ):
        """When formats=None, both cyclonedx and spdx are generated."""
        from scripts.trivy_scanner import TrivyScanner

        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.side_effect = [SAMPLE_CYCLONEDX, SAMPLE_SPDX]

        scanner = TrivyScanner()
        result = scanner.generate_sbom("/app")

        assert "cyclonedx" in result
        assert "spdx" in result

    @patch("scripts.trivy_scanner.TrivyScanner._verify_trivy_installation")
    @patch("scripts.sbom_generator.SBOMGenerator._parse_sbom_file")
    @patch("scripts.sbom_generator.SBOMGenerator._run_trivy")
    @patch("scripts.sbom_generator.Path.mkdir")
    def test_generate_sbom_spdx_only(
        self, mock_mkdir, mock_run, mock_parse, mock_verify
    ):
        from scripts.trivy_scanner import TrivyScanner

        mock_run.return_value = MagicMock(returncode=0)
        mock_parse.return_value = SAMPLE_SPDX

        scanner = TrivyScanner()
        result = scanner.generate_sbom("/app", formats=["spdx"])

        assert "spdx" in result
        assert "cyclonedx" not in result
        assert result["spdx"]["success"] is True
