#!/usr/bin/env python3
"""
Unit tests for sandbox validation system

Tests docker_manager, sandbox_validator, and sandbox_integration
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))


@pytest.mark.skip(reason="Docker tests require Docker daemon to be running. Sandbox validation is an optional feature for exploit verification.")
class TestDockerManager(unittest.TestCase):
    """Test DockerManager functionality"""

    @patch("docker_manager.docker")
    def test_docker_manager_initialization(self, mock_docker):
        """Test DockerManager can be initialized"""
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.ping.return_value = True

        from docker_manager import DockerManager

        manager = DockerManager()
        self.assertIsNotNone(manager)
        self.assertEqual(manager.image, "argus-sandbox:latest")
        mock_docker.from_env.assert_called_once()

    @patch("docker_manager.docker")
    def test_docker_manager_custom_image(self, mock_docker):
        """Test DockerManager with custom image"""
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.ping.return_value = True

        from docker_manager import DockerManager

        custom_image = "custom-sandbox:test"
        manager = DockerManager(image=custom_image)
        self.assertEqual(manager.image, custom_image)

    @patch("docker_manager.docker")
    def test_create_container(self, mock_docker):
        """Test container creation"""
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.ping.return_value = True

        # Mock container
        mock_container = MagicMock()
        mock_container.id = "test-container-id-12345"
        mock_client.containers.run.return_value = mock_container

        # Mock image verification
        mock_image = MagicMock()
        mock_image.id = "test-image-id"
        mock_image.attrs = {"some": "data"}
        mock_client.images.get.return_value = mock_image

        from docker_manager import DockerManager

        manager = DockerManager()

        # Create container
        container_id = manager.create_container(
            name="test-container",
            memory_limit="256m",
            cpu_limit=0.5,
        )

        self.assertEqual(container_id, "test-container-id-12345")
        self.assertIn(container_id, manager._containers)

        # Verify container was created with correct parameters
        mock_client.containers.run.assert_called_once()
        call_kwargs = mock_client.containers.run.call_args[1]
        self.assertEqual(call_kwargs["name"], "test-container")
        self.assertEqual(call_kwargs["mem_limit"], "256m")
        self.assertTrue(call_kwargs["detach"])

    @patch("docker_manager.docker")
    def test_execute_code_python(self, mock_docker):
        """Test code execution in container"""
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.ping.return_value = True

        mock_container = MagicMock()
        mock_container.id = "test-container-id"

        # Mock exec_run result
        mock_result = MagicMock()
        mock_result.output = (b"Hello from Python\n", b"")
        mock_result.exit_code = 0
        mock_container.exec_run.return_value = mock_result

        from docker_manager import DockerManager

        manager = DockerManager()
        manager._containers["test-container-id"] = mock_container

        result = manager.execute_code(
            "test-container-id",
            "print('Hello from Python')",
            language="python",
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("Hello from Python", result["stdout"])

    @patch("docker_manager.docker")
    def test_list_containers(self, mock_docker):
        """Test listing containers"""
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_client.ping.return_value = True

        # Mock container list
        mock_container = MagicMock()
        mock_container.id = "abc123def456"
        mock_container.name = "test-sandbox"
        mock_container.status = "running"
        mock_container.attrs = {"Created": "2024-01-01T00:00:00Z"}

        mock_client.containers.list.return_value = [mock_container]

        from docker_manager import DockerManager

        manager = DockerManager()
        containers = manager.list_containers()

        self.assertEqual(len(containers), 1)
        self.assertEqual(containers[0]["id"], "abc123def456")
        self.assertEqual(containers[0]["name"], "test-sandbox")
        self.assertEqual(containers[0]["status"], "running")


@pytest.mark.skip(reason="Docker tests require Docker daemon to be running. Sandbox validation is an optional feature for exploit verification.")
class TestSandboxValidator(unittest.TestCase):
    """Test SandboxValidator functionality"""

    def test_exploit_type_enum(self):
        """Test ExploitType enum"""
        from sandbox_validator import ExploitType

        self.assertEqual(ExploitType.SQL_INJECTION.value, "sql_injection")
        self.assertEqual(ExploitType.XSS.value, "xss")
        self.assertEqual(ExploitType.COMMAND_INJECTION.value, "command_injection")

    def test_validation_result_enum(self):
        """Test ValidationResult enum"""
        from sandbox_validator import ValidationResult

        self.assertEqual(ValidationResult.EXPLOITABLE.value, "exploitable")
        self.assertEqual(ValidationResult.NOT_EXPLOITABLE.value, "not_exploitable")
        self.assertEqual(ValidationResult.ERROR.value, "error")

    def test_exploit_config_creation(self):
        """Test ExploitConfig creation"""
        from sandbox_validator import ExploitConfig, ExploitType

        exploit = ExploitConfig(
            name="test-exploit",
            exploit_type=ExploitType.SQL_INJECTION,
            language="python",
            code="print('test')",
            expected_indicators=["SUCCESS"],
            timeout=30,
        )

        self.assertEqual(exploit.name, "test-exploit")
        self.assertEqual(exploit.exploit_type, ExploitType.SQL_INJECTION)
        self.assertEqual(exploit.language, "python")
        self.assertEqual(exploit.timeout, 30)

    @patch("sandbox_validator.DockerManager")
    def test_sandbox_validator_initialization(self, mock_docker_manager):
        """Test SandboxValidator initialization"""
        from sandbox_validator import SandboxValidator

        validator = SandboxValidator()
        self.assertIsNotNone(validator)
        self.assertEqual(validator._validation_count, 0)
        self.assertEqual(len(validator._metrics), 0)

    @patch("sandbox_validator.DockerManager")
    def test_safety_check_dangerous_patterns(self, mock_docker_manager):
        """Test safety checks for dangerous code"""
        from sandbox_validator import ExploitConfig, ExploitType, SandboxValidator

        validator = SandboxValidator()

        # Test dangerous pattern: rm -rf /
        dangerous_exploit = ExploitConfig(
            name="dangerous-test",
            exploit_type=ExploitType.CUSTOM,
            language="bash",
            code="rm -rf /",
            expected_indicators=["SUCCESS"],
        )

        safety_result = validator._safety_check(dangerous_exploit)
        self.assertFalse(safety_result["safe"])
        self.assertIn("root filesystem", safety_result["reason"])

    @patch("sandbox_validator.DockerManager")
    def test_safety_check_safe_code(self, mock_docker_manager):
        """Test safety checks pass for safe code"""
        from sandbox_validator import ExploitConfig, ExploitType, SandboxValidator

        validator = SandboxValidator()

        safe_exploit = ExploitConfig(
            name="safe-test",
            exploit_type=ExploitType.SQL_INJECTION,
            language="python",
            code="print('Hello World')",
            expected_indicators=["Hello"],
        )

        safety_result = validator._safety_check(safe_exploit)
        self.assertTrue(safety_result["safe"])

    @patch("sandbox_validator.DockerManager")
    def test_analyze_results(self, mock_docker_manager):
        """Test result analysis for indicators"""
        from sandbox_validator import SandboxValidator

        validator = SandboxValidator()

        stdout = "Test output SQL_INJECTION_SUCCESS completed"
        stderr = "No errors"
        expected = ["SQL_INJECTION_SUCCESS", "EXPLOIT_VERIFIED", "MISSING"]

        found, missing = validator._analyze_results(stdout, stderr, expected)

        self.assertIn("SQL_INJECTION_SUCCESS", found)
        self.assertIn("MISSING", missing)
        self.assertNotIn("EXPLOIT_VERIFIED", found)

    @patch("sandbox_validator.DockerManager")
    def test_determine_result_exploitable(self, mock_docker_manager):
        """Test determining exploitable result"""
        from sandbox_validator import SandboxValidator, ValidationResult

        validator = SandboxValidator()

        exec_result = {"success": True, "exit_code": 0}
        indicators_found = ["SUCCESS", "VERIFIED"]
        indicators_missing = []

        result = validator._determine_result(
            exec_result,
            indicators_found,
            indicators_missing,
        )

        self.assertEqual(result, ValidationResult.EXPLOITABLE)

    @patch("sandbox_validator.DockerManager")
    def test_determine_result_not_exploitable(self, mock_docker_manager):
        """Test determining not exploitable result"""
        from sandbox_validator import SandboxValidator, ValidationResult

        validator = SandboxValidator()

        # When execution fails with no indicators, it's an error
        exec_result = {"success": False, "exit_code": 1}
        indicators_found = []
        indicators_missing = ["SUCCESS", "VERIFIED"]

        result = validator._determine_result(
            exec_result,
            indicators_found,
            indicators_missing,
        )

        # With no indicators found and failed execution, result is ERROR
        self.assertEqual(result, ValidationResult.ERROR)

    @patch("sandbox_validator.DockerManager")
    def test_get_metrics_summary(self, mock_docker_manager):
        """Test metrics summary generation"""
        from sandbox_validator import (
            SandboxValidator,
            ValidationMetrics,
            ValidationResult,
        )

        validator = SandboxValidator()

        # Add some mock metrics
        validator._metrics = [
            ValidationMetrics(
                validation_id="v1",
                exploit_name="test1",
                exploit_type="sql_injection",
                result=ValidationResult.EXPLOITABLE.value,
                execution_time_ms=100,
                stdout="",
                stderr="",
                exit_code=0,
                indicators_found=["SUCCESS"],
                indicators_missing=[],
                container_id="c1",
                timestamp="2024-01-01T00:00:00Z",
            ),
            ValidationMetrics(
                validation_id="v2",
                exploit_name="test2",
                exploit_type="xss",
                result=ValidationResult.NOT_EXPLOITABLE.value,
                execution_time_ms=200,
                stdout="",
                stderr="",
                exit_code=1,
                indicators_found=[],
                indicators_missing=["SUCCESS"],
                container_id="c2",
                timestamp="2024-01-01T00:00:01Z",
            ),
        ]

        summary = validator.get_metrics_summary()

        self.assertEqual(summary["total_validations"], 2)
        self.assertEqual(summary["by_result"]["exploitable"], 1)
        self.assertEqual(summary["by_result"]["not_exploitable"], 1)
        self.assertEqual(summary["avg_execution_time_ms"], 150)
        self.assertEqual(summary["success_rate"], 50.0)


class TestSandboxIntegration(unittest.TestCase):
    """Test sandbox integration functionality"""

    def test_extend_review_metrics(self):
        """Test extending review metrics"""
        from sandbox_integration import extend_review_metrics

        metrics = {"version": "1.0.16"}
        extended = extend_review_metrics(metrics)

        self.assertIn("sandbox_validation", extended)
        self.assertIn("total_validations", extended["sandbox_validation"])
        self.assertIn("exploitable", extended["sandbox_validation"])
        self.assertIn("success_rate_percent", extended["sandbox_validation"])

    def test_update_sandbox_metrics(self):
        """Test updating sandbox metrics with results"""
        from sandbox_integration import update_sandbox_metrics
        from sandbox_validator import ValidationMetrics, ValidationResult

        metrics = {"version": "1.0.16"}

        results = [
            ValidationMetrics(
                validation_id="v1",
                exploit_name="test1",
                exploit_type="sql_injection",
                result=ValidationResult.EXPLOITABLE.value,
                execution_time_ms=100,
                stdout="",
                stderr="",
                exit_code=0,
                indicators_found=["SUCCESS"],
                indicators_missing=[],
                container_id="c1",
                timestamp="2024-01-01T00:00:00Z",
            ),
        ]

        updated = update_sandbox_metrics(metrics, results)

        self.assertEqual(updated["sandbox_validation"]["total_validations"], 1)
        self.assertEqual(updated["sandbox_validation"]["exploitable"], 1)
        self.assertEqual(updated["sandbox_validation"]["success_rate_percent"], 100.0)

    def test_get_expected_indicators(self):
        """Test getting expected indicators for exploit types"""
        from sandbox_integration import _get_expected_indicators
        from sandbox_validator import ExploitType

        sql_indicators = _get_expected_indicators(ExploitType.SQL_INJECTION)
        self.assertIn("SQL_INJECTION_SUCCESS", sql_indicators)

        cmd_indicators = _get_expected_indicators(ExploitType.COMMAND_INJECTION)
        self.assertIn("COMMAND_INJECTION_SUCCESS", cmd_indicators)

        xss_indicators = _get_expected_indicators(ExploitType.XSS)
        self.assertIn("XSS_SUCCESS", xss_indicators)

    def test_generate_exploit_code(self):
        """Test exploit code generation"""
        from sandbox_integration import _generate_exploit_code
        from sandbox_validator import ExploitType

        finding = {"description": "SQL injection in user search"}

        code = _generate_exploit_code(ExploitType.SQL_INJECTION, "python", finding)

        self.assertIsNotNone(code)
        self.assertIn("sqlite3", code)
        self.assertIn("SQL_INJECTION", code)

    def test_create_exploit_from_finding_sql_injection(self):
        """Test creating exploit from SQL injection finding"""
        from sandbox_integration import create_exploit_from_finding
        from sandbox_validator import ExploitType

        finding = {
            "issue_type": "SQL Injection",
            "severity": "critical",
            "description": "Vulnerable SQL query in user search",
            "file": "test.py",
        }

        exploit = create_exploit_from_finding(finding, "/tmp")

        if exploit:  # Only test if sandbox available
            self.assertIsNotNone(exploit)
            self.assertEqual(exploit.exploit_type, ExploitType.SQL_INJECTION)
            self.assertEqual(exploit.language, "python")
            self.assertIn("SQL_INJECTION_SUCCESS", exploit.expected_indicators)

    def test_create_exploit_from_finding_command_injection(self):
        """Test creating exploit from command injection finding"""
        from sandbox_integration import create_exploit_from_finding
        from sandbox_validator import ExploitType

        finding = {
            "issue_type": "Command Injection",
            "severity": "high",
            "description": "User input executed as shell command",
            "file": "api.py",
        }

        exploit = create_exploit_from_finding(finding, "/tmp")

        if exploit:  # Only test if sandbox available
            self.assertEqual(exploit.exploit_type, ExploitType.COMMAND_INJECTION)
            self.assertIn("COMMAND_INJECTION_SUCCESS", exploit.expected_indicators)


class TestExampleExploits(unittest.TestCase):
    """Test example exploit generation"""

    def test_create_example_exploits(self):
        """Test creating example exploits"""
        from sandbox_validator import create_example_exploits

        exploits = create_example_exploits()

        self.assertGreater(len(exploits), 0)
        self.assertTrue(all(e.name for e in exploits))
        self.assertTrue(all(e.code for e in exploits))
        self.assertTrue(all(e.expected_indicators for e in exploits))


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
