#!/usr/bin/env python3
"""
Container Runtime Security Monitoring for Argus
Falco-based runtime threat detection

This module monitors container runtime behavior using Falco to detect:
- Unexpected process execution (shells, suspicious binaries)
- Network connections to suspicious IPs or ports
- File access outside expected paths
- Privilege escalation attempts
- Cryptocurrency mining indicators
- Data exfiltration patterns
"""

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any
import re
import sys

logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """Security threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatType(Enum):
    """Types of runtime threats"""
    SHELL_IN_CONTAINER = "shell_in_container"
    CRYPTO_MINING = "cryptocurrency_mining"
    SENSITIVE_FILE_ACCESS = "sensitive_file_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_NETWORK = "suspicious_network"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_BINARY = "malicious_binary"
    REVERSE_SHELL = "reverse_shell"
    CONTAINER_ESCAPE = "container_escape"


@dataclass
class RuntimeEvent:
    """Runtime security event from Falco"""
    event_id: str
    timestamp: str
    severity: ThreatSeverity
    rule_name: str
    description: str
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    process: Optional[str] = None
    command: Optional[str] = None
    file_path: Optional[str] = None
    network_connection: Optional[Dict[str, Any]] = None
    user: Optional[str] = None
    syscall: Optional[str] = None
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data


@dataclass
class ThreatAlert:
    """Security threat alert"""
    alert_id: str
    timestamp: str
    severity: ThreatSeverity
    threat_type: ThreatType
    description: str
    indicators: List[str]
    remediation: str
    confidence: float = 1.0
    related_events: List[RuntimeEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp,
            'severity': self.severity.value,
            'threat_type': self.threat_type.value,
            'description': self.description,
            'indicators': self.indicators,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'event_count': len(self.related_events)
        }


class RuntimeSecurityMonitor:
    """Monitor container runtime security with Falco"""

    # Suspicious command patterns
    SUSPICIOUS_PATTERNS = {
        "shell_in_container": [
            r"/bin/bash", r"/bin/sh", r"/bin/zsh", r"/bin/dash",
            r"/bin/csh", r"/bin/tcsh", r"/bin/ksh"
        ],
        "crypto_mining": [
            r"xmrig", r"minerd", r"ccminer", r"ethminer", r"cgminer",
            r"stratum\+tcp", r"pool\..*\.com", r"cryptonight",
            r"monero", r"xmr-stak", r"claymore"
        ],
        "suspicious_network": [
            r"nc\s", r"netcat", r"ncat", r"socat", r"telnet",
            r"wget.*\|\s*sh", r"curl.*\|\s*sh", r"curl.*\|\s*bash"
        ],
        "sensitive_files": [
            r"/etc/shadow", r"/etc/passwd", r"\.ssh/id_rsa",
            r"\.ssh/id_dsa", r"\.aws/credentials", r"/root/\.bash_history",
            r"\.kube/config", r"\.docker/config\.json", r"\.npmrc",
            r"\.pypirc", r"\.gem/credentials"
        ],
        "reverse_shell": [
            r"bash\s+-i", r"sh\s+-i", r"/dev/tcp/", r"/dev/udp/",
            r"0<&\d+", r"exec\s+\d+<>", r"python.*socket\.socket"
        ],
        "privilege_escalation": [
            r"sudo\s", r"su\s+-", r"pkexec", r"doas\s",
            r"setuid", r"setgid", r"chmod\s+[u+]s"
        ],
        "data_exfiltration": [
            r"scp\s.*@", r"rsync\s.*@", r"curl.*-T", r"wget.*--post-file",
            r"base64.*\|.*curl", r"tar.*\|.*nc", r"dd.*of=/dev/tcp"
        ],
        "malicious_binary": [
            r"masscan", r"nmap", r"nikto", r"sqlmap", r"metasploit",
            r"msfvenom", r"msfconsole", r"mimikatz"
        ]
    }

    # Suspicious ports
    SUSPICIOUS_PORTS = [
        4444,  # Metasploit default
        5555,  # Android Debug Bridge
        6666, 6667, 6668,  # IRC
        1337, 31337,  # Leet ports
        8080, 8888,  # Common proxy ports
        3389,  # RDP
        22,  # SSH (suspicious from container)
        23,  # Telnet
    ]

    # Suspicious IP patterns (examples)
    SUSPICIOUS_IP_PATTERNS = [
        r"^10\.0\.0\.",  # Internal networks (context-dependent)
        r"^192\.168\.",  # Private networks
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",  # Private Class B
    ]

    def __init__(self, falco_path: str = "falco", rules_file: Optional[str] = None):
        """
        Initialize runtime security monitor

        Args:
            falco_path: Path to Falco binary
            rules_file: Optional custom Falco rules file
        """
        self.falco_path = falco_path
        self.rules_file = rules_file
        self.events: List[RuntimeEvent] = []
        self.alerts: List[ThreatAlert] = []
        self.stats = {
            'total_events': 0,
            'events_by_severity': {},
            'events_by_container': {},
            'threats_detected': 0,
            'monitoring_start': None,
            'monitoring_end': None
        }

        # Check if Falco is available
        if not self._check_falco_installed():
            logger.warning("Falco not installed - runtime monitoring unavailable")

    def _check_falco_installed(self) -> bool:
        """Check if Falco is installed and accessible"""
        try:
            result = subprocess.run(
                [self.falco_path, "--version"],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode == 0:
                version = result.stdout.decode().strip()
                logger.info(f"Falco detected: {version}")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"Falco check failed: {e}")
            return False

    def monitor_realtime(
        self,
        duration_seconds: int = 60,
        container_filter: Optional[str] = None,
        output_file: Optional[str] = None
    ) -> List[ThreatAlert]:
        """
        Monitor runtime events in real-time

        Args:
            duration_seconds: How long to monitor
            container_filter: Optional container name filter
            output_file: Optional file to write events to

        Returns:
            List of threat alerts detected
        """
        logger.info(f"Starting runtime monitoring for {duration_seconds} seconds")
        self.stats['monitoring_start'] = datetime.utcnow().isoformat()

        if not self._check_falco_installed():
            logger.error("Falco not available - cannot monitor")
            return []

        # Build Falco command
        cmd = [
            self.falco_path,
            "-o", "json_output=true",
            "-o", "json_include_output_property=true",
            "-o", "file_output.enabled=false"
        ]

        # Add custom rules file if provided
        if self.rules_file and Path(self.rules_file).exists():
            cmd.extend(["-r", self.rules_file])

        # Add container filter if specified
        if container_filter:
            cmd.extend(["-k", f"container.name={container_filter}"])

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            start_time = time.time()
            event_count = 0

            # Read events line by line
            while (time.time() - start_time) < duration_seconds:
                if process.poll() is not None:
                    logger.warning("Falco process terminated unexpectedly")
                    break

                line = process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                try:
                    event_data = json.loads(line.strip())
                    event = self._parse_falco_event(event_data)
                    if event:
                        self.events.append(event)
                        event_count += 1
                        self._update_stats(event)

                        # Check for threats
                        self._check_for_threats(event)

                        # Write to output file if specified
                        if output_file:
                            with open(output_file, 'a') as f:
                                f.write(json.dumps(event.to_dict()) + '\n')

                        # Log high-severity events immediately
                        if event.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
                            logger.warning(
                                f"High-severity event: {event.rule_name} - {event.description}"
                            )

                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse Falco output: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
                    continue

            # Stop Falco gracefully
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("Falco did not terminate gracefully, killing")
                process.kill()

        except Exception as e:
            logger.error(f"Runtime monitoring failed: {e}")
            return []

        self.stats['monitoring_end'] = datetime.utcnow().isoformat()
        self.stats['total_events'] = len(self.events)

        logger.info(
            f"Monitoring complete: {len(self.events)} events, "
            f"{len(self.alerts)} threats detected"
        )

        return self.alerts

    def analyze_log_file(self, log_file: str) -> List[ThreatAlert]:
        """
        Analyze existing Falco JSON log file

        Args:
            log_file: Path to Falco JSON log file

        Returns:
            List of threat alerts detected
        """
        logger.info(f"Analyzing Falco log: {log_file}")
        self.stats['monitoring_start'] = datetime.utcnow().isoformat()

        if not Path(log_file).exists():
            logger.error(f"Log file not found: {log_file}")
            return []

        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event_data = json.loads(line)
                    event = self._parse_falco_event(event_data)
                    if event:
                        self.events.append(event)
                        self._update_stats(event)
                        self._check_for_threats(event)
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse line {line_num}: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error processing line {line_num}: {e}")
                    continue

        self.stats['monitoring_end'] = datetime.utcnow().isoformat()
        self.stats['total_events'] = len(self.events)

        logger.info(
            f"Analysis complete: {len(self.events)} events, "
            f"{len(self.alerts)} threats detected"
        )

        return self.alerts

    def _parse_falco_event(self, data: Dict[str, Any]) -> Optional[RuntimeEvent]:
        """Parse Falco JSON event into RuntimeEvent"""
        if "output" not in data:
            return None

        # Map Falco priority to our severity
        priority_map = {
            "Emergency": ThreatSeverity.CRITICAL,
            "Alert": ThreatSeverity.CRITICAL,
            "Critical": ThreatSeverity.HIGH,
            "Error": ThreatSeverity.MEDIUM,
            "Warning": ThreatSeverity.LOW,
            "Notice": ThreatSeverity.INFO,
            "Informational": ThreatSeverity.INFO,
            "Debug": ThreatSeverity.INFO
        }

        severity = priority_map.get(data.get("priority", ""), ThreatSeverity.INFO)

        # Extract output fields
        output_fields = data.get("output_fields", {})

        # Build network connection info if available
        network_conn = None
        if output_fields.get("fd.rip"):
            network_conn = {
                "destination_ip": output_fields.get("fd.rip"),
                "destination_port": output_fields.get("fd.rport"),
                "source_ip": output_fields.get("fd.lip"),
                "source_port": output_fields.get("fd.lport"),
                "protocol": output_fields.get("fd.l4proto")
            }

        return RuntimeEvent(
            event_id=f"evt_{int(time.time() * 1000000)}_{len(self.events)}",
            timestamp=data.get("time", datetime.utcnow().isoformat()),
            severity=severity,
            rule_name=data.get("rule", "unknown"),
            description=data.get("output", ""),
            container_id=output_fields.get("container.id"),
            container_name=output_fields.get("container.name"),
            process=output_fields.get("proc.name"),
            command=output_fields.get("proc.cmdline"),
            file_path=output_fields.get("fd.name"),
            network_connection=network_conn,
            user=output_fields.get("user.name"),
            syscall=output_fields.get("evt.type"),
            raw_event=data
        )

    def _update_stats(self, event: RuntimeEvent):
        """Update statistics with new event"""
        # Count by severity
        sev_key = event.severity.value
        self.stats['events_by_severity'][sev_key] = \
            self.stats['events_by_severity'].get(sev_key, 0) + 1

        # Count by container
        if event.container_name:
            self.stats['events_by_container'][event.container_name] = \
                self.stats['events_by_container'].get(event.container_name, 0) + 1

    def _check_for_threats(self, event: RuntimeEvent):
        """Analyze event for security threats"""
        # Check each threat type
        self._check_shell_execution(event)
        self._check_crypto_mining(event)
        self._check_sensitive_files(event)
        self._check_privilege_escalation(event)
        self._check_suspicious_network(event)
        self._check_data_exfiltration(event)
        self._check_reverse_shell(event)
        self._check_malicious_binary(event)

    def _check_shell_execution(self, event: RuntimeEvent):
        """Check for shell execution in container"""
        if not event.command:
            return

        for pattern in self.SUSPICIOUS_PATTERNS["shell_in_container"]:
            if re.search(pattern, event.command):
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.SHELL_IN_CONTAINER,
                    severity=ThreatSeverity.HIGH,
                    description=f"Shell executed in container {event.container_name or 'unknown'}",
                    indicators=[
                        f"Command: {event.command}",
                        f"Process: {event.process}",
                        f"User: {event.user or 'unknown'}"
                    ],
                    remediation=(
                        "Investigate why shell was spawned. Containers should not run "
                        "interactive shells in production. Consider using exec for "
                        "debugging instead of embedding shells in images."
                    ),
                    confidence=0.85
                )
                return

    def _check_crypto_mining(self, event: RuntimeEvent):
        """Check for cryptocurrency mining activity"""
        search_text = f"{event.command or ''} {event.process or ''}"

        for pattern in self.SUSPICIOUS_PATTERNS["crypto_mining"]:
            if re.search(pattern, search_text, re.IGNORECASE):
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.CRYPTO_MINING,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"Cryptocurrency mining detected in {event.container_name or 'container'}",
                    indicators=[
                        f"Process: {event.process}",
                        f"Command: {event.command}",
                        f"Pattern matched: {pattern}"
                    ],
                    remediation=(
                        "IMMEDIATE ACTION REQUIRED: Terminate container immediately. "
                        "Investigate how mining software was introduced. "
                        "Rotate all credentials and secrets. "
                        "Review image build pipeline for compromise."
                    ),
                    confidence=0.95
                )
                return

    def _check_sensitive_files(self, event: RuntimeEvent):
        """Check for access to sensitive files"""
        if not event.file_path:
            return

        for pattern in self.SUSPICIOUS_PATTERNS["sensitive_files"]:
            if re.search(pattern, event.file_path):
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.SENSITIVE_FILE_ACCESS,
                    severity=ThreatSeverity.HIGH,
                    description=f"Access to sensitive file: {event.file_path}",
                    indicators=[
                        f"File: {event.file_path}",
                        f"Process: {event.process}",
                        f"User: {event.user or 'unknown'}",
                        f"Container: {event.container_name or 'unknown'}"
                    ],
                    remediation=(
                        "Verify if file access is legitimate for application function. "
                        "Review container security context and volume mounts. "
                        "Consider using secrets management instead of file-based credentials. "
                        "Implement principle of least privilege."
                    ),
                    confidence=0.80
                )
                return

    def _check_privilege_escalation(self, event: RuntimeEvent):
        """Check for privilege escalation attempts"""
        if not event.command:
            return

        for pattern in self.SUSPICIOUS_PATTERNS["privilege_escalation"]:
            if re.search(pattern, event.command):
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.PRIVILEGE_ESCALATION,
                    severity=ThreatSeverity.CRITICAL,
                    description="Privilege escalation attempt detected",
                    indicators=[
                        f"Command: {event.command}",
                        f"User: {event.user or 'unknown'}",
                        f"Process: {event.process}"
                    ],
                    remediation=(
                        "Investigate privilege escalation attempt immediately. "
                        "Verify if elevation is required for legitimate function. "
                        "Review container capabilities and security context. "
                        "Run containers as non-root user when possible."
                    ),
                    confidence=0.90
                )
                return

    def _check_suspicious_network(self, event: RuntimeEvent):
        """Check for suspicious network activity"""
        # Check command patterns
        if event.command:
            for pattern in self.SUSPICIOUS_PATTERNS["suspicious_network"]:
                if re.search(pattern, event.command):
                    self._create_alert(
                        event=event,
                        threat_type=ThreatType.SUSPICIOUS_NETWORK,
                        severity=ThreatSeverity.HIGH,
                        description="Suspicious network tool usage detected",
                        indicators=[
                            f"Command: {event.command}",
                            f"Process: {event.process}"
                        ],
                        remediation=(
                            "Investigate network tool usage. These tools are commonly "
                            "used for reconnaissance or establishing backdoors. "
                            "Verify if tools are required for legitimate function. "
                            "Consider network policies to restrict outbound connections."
                        ),
                        confidence=0.85
                    )
                    return

        # Check network connections
        if event.network_connection:
            dest_port = event.network_connection.get("destination_port")
            if dest_port in self.SUSPICIOUS_PORTS:
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.SUSPICIOUS_NETWORK,
                    severity=ThreatSeverity.MEDIUM,
                    description=f"Connection to suspicious port: {dest_port}",
                    indicators=[
                        f"Destination: {event.network_connection.get('destination_ip')}:{dest_port}",
                        f"Process: {event.process}",
                        f"Protocol: {event.network_connection.get('protocol')}"
                    ],
                    remediation=(
                        f"Verify if connection to port {dest_port} is expected. "
                        "This port is commonly associated with malicious activity. "
                        "Review network policies and egress filtering."
                    ),
                    confidence=0.70
                )

    def _check_data_exfiltration(self, event: RuntimeEvent):
        """Check for potential data exfiltration"""
        if not event.command:
            return

        for pattern in self.SUSPICIOUS_PATTERNS["data_exfiltration"]:
            if re.search(pattern, event.command):
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    severity=ThreatSeverity.CRITICAL,
                    description="Potential data exfiltration detected",
                    indicators=[
                        f"Command: {event.command}",
                        f"Process: {event.process}",
                        f"Pattern: {pattern}"
                    ],
                    remediation=(
                        "IMMEDIATE INVESTIGATION REQUIRED: Command pattern suggests "
                        "data exfiltration attempt. Review what data may have been accessed. "
                        "Check network logs for unusual outbound transfers. "
                        "Implement DLP controls and egress filtering."
                    ),
                    confidence=0.90
                )
                return

    def _check_reverse_shell(self, event: RuntimeEvent):
        """Check for reverse shell patterns"""
        if not event.command:
            return

        for pattern in self.SUSPICIOUS_PATTERNS["reverse_shell"]:
            if re.search(pattern, event.command):
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.REVERSE_SHELL,
                    severity=ThreatSeverity.CRITICAL,
                    description="Reverse shell detected",
                    indicators=[
                        f"Command: {event.command}",
                        f"Process: {event.process}"
                    ],
                    remediation=(
                        "CRITICAL: Reverse shell detected - indicates active compromise. "
                        "Terminate container immediately. Isolate affected systems. "
                        "Begin incident response procedures. "
                        "Rotate all credentials and investigate breach timeline."
                    ),
                    confidence=0.95
                )
                return

    def _check_malicious_binary(self, event: RuntimeEvent):
        """Check for known malicious binaries"""
        search_text = f"{event.command or ''} {event.process or ''}"

        for pattern in self.SUSPICIOUS_PATTERNS["malicious_binary"]:
            if re.search(pattern, search_text, re.IGNORECASE):
                self._create_alert(
                    event=event,
                    threat_type=ThreatType.MALICIOUS_BINARY,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"Known attack tool detected: {pattern}",
                    indicators=[
                        f"Process: {event.process}",
                        f"Command: {event.command}",
                        f"Tool: {pattern}"
                    ],
                    remediation=(
                        "CRITICAL: Known attack tool detected in container. "
                        "Terminate container immediately and preserve for forensics. "
                        "Investigate how tool was introduced. "
                        "Review image build and supply chain security."
                    ),
                    confidence=0.98
                )
                return

    def _create_alert(
        self,
        event: RuntimeEvent,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        description: str,
        indicators: List[str],
        remediation: str,
        confidence: float = 1.0
    ):
        """Create a new threat alert"""
        alert = ThreatAlert(
            alert_id=f"alert_{len(self.alerts) + 1:04d}",
            timestamp=event.timestamp,
            severity=severity,
            threat_type=threat_type,
            description=description,
            indicators=indicators,
            remediation=remediation,
            confidence=confidence,
            related_events=[event]
        )

        self.alerts.append(alert)
        self.stats['threats_detected'] += 1

        # Log alert based on severity
        emoji = {
            ThreatSeverity.CRITICAL: "🚨",
            ThreatSeverity.HIGH: "⚠️",
            ThreatSeverity.MEDIUM: "⚡",
            ThreatSeverity.LOW: "ℹ️"
        }.get(severity, "•")

        log_func = {
            ThreatSeverity.CRITICAL: logger.error,
            ThreatSeverity.HIGH: logger.warning,
            ThreatSeverity.MEDIUM: logger.info,
            ThreatSeverity.LOW: logger.info
        }.get(severity, logger.info)

        log_func(f"{emoji} {severity.value.upper()}: {description}")

    def export_to_json(self, output_file: str):
        """Export monitoring results to JSON"""
        output = {
            "metadata": {
                "tool": "Argus Runtime Security Monitor",
                "version": "1.0.0",
                "timestamp": datetime.utcnow().isoformat(),
                "monitoring_start": self.stats.get('monitoring_start'),
                "monitoring_end": self.stats.get('monitoring_end')
            },
            "statistics": {
                "total_events": len(self.events),
                "total_alerts": len(self.alerts),
                "events_by_severity": self.stats.get('events_by_severity', {}),
                "events_by_container": self.stats.get('events_by_container', {}),
                "critical_alerts": sum(
                    1 for a in self.alerts if a.severity == ThreatSeverity.CRITICAL
                ),
                "high_alerts": sum(
                    1 for a in self.alerts if a.severity == ThreatSeverity.HIGH
                )
            },
            "alerts": [alert.to_dict() for alert in self.alerts],
            "events": [event.to_dict() for event in self.events[:200]]  # Limit events
        }

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

        logger.info(f"Exported runtime security report to {output_file}")

    def export_to_sarif(self, output_file: str):
        """Export alerts to SARIF format for GitHub integration"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Argus Runtime Security Monitor",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/devatsecure/Argus-Security",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        # Add rules
        rules_added = set()
        for alert in self.alerts:
            rule_id = alert.threat_type.value
            if rule_id not in rules_added:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": alert.threat_type.value.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": alert.description
                    },
                    "help": {
                        "text": alert.remediation
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(alert.severity)
                    }
                })
                rules_added.add(rule_id)

        # Add results
        for alert in self.alerts:
            result = {
                "ruleId": alert.threat_type.value,
                "level": self._severity_to_sarif_level(alert.severity),
                "message": {
                    "text": f"{alert.description}\n\nIndicators:\n" +
                           "\n".join(f"- {ind}" for ind in alert.indicators)
                },
                "properties": {
                    "confidence": alert.confidence,
                    "timestamp": alert.timestamp
                }
            }

            # Add location if we have container info
            if alert.related_events and alert.related_events[0].container_name:
                event = alert.related_events[0]
                result["locations"] = [{
                    "logicalLocations": [{
                        "name": event.container_name or "unknown",
                        "kind": "container"
                    }]
                }]

            sarif["runs"][0]["results"].append(result)

        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2)

        logger.info(f"Exported SARIF report to {output_file}")

    def _severity_to_sarif_level(self, severity: ThreatSeverity) -> str:
        """Convert our severity to SARIF level"""
        mapping = {
            ThreatSeverity.CRITICAL: "error",
            ThreatSeverity.HIGH: "error",
            ThreatSeverity.MEDIUM: "warning",
            ThreatSeverity.LOW: "note",
            ThreatSeverity.INFO: "note"
        }
        return mapping.get(severity, "warning")

    def print_summary(self):
        """Print comprehensive summary of monitoring results"""
        print("\n" + "=" * 80)
        print("🛡️  CONTAINER RUNTIME SECURITY SUMMARY")
        print("=" * 80)

        # Statistics
        print(f"\n📊 Statistics:")
        print(f"   Total Events: {len(self.events)}")
        print(f"   Security Alerts: {len(self.alerts)}")

        if self.stats.get('monitoring_start'):
            print(f"   Monitoring Period: {self.stats['monitoring_start']} to {self.stats.get('monitoring_end', 'ongoing')}")

        # Events by severity
        if self.stats.get('events_by_severity'):
            print(f"\n📈 Events by Severity:")
            for severity in ['critical', 'high', 'medium', 'low']:
                count = self.stats['events_by_severity'].get(severity, 0)
                if count > 0:
                    print(f"   {severity.upper()}: {count}")

        # Alerts by severity
        if self.alerts:
            print(f"\n🚨 Alerts by Severity:")
            by_severity = {}
            for alert in self.alerts:
                by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

            for severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH,
                            ThreatSeverity.MEDIUM, ThreatSeverity.LOW]:
                count = by_severity.get(severity, 0)
                if count > 0:
                    emoji = "🔴" if severity == ThreatSeverity.CRITICAL else \
                            "🟠" if severity == ThreatSeverity.HIGH else \
                            "🟡" if severity == ThreatSeverity.MEDIUM else "🟢"
                    print(f"   {emoji} {severity.value.upper()}: {count}")

            # Show top alerts
            print(f"\n🚨 Top Alerts:")
            critical_high = [a for a in self.alerts
                           if a.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]]
            for i, alert in enumerate(critical_high[:5], 1):
                print(f"\n   {i}. [{alert.severity.value.upper()}] {alert.threat_type.value}")
                print(f"      {alert.description}")
                print(f"      Confidence: {alert.confidence:.0%}")
                print(f"      Remediation: {alert.remediation[:100]}...")

        # Container breakdown
        if self.stats.get('events_by_container'):
            print(f"\n📦 Events by Container:")
            sorted_containers = sorted(
                self.stats['events_by_container'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for container, count in sorted_containers[:5]:
                print(f"   {container}: {count} events")

        # Recommendations
        if self.alerts:
            critical_count = sum(1 for a in self.alerts if a.severity == ThreatSeverity.CRITICAL)
            high_count = sum(1 for a in self.alerts if a.severity == ThreatSeverity.HIGH)

            if critical_count > 0:
                print(f"\n⚠️  IMMEDIATE ACTION REQUIRED:")
                print(f"   {critical_count} CRITICAL threats detected requiring immediate response")
            elif high_count > 0:
                print(f"\n⚠️  ATTENTION REQUIRED:")
                print(f"   {high_count} HIGH-severity threats detected")
            else:
                print(f"\n✅ No critical threats detected")
        else:
            print(f"\n✅ No security threats detected")

        print("\n" + "=" * 80 + "\n")


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Container Runtime Security Monitoring with Falco",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor containers in real-time for 60 seconds
  %(prog)s --mode realtime --duration 60

  # Analyze existing Falco log file
  %(prog)s --mode analyze --log-file /var/log/falco/events.json

  # Monitor specific container
  %(prog)s --mode realtime --container web-server --duration 120

  # Export to SARIF for GitHub
  %(prog)s --mode analyze --log-file events.json --sarif output.sarif
        """
    )

    parser.add_argument(
        "--mode",
        choices=["realtime", "analyze"],
        default="realtime",
        help="Monitoring mode"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Monitoring duration in seconds (realtime mode)"
    )
    parser.add_argument(
        "--log-file",
        help="Falco log file to analyze (analyze mode)"
    )
    parser.add_argument(
        "--container",
        help="Container name filter (realtime mode)"
    )
    parser.add_argument(
        "--falco-path",
        default="falco",
        help="Path to Falco binary"
    )
    parser.add_argument(
        "--rules-file",
        help="Custom Falco rules file"
    )
    parser.add_argument(
        "--output",
        default="runtime_security.json",
        help="Output JSON file"
    )
    parser.add_argument(
        "--sarif",
        help="Output SARIF file for GitHub integration"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create monitor
    monitor = RuntimeSecurityMonitor(
        falco_path=args.falco_path,
        rules_file=args.rules_file
    )

    # Run monitoring
    try:
        if args.mode == "realtime":
            monitor.monitor_realtime(
                duration_seconds=args.duration,
                container_filter=args.container
            )
        else:
            if not args.log_file:
                print("Error: --log-file required for analyze mode")
                sys.exit(1)
            monitor.analyze_log_file(args.log_file)

        # Print summary
        monitor.print_summary()

        # Export results
        monitor.export_to_json(args.output)

        if args.sarif:
            monitor.export_to_sarif(args.sarif)

        # Exit code based on alerts
        critical_count = sum(
            1 for a in monitor.alerts if a.severity == ThreatSeverity.CRITICAL
        )
        high_count = sum(
            1 for a in monitor.alerts if a.severity == ThreatSeverity.HIGH
        )

        if critical_count > 0:
            sys.exit(2)  # Critical threats found
        elif high_count > 0:
            sys.exit(1)  # High-severity threats found
        else:
            sys.exit(0)  # Success

    except KeyboardInterrupt:
        print("\n\nMonitoring interrupted by user")
        monitor.print_summary()
        sys.exit(130)
    except Exception as e:
        logger.error(f"Monitoring failed: {e}", exc_info=args.debug)
        sys.exit(1)


if __name__ == "__main__":
    main()
