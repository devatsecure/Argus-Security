#!/usr/bin/env python3
"""
Supply Chain Attack Detection for Argus
Detects malicious dependencies, typosquatting, and compromised packages

This module analyzes dependency changes in version control to identify:
- Typosquatting attempts (similar names to popular packages)
- Malicious install scripts (network calls, env access, process spawning)
- Low security scores (OpenSSF Scorecard integration)
- Suspicious behavior patterns (crypto mining, data exfiltration)

Supports: npm, PyPI, Go modules, Cargo (Rust), Maven
"""

import json
import logging
import re
import subprocess
import sys
import tempfile

try:
    import defusedxml.ElementTree as ET
except ImportError:
    # Fallback to standard library with warning
    import xml.etree.ElementTree as ET
    logging.warning("defusedxml not available - XML parsing may be vulnerable to XXE/billion laughs attacks")

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from tenacity import (
    retry,
    wait_exponential,
    stop_after_attempt,
    retry_if_exception_type,
)

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DependencyChange:
    """Represents a dependency change between two refs"""

    package_name: str
    ecosystem: str  # npm, pypi, maven, cargo, go
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    change_type: str = "added"  # added, removed, upgraded, downgraded
    file_path: str = ""

    def __str__(self) -> str:
        """Human-readable representation"""
        if self.change_type == "added":
            return f"{self.package_name}@{self.new_version} (new dependency)"
        elif self.change_type == "removed":
            return f"{self.package_name}@{self.old_version} (removed)"
        elif self.change_type == "upgraded":
            return f"{self.package_name}: {self.old_version} → {self.new_version}"
        elif self.change_type == "downgraded":
            return f"{self.package_name}: {self.old_version} → {self.new_version} (downgrade)"
        return f"{self.package_name}"


@dataclass
class ThreatAssessment:
    """Threat assessment for a dependency"""

    package_name: str
    ecosystem: str
    threat_level: ThreatLevel
    threat_types: List[str]  # ["typosquatting", "malicious_script", "low_scorecard"]
    evidence: List[str]
    recommendations: List[str]
    similar_legitimate_packages: List[str] = field(default_factory=list)
    scorecard_score: Optional[float] = None
    change_info: Optional[DependencyChange] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        result["threat_level"] = self.threat_level.value
        if self.change_info:
            result["change_info"] = asdict(self.change_info)
        return result


class SupplyChainAnalyzer:
    """Detect supply chain attacks and malicious dependencies"""

    # Popular packages for typosquatting detection (top 100+ per ecosystem)
    POPULAR_PACKAGES = {
        "npm": [
            "react",
            "lodash",
            "express",
            "axios",
            "webpack",
            "typescript",
            "eslint",
            "prettier",
            "jest",
            "babel",
            "next",
            "vue",
            "angular",
            "moment",
            "jquery",
            "chalk",
            "commander",
            "request",
            "dotenv",
            "async",
            "socket.io",
            "redux",
            "mocha",
            "underscore",
            "yargs",
            "mongoose",
            "cors",
            "uuid",
            "nodemon",
            "body-parser",
        ],
        "pypi": [
            "requests",
            "numpy",
            "pandas",
            "django",
            "flask",
            "pytest",
            "boto3",
            "sqlalchemy",
            "pillow",
            "matplotlib",
            "tensorflow",
            "keras",
            "scikit-learn",
            "scipy",
            "beautifulsoup4",
            "celery",
            "pyyaml",
            "urllib3",
            "certifi",
            "setuptools",
            "pip",
            "wheel",
            "click",
            "jinja2",
            "cryptography",
            "pydantic",
            "fastapi",
            "aiohttp",
            "httpx",
        ],
        "maven": [
            "spring-boot",
            "junit",
            "slf4j",
            "jackson",
            "commons-lang3",
            "guava",
            "hibernate",
            "log4j",
            "mockito",
            "gson",
            "lombok",
            "logback",
            "commons-io",
            "httpclient",
            "spring-core",
            "spring-web",
            "spring-data",
            "mysql-connector",
            "postgresql",
            "kafka",
        ],
        "cargo": [
            "serde",
            "tokio",
            "clap",
            "reqwest",
            "anyhow",
            "thiserror",
            "tracing",
            "async-trait",
            "hyper",
            "rand",
            "regex",
            "log",
            "env_logger",
            "chrono",
            "rayon",
            "diesel",
            "actix-web",
            "axum",
            "bytes",
            "futures",
        ],
        "go": [
            "github.com/gin-gonic/gin",
            "github.com/gorilla/mux",
            "github.com/stretchr/testify",
            "github.com/sirupsen/logrus",
            "github.com/spf13/cobra",
            "github.com/spf13/viper",
            "go.uber.org/zap",
            "google.golang.org/grpc",
            "github.com/go-redis/redis",
            "gorm.io/gorm",
        ],
    }

    # Suspicious patterns in install scripts
    SUSPICIOUS_PATTERNS = {
        "network_call": [
            r"curl\s+['\"]?https?://(?!pypi\.org|npmjs\.com|github\.com|registry\.npmjs\.org|crates\.io|githubusercontent\.com)",
            r"wget\s+['\"]?https?://(?!pypi\.org|npmjs\.com|github\.com|crates\.io)",
            r"requests\.get\(['\"]https?://(?!pypi\.org|api\.github\.com|files\.pythonhosted\.org)",
            r"fetch\(['\"]https?://(?!registry\.npmjs\.org|api\.github\.com|unpkg\.com)",
            r"urllib\.request\.urlopen\(['\"]https?://(?!pypi\.org|api\.github\.com)",
        ],
        "file_access": [
            r"open\(['\"][~/]",  # Access to home directory
            r"fs\.readFileSync\(['\"][~/]",
            r"std::fs::read\(['\"][~/]",
            r"File\.read\(['\"][~/]",
            r"/etc/passwd",
            r"/etc/shadow",
            r"\.ssh/",
            r"\.aws/credentials",
        ],
        "env_access": [
            r"(os\.environ|process\.env|std::env::var|System\.getenv)\[?['\"]?(AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN|GITLAB_TOKEN|API_KEY|API_TOKEN|SECRET_KEY|PASSWORD|PRIVATE_KEY)",
            r"(AWS|GITHUB|GITLAB|SLACK|STRIPE)_?(API_?)?KEY",
        ],
        "process_spawn": [
            r"subprocess\.(Popen|call|run|check_output)\(['\"]?(sh|bash|cmd|powershell)",
            r"child_process\.(exec|spawn|execSync|spawnSync)\(['\"]?(sh|bash|cmd|powershell)",
            r"std::process::Command::new\(['\"]?(sh|bash|cmd|powershell)",
            r"os\.system\(",
            r"eval\(",
            r"exec\(",
        ],
        "crypto_mining": [
            r"(monero|xmr|mining|cryptonight|stratum\+tcp)",
            r"(pool\..*\.com|mining.*pool)",
            r"coinhive",
            r"crypto-?miner",
        ],
        "data_exfil": [
            r"(atob|btoa|Buffer\.from)\(.*(base64|hex)",
            r"base64\.(b64encode|b64decode)",
            r"(gzip|zlib|deflate).*compress",
            r"socket\.(socket|connect)\(",
            r"\.send\(.*env",
        ],
        "obfuscation": [
            r"eval\(.*atob",
            r"Function\(['\"]return",
            r"\\x[0-9a-f]{2}",  # Hex encoded strings
            r"String\.fromCharCode",
        ],
    }

    def __init__(self, repo_path: str = ".", enable_network: bool = True):
        """
        Initialize Supply Chain Analyzer

        Args:
            repo_path: Path to git repository
            enable_network: Enable network calls (OpenSSF Scorecard)
        """
        self.repo_path = Path(repo_path)
        self.enable_network = enable_network

    def analyze_dependency_diff(
        self, base_ref: str = "main", head_ref: str = "HEAD"
    ) -> List[ThreatAssessment]:
        """
        Analyze new/changed dependencies between two refs

        Args:
            base_ref: Base git ref (e.g., "main", "origin/main")
            head_ref: Head git ref (e.g., "HEAD", "feature-branch")

        Returns:
            List of threat assessments for suspicious dependencies
        """
        logger.info(f"Analyzing dependency changes from {base_ref} to {head_ref}")

        # 1. Get dependency changes
        changes = self._get_dependency_changes(base_ref, head_ref)

        if not changes:
            logger.info("No dependency changes detected")
            return []

        logger.info(f"Found {len(changes)} dependency changes")

        # 2. Assess threats for each change
        threats = []
        for change in changes:
            logger.debug(f"Assessing {change}")
            assessment = self._assess_dependency(change)
            if assessment:
                threats.append(assessment)

        logger.info(f"Found {len(threats)} potential supply chain threats")
        return threats

    def _get_dependency_changes(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Get dependency changes between two refs"""
        changes = []

        # Check package.json (npm)
        npm_changes = self._diff_npm_packages(base_ref, head_ref)
        changes.extend(npm_changes)
        if npm_changes:
            logger.debug(f"Found {len(npm_changes)} npm changes")

        # Check requirements.txt / pyproject.toml (Python)
        python_changes = self._diff_python_packages(base_ref, head_ref)
        changes.extend(python_changes)
        if python_changes:
            logger.debug(f"Found {len(python_changes)} Python changes")

        # Check go.mod (Go)
        go_changes = self._diff_go_packages(base_ref, head_ref)
        changes.extend(go_changes)
        if go_changes:
            logger.debug(f"Found {len(go_changes)} Go changes")

        # Check Cargo.toml (Rust)
        cargo_changes = self._diff_cargo_packages(base_ref, head_ref)
        changes.extend(cargo_changes)
        if cargo_changes:
            logger.debug(f"Found {len(cargo_changes)} Cargo changes")

        # Check pom.xml (Maven)
        maven_changes = self._diff_maven_packages(base_ref, head_ref)
        changes.extend(maven_changes)
        if maven_changes:
            logger.debug(f"Found {len(maven_changes)} Maven changes")

        return changes

    def _get_file_content(self, ref: str, file_path: str) -> Optional[str]:
        """
        Get file content at a specific git ref

        Args:
            ref: Git ref (commit, branch, tag)
            file_path: Path to file relative to repo root

        Returns:
            File content or None if file doesn't exist
        """
        try:
            result = subprocess.run(
                ["git", "show", f"{ref}:{file_path}"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception as e:
            logger.debug(f"Could not get {file_path} at {ref}: {e}")
            return None

    def _diff_npm_packages(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Detect npm package changes from package.json"""
        changes = []
        file_path = "package.json"

        base_content = self._get_file_content(base_ref, file_path)
        head_content = self._get_file_content(head_ref, file_path)

        if not base_content and not head_content:
            return changes

        base_deps = self._parse_npm_packages(base_content) if base_content else {}
        head_deps = self._parse_npm_packages(head_content) if head_content else {}

        # Find added, removed, and changed packages
        all_packages = set(base_deps.keys()) | set(head_deps.keys())

        for pkg in all_packages:
            base_ver = base_deps.get(pkg)
            head_ver = head_deps.get(pkg)

            if base_ver is None and head_ver is not None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="npm",
                        new_version=head_ver,
                        change_type="added",
                        file_path=file_path,
                    )
                )
            elif base_ver is not None and head_ver is None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="npm",
                        old_version=base_ver,
                        change_type="removed",
                        file_path=file_path,
                    )
                )
            elif base_ver != head_ver:
                change_type = self._determine_version_change_type(base_ver, head_ver)
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="npm",
                        old_version=base_ver,
                        new_version=head_ver,
                        change_type=change_type,
                        file_path=file_path,
                    )
                )

        return changes

    def _parse_npm_packages(self, content: str) -> Dict[str, str]:
        """Parse package.json and extract dependencies"""
        try:
            data = json.loads(content)
            deps = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))
            return deps
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse package.json: {e}")
            return {}

    def _diff_python_packages(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Detect Python package changes from requirements.txt or pyproject.toml"""
        changes = []

        # Try requirements.txt first
        req_changes = self._diff_requirements_txt(base_ref, head_ref)
        changes.extend(req_changes)

        # Try pyproject.toml
        pyproject_changes = self._diff_pyproject_toml(base_ref, head_ref)
        changes.extend(pyproject_changes)

        return changes

    def _diff_requirements_txt(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Parse requirements.txt changes"""
        changes = []
        file_path = "requirements.txt"

        base_content = self._get_file_content(base_ref, file_path)
        head_content = self._get_file_content(head_ref, file_path)

        if not base_content and not head_content:
            return changes

        base_deps = self._parse_requirements_txt(base_content) if base_content else {}
        head_deps = self._parse_requirements_txt(head_content) if head_content else {}

        all_packages = set(base_deps.keys()) | set(head_deps.keys())

        for pkg in all_packages:
            base_ver = base_deps.get(pkg)
            head_ver = head_deps.get(pkg)

            if base_ver is None and head_ver is not None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="pypi",
                        new_version=head_ver,
                        change_type="added",
                        file_path=file_path,
                    )
                )
            elif base_ver is not None and head_ver is None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="pypi",
                        old_version=base_ver,
                        change_type="removed",
                        file_path=file_path,
                    )
                )
            elif base_ver != head_ver:
                change_type = self._determine_version_change_type(base_ver, head_ver)
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="pypi",
                        old_version=base_ver,
                        new_version=head_ver,
                        change_type=change_type,
                        file_path=file_path,
                    )
                )

        return changes

    def _parse_requirements_txt(self, content: str) -> Dict[str, str]:
        """Parse requirements.txt format"""
        deps = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Handle various formats: pkg==1.0.0, pkg>=1.0.0, pkg~=1.0.0
            match = re.match(r"^([a-zA-Z0-9_-]+)\s*([=~><]+)\s*(.+)$", line)
            if match:
                pkg, operator, version = match.groups()
                deps[pkg.lower()] = version.strip()
            else:
                # Package without version
                pkg = line.split()[0]
                deps[pkg.lower()] = "unspecified"

        return deps

    def _diff_pyproject_toml(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Parse pyproject.toml changes"""
        changes = []
        file_path = "pyproject.toml"

        base_content = self._get_file_content(base_ref, file_path)
        head_content = self._get_file_content(head_ref, file_path)

        if not base_content and not head_content:
            return changes

        base_deps = self._parse_pyproject_toml(base_content) if base_content else {}
        head_deps = self._parse_pyproject_toml(head_content) if head_content else {}

        all_packages = set(base_deps.keys()) | set(head_deps.keys())

        for pkg in all_packages:
            base_ver = base_deps.get(pkg)
            head_ver = head_deps.get(pkg)

            if base_ver is None and head_ver is not None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="pypi",
                        new_version=head_ver,
                        change_type="added",
                        file_path=file_path,
                    )
                )
            elif base_ver is not None and head_ver is None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="pypi",
                        old_version=base_ver,
                        change_type="removed",
                        file_path=file_path,
                    )
                )
            elif base_ver != head_ver:
                change_type = self._determine_version_change_type(base_ver, head_ver)
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="pypi",
                        old_version=base_ver,
                        new_version=head_ver,
                        change_type=change_type,
                        file_path=file_path,
                    )
                )

        return changes

    def _parse_pyproject_toml(self, content: str) -> Dict[str, str]:
        """Parse pyproject.toml for dependencies (simple parser)"""
        deps = {}
        in_dependencies = False

        for line in content.splitlines():
            line = line.strip()

            # Check for dependencies section
            if line in ["[tool.poetry.dependencies]", "[project.dependencies]"]:
                in_dependencies = True
                continue

            # Stop at next section
            if line.startswith("[") and in_dependencies:
                in_dependencies = False

            if in_dependencies and "=" in line:
                # Parse: package = "^1.0.0" or package = { version = "1.0.0" }
                parts = line.split("=", 1)
                pkg = parts[0].strip()
                version_str = parts[1].strip().strip('"\'')

                # Extract version from complex formats
                version_match = re.search(r'[\^~>=<]*([0-9.]+)', version_str)
                if version_match:
                    deps[pkg.lower()] = version_match.group(1)
                else:
                    deps[pkg.lower()] = version_str

        return deps

    def _diff_go_packages(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Detect Go module changes from go.mod"""
        changes = []
        file_path = "go.mod"

        base_content = self._get_file_content(base_ref, file_path)
        head_content = self._get_file_content(head_ref, file_path)

        if not base_content and not head_content:
            return changes

        base_deps = self._parse_go_mod(base_content) if base_content else {}
        head_deps = self._parse_go_mod(head_content) if head_content else {}

        all_packages = set(base_deps.keys()) | set(head_deps.keys())

        for pkg in all_packages:
            base_ver = base_deps.get(pkg)
            head_ver = head_deps.get(pkg)

            if base_ver is None and head_ver is not None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="go",
                        new_version=head_ver,
                        change_type="added",
                        file_path=file_path,
                    )
                )
            elif base_ver is not None and head_ver is None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="go",
                        old_version=base_ver,
                        change_type="removed",
                        file_path=file_path,
                    )
                )
            elif base_ver != head_ver:
                change_type = self._determine_version_change_type(base_ver, head_ver)
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="go",
                        old_version=base_ver,
                        new_version=head_ver,
                        change_type=change_type,
                        file_path=file_path,
                    )
                )

        return changes

    def _parse_go_mod(self, content: str) -> Dict[str, str]:
        """Parse go.mod file"""
        deps = {}
        in_require = False

        for line in content.splitlines():
            line = line.strip()

            if line.startswith("require"):
                in_require = True
                # Handle single-line require
                if "(" not in line:
                    match = re.match(r"require\s+([^\s]+)\s+([^\s]+)", line)
                    if match:
                        pkg, version = match.groups()
                        deps[pkg] = version
                    in_require = False
                continue

            if in_require:
                if line == ")":
                    in_require = False
                    continue

                # Parse: github.com/pkg/name v1.0.0
                parts = line.split()
                if len(parts) >= 2:
                    pkg, version = parts[0], parts[1]
                    deps[pkg] = version

        return deps

    def _diff_cargo_packages(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Detect Cargo package changes from Cargo.toml"""
        changes = []
        file_path = "Cargo.toml"

        base_content = self._get_file_content(base_ref, file_path)
        head_content = self._get_file_content(head_ref, file_path)

        if not base_content and not head_content:
            return changes

        base_deps = self._parse_cargo_toml(base_content) if base_content else {}
        head_deps = self._parse_cargo_toml(head_content) if head_content else {}

        all_packages = set(base_deps.keys()) | set(head_deps.keys())

        for pkg in all_packages:
            base_ver = base_deps.get(pkg)
            head_ver = head_deps.get(pkg)

            if base_ver is None and head_ver is not None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="cargo",
                        new_version=head_ver,
                        change_type="added",
                        file_path=file_path,
                    )
                )
            elif base_ver is not None and head_ver is None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="cargo",
                        old_version=base_ver,
                        change_type="removed",
                        file_path=file_path,
                    )
                )
            elif base_ver != head_ver:
                change_type = self._determine_version_change_type(base_ver, head_ver)
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="cargo",
                        old_version=base_ver,
                        new_version=head_ver,
                        change_type=change_type,
                        file_path=file_path,
                    )
                )

        return changes

    def _parse_cargo_toml(self, content: str) -> Dict[str, str]:
        """Parse Cargo.toml for dependencies"""
        deps = {}
        in_dependencies = False

        for line in content.splitlines():
            line = line.strip()

            if line in ["[dependencies]", "[dev-dependencies]"]:
                in_dependencies = True
                continue

            if line.startswith("[") and in_dependencies:
                in_dependencies = False

            if in_dependencies and "=" in line:
                parts = line.split("=", 1)
                pkg = parts[0].strip()
                version_str = parts[1].strip().strip('"\'')

                # Handle version = "1.0" and { version = "1.0", features = [...] }
                version_match = re.search(r'(?:version\s*=\s*)?["\']?([0-9.]+)', version_str)
                if version_match:
                    deps[pkg] = version_match.group(1)

        return deps

    def _diff_maven_packages(self, base_ref: str, head_ref: str) -> List[DependencyChange]:
        """Detect Maven package changes from pom.xml"""
        changes = []
        file_path = "pom.xml"

        base_content = self._get_file_content(base_ref, file_path)
        head_content = self._get_file_content(head_ref, file_path)

        if not base_content and not head_content:
            return changes

        base_deps = self._parse_pom_xml(base_content) if base_content else {}
        head_deps = self._parse_pom_xml(head_content) if head_content else {}

        all_packages = set(base_deps.keys()) | set(head_deps.keys())

        for pkg in all_packages:
            base_ver = base_deps.get(pkg)
            head_ver = head_deps.get(pkg)

            if base_ver is None and head_ver is not None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="maven",
                        new_version=head_ver,
                        change_type="added",
                        file_path=file_path,
                    )
                )
            elif base_ver is not None and head_ver is None:
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="maven",
                        old_version=base_ver,
                        change_type="removed",
                        file_path=file_path,
                    )
                )
            elif base_ver != head_ver:
                change_type = self._determine_version_change_type(base_ver, head_ver)
                changes.append(
                    DependencyChange(
                        package_name=pkg,
                        ecosystem="maven",
                        old_version=base_ver,
                        new_version=head_ver,
                        change_type=change_type,
                        file_path=file_path,
                    )
                )

        return changes

    def _parse_pom_xml(self, content: str) -> Dict[str, str]:
        """Parse Maven pom.xml for dependencies"""
        deps = {}
        try:
            # Parse XML
            root = ET.fromstring(content)

            # Handle namespace
            namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
            dependencies = root.findall(".//m:dependency", namespace)

            # If no namespace found, try without
            if not dependencies:
                dependencies = root.findall(".//dependency")
                namespace = None

            for dep in dependencies:
                if namespace:
                    group_id_elem = dep.find("m:groupId", namespace)
                    artifact_id_elem = dep.find("m:artifactId", namespace)
                    version_elem = dep.find("m:version", namespace)
                else:
                    group_id_elem = dep.find("groupId")
                    artifact_id_elem = dep.find("artifactId")
                    version_elem = dep.find("version")

                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text or ""
                    artifact_id = artifact_id_elem.text or ""
                    version = version_elem.text if version_elem is not None else "unspecified"

                    pkg_name = f"{group_id}:{artifact_id}"
                    deps[pkg_name] = version

        except ET.ParseError as e:
            logger.warning(f"Failed to parse pom.xml: {e}")

        return deps

    def _determine_version_change_type(self, old_ver: str, new_ver: str) -> str:
        """Determine if version change is upgrade or downgrade"""
        # Simple semantic version comparison
        try:
            old_parts = [int(x) for x in re.findall(r"\d+", old_ver)]
            new_parts = [int(x) for x in re.findall(r"\d+", new_ver)]

            # Pad to same length
            max_len = max(len(old_parts), len(new_parts))
            old_parts.extend([0] * (max_len - len(old_parts)))
            new_parts.extend([0] * (max_len - len(new_parts)))

            if new_parts > old_parts:
                return "upgraded"
            elif new_parts < old_parts:
                return "downgraded"
        except (ValueError, IndexError):
            pass

        return "upgraded"  # Default to upgrade if can't determine

    def _assess_dependency(self, change: DependencyChange) -> Optional[ThreatAssessment]:
        """
        Assess a dependency for potential threats

        Args:
            change: Dependency change to assess

        Returns:
            ThreatAssessment if threats found, None otherwise
        """
        threats = []
        evidence = []
        recommendations = []
        threat_level = ThreatLevel.INFO
        similar_packages = []
        scorecard_score = None

        # 1. Typosquatting check
        typo_result = self.check_typosquatting(change.package_name, change.ecosystem)
        if typo_result:
            threats.append("typosquatting")
            legitimate_pkg = typo_result["legitimate_package"]
            distance = typo_result["distance"]
            evidence.append(
                f"Package name '{change.package_name}' is similar to popular package "
                f"'{legitimate_pkg}' (distance: {distance})"
            )
            similar_packages = typo_result.get("similar", [])
            threat_level = ThreatLevel.HIGH
            recommendations.append(
                f"CRITICAL: Verify you meant '{legitimate_pkg}' instead of '{change.package_name}'"
            )
            recommendations.append(
                f"This may be a typosquatting attack attempting to mimic '{legitimate_pkg}'"
            )

        # 2. Malicious behavior check
        behavior_result = self.analyze_package_behavior(change.package_name, change.ecosystem)
        if behavior_result and behavior_result["suspicious"]:
            threats.extend(behavior_result["threats"])
            evidence.extend(behavior_result["evidence"])
            if threat_level.value != "critical":
                threat_level = ThreatLevel.CRITICAL
            recommendations.append(
                "CRITICAL: Package contains suspicious install scripts - manual review required"
            )
            recommendations.append("Do not install this package without thorough security review")

        # 3. OpenSSF Scorecard check
        if self.enable_network:
            scorecard_result = self.check_openssf_scorecard(change.package_name, change.ecosystem)
            if scorecard_result and scorecard_result["score"] is not None:
                scorecard_score = scorecard_result["score"]
                if scorecard_score < 5.0:
                    threats.append("low_security_score")
                    evidence.append(f"OpenSSF Scorecard score: {scorecard_score:.1f}/10 (below recommended 5.0)")

                    # Add specific failing checks
                    if "failed_checks" in scorecard_result:
                        for check in scorecard_result["failed_checks"][:3]:
                            evidence.append(f"Failed security check: {check}")

                    if threat_level not in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                        threat_level = ThreatLevel.MEDIUM

                    recommendations.append(
                        f"Package has low security score ({scorecard_score:.1f}/10) - review security practices"
                    )

        # Only return assessment if threats found
        if threats:
            return ThreatAssessment(
                package_name=change.package_name,
                ecosystem=change.ecosystem,
                threat_level=threat_level,
                threat_types=threats,
                evidence=evidence,
                recommendations=recommendations,
                similar_legitimate_packages=similar_packages,
                scorecard_score=scorecard_score,
                change_info=change,
            )

        return None

    def check_typosquatting(self, package_name: str, ecosystem: str) -> Optional[Dict[str, Any]]:
        """
        Check if package name is typosquatting a popular package

        Args:
            package_name: Name of package to check
            ecosystem: Package ecosystem (npm, pypi, etc.)

        Returns:
            Dict with legitimate package info if typosquatting detected, None otherwise
        """
        popular = self.POPULAR_PACKAGES.get(ecosystem, [])

        for legitimate in popular:
            # Normalize for comparison (handle scoped packages)
            pkg_normalized = package_name.lower().replace("@", "").replace("/", "-")
            legitimate_normalized = legitimate.lower().replace("@", "").replace("/", "-")

            distance = self._levenshtein_distance(pkg_normalized, legitimate_normalized)

            # If very similar (distance 1-2), likely typosquatting
            if 1 <= distance <= 2 and pkg_normalized != legitimate_normalized:
                return {"legitimate_package": legitimate, "distance": distance, "similar": [legitimate]}

        return None

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance between two strings

        Args:
            s1: First string
            s2: Second string

        Returns:
            Edit distance (number of single-character edits needed)
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def analyze_package_behavior(self, package_name: str, ecosystem: str) -> Optional[Dict[str, Any]]:
        """
        Analyze package for malicious behavior patterns

        Downloads package and scans for:
        1. Suspicious install scripts (curl, wget, eval, exec)
        2. Network calls during install
        3. File system access outside package directory
        4. Process spawning and command execution
        5. Obfuscated code patterns
        6. Environment variable exfiltration

        Args:
            package_name: Name of package
            ecosystem: Package ecosystem

        Returns:
            Dict with suspicious=True and threats/evidence if malicious patterns found
        """
        try:
            # Download package to temporary directory
            with tempfile.TemporaryDirectory() as tmpdir:
                package_path = Path(tmpdir)
                logger.debug(f"Downloading {ecosystem}:{package_name} to {package_path}")

                # Download package
                if not self._download_package(package_name, ecosystem, package_path):
                    logger.warning(f"Failed to download {ecosystem}:{package_name}")
                    return None

                # Analyze package behavior
                analysis = self._analyze_package_behavior(package_path, ecosystem)

                if analysis["suspicious"]:
                    # Calculate risk score
                    risk_score = self._score_package_risk(analysis)
                    analysis["risk_score"] = risk_score
                    logger.info(f"Suspicious package detected: {package_name} (risk: {risk_score}/100)")

                return analysis

        except Exception as e:
            logger.error(f"Error analyzing {ecosystem}:{package_name}: {e}")
            return None

    def _download_package(self, package_name: str, ecosystem: str, dest_path: Path) -> bool:
        """
        Download package from registry to destination path

        Args:
            package_name: Package name
            ecosystem: Package ecosystem (npm, pypi, maven, cargo, go)
            dest_path: Destination directory for download

        Returns:
            True if download successful, False otherwise
        """
        try:
            if ecosystem == "npm":
                return self._download_npm_package(package_name, dest_path)
            elif ecosystem == "pypi":
                return self._download_pypi_package(package_name, dest_path)
            elif ecosystem == "maven":
                return self._download_maven_package(package_name, dest_path)
            elif ecosystem == "cargo":
                return self._download_cargo_package(package_name, dest_path)
            elif ecosystem == "go":
                return self._download_go_package(package_name, dest_path)
            else:
                logger.warning(f"Unsupported ecosystem for download: {ecosystem}")
                return False
        except Exception as e:
            logger.error(f"Failed to download {ecosystem}:{package_name}: {e}")
            return False

    def _download_npm_package(self, package_name: str, dest_path: Path) -> bool:
        """Download npm package using npm pack"""
        try:
            # Use npm view to get latest version
            result = subprocess.run(
                ["npm", "view", package_name, "version"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                logger.debug(f"npm package not found: {package_name}")
                return False

            version = result.stdout.strip()

            # Download package tarball using npm pack
            result = subprocess.run(
                ["npm", "pack", f"{package_name}@{version}"],
                cwd=dest_path,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return False

            # Extract tarball
            tarball = list(dest_path.glob("*.tgz"))[0]
            subprocess.run(
                ["tar", "-xzf", str(tarball), "-C", str(dest_path)],
                check=True,
                timeout=30,
            )

            return True

        except Exception as e:
            logger.debug(f"npm download failed: {e}")
            return False

    def _download_pypi_package(self, package_name: str, dest_path: Path) -> bool:
        """Download PyPI package using pip download"""
        try:
            # Use pip download to get package
            result = subprocess.run(
                ["pip", "download", "--no-deps", "--dest", str(dest_path), package_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                logger.debug(f"PyPI package not found: {package_name}")
                return False

            # Extract wheel or tar.gz
            for archive in dest_path.glob("*"):
                if archive.suffix == ".whl":
                    # Extract wheel (it's a zip file)
                    subprocess.run(
                        ["unzip", "-q", str(archive), "-d", str(dest_path / "extracted")],
                        check=False,
                        timeout=30,
                    )
                elif archive.suffix == ".gz":
                    # Extract tar.gz
                    subprocess.run(
                        ["tar", "-xzf", str(archive), "-C", str(dest_path)],
                        check=False,
                        timeout=30,
                    )

            return True

        except Exception as e:
            logger.debug(f"PyPI download failed: {e}")
            return False

    def _download_maven_package(self, package_name: str, dest_path: Path) -> bool:
        """Download Maven package using mvn dependency:get"""
        try:
            # Parse group:artifact format
            if ":" not in package_name:
                return False

            parts = package_name.split(":")
            if len(parts) < 2:
                return False

            group_id, artifact_id = parts[0], parts[1]

            # Download using mvn dependency:get
            result = subprocess.run(
                [
                    "mvn",
                    "dependency:get",
                    f"-DgroupId={group_id}",
                    f"-DartifactId={artifact_id}",
                    "-Dpackaging=jar",
                    f"-Ddest={dest_path / 'package.jar'}",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                logger.debug(f"Maven package not found: {package_name}")
                return False

            # Extract JAR
            jar_file = dest_path / "package.jar"
            if jar_file.exists():
                subprocess.run(
                    ["unzip", "-q", str(jar_file), "-d", str(dest_path / "extracted")],
                    check=False,
                    timeout=30,
                )

            return True

        except Exception as e:
            logger.debug(f"Maven download failed: {e}")
            return False

    def _download_cargo_package(self, package_name: str, dest_path: Path) -> bool:
        """Download Cargo package from crates.io"""
        try:
            # Use cargo download (if available) or fetch from crates.io API
            # First try cargo install --no-track with download only
            result = subprocess.run(
                [
                    "cargo",
                    "install",
                    "--root",
                    str(dest_path),
                    "--no-track",
                    package_name,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            # Alternative: Download directly from crates.io
            if result.returncode != 0:
                # Get latest version from crates.io API
                api_url = f"https://crates.io/api/v1/crates/{package_name}"
                curl_result = subprocess.run(
                    ["curl", "-s", api_url],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                if curl_result.returncode != 0:
                    return False

                data = json.loads(curl_result.stdout)
                version = data["crate"]["newest_version"]

                # Download tarball
                download_url = f"https://crates.io/api/v1/crates/{package_name}/{version}/download"
                tarball_path = dest_path / f"{package_name}.tar.gz"

                subprocess.run(
                    ["curl", "-L", "-o", str(tarball_path), download_url],
                    check=True,
                    timeout=60,
                )

                # Extract
                subprocess.run(
                    ["tar", "-xzf", str(tarball_path), "-C", str(dest_path)],
                    check=True,
                    timeout=30,
                )

            return True

        except Exception as e:
            logger.debug(f"Cargo download failed: {e}")
            return False

    def _download_go_package(self, package_name: str, dest_path: Path) -> bool:
        """Download Go package using go mod download"""
        try:
            # Create temporary go.mod
            go_mod_content = f"""module temp
go 1.20

require {package_name} v0.0.0
"""
            go_mod_path = dest_path / "go.mod"
            go_mod_path.write_text(go_mod_content)

            # Download package
            result = subprocess.run(
                ["go", "mod", "download", "-x", package_name],
                cwd=dest_path,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                # Try with @latest
                result = subprocess.run(
                    ["go", "get", "-d", f"{package_name}@latest"],
                    cwd=dest_path,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

            return result.returncode == 0

        except Exception as e:
            logger.debug(f"Go download failed: {e}")
            return False

    def _analyze_package_behavior(self, package_path: Path, ecosystem: str) -> Dict[str, Any]:
        """
        Analyze downloaded package for suspicious behavior

        Scans for:
        - Install scripts with curl/wget
        - eval/exec in setup scripts
        - Network calls during install
        - File system modifications outside package dir
        - Process spawning
        - Obfuscated code
        - Environment variable access

        Args:
            package_path: Path to extracted package
            ecosystem: Package ecosystem

        Returns:
            Dict with analysis results including threats, evidence, and suspicious flag
        """
        threats = []
        evidence = []
        patterns_found = {}

        # Get install/setup scripts based on ecosystem
        install_scripts = self._get_install_scripts(package_path, ecosystem)

        # Scan each script for suspicious patterns
        for script_path in install_scripts:
            try:
                content = script_path.read_text(errors="ignore")

                # Check each pattern category
                for category, pattern_list in self.SUSPICIOUS_PATTERNS.items():
                    if category not in patterns_found:
                        patterns_found[category] = []

                    for pattern in pattern_list:
                        matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                        for match in matches:
                            match_text = match.group(0)[:100]  # Limit length
                            patterns_found[category].append(
                                {
                                    "file": str(script_path.relative_to(package_path)),
                                    "match": match_text,
                                    "line": content[: match.start()].count("\n") + 1,
                                }
                            )

            except Exception as e:
                logger.debug(f"Error scanning {script_path}: {e}")

        # Build threats and evidence from findings
        if patterns_found.get("network_call"):
            threats.append("network_call")
            for finding in patterns_found["network_call"][:3]:  # Limit to top 3
                evidence.append(
                    f"Suspicious network call in {finding['file']}:{finding['line']}: {finding['match']}"
                )

        if patterns_found.get("file_access"):
            threats.append("file_access")
            for finding in patterns_found["file_access"][:3]:
                evidence.append(
                    f"Suspicious file access in {finding['file']}:{finding['line']}: {finding['match']}"
                )

        if patterns_found.get("env_access"):
            threats.append("env_access")
            for finding in patterns_found["env_access"][:3]:
                evidence.append(
                    f"Environment variable access in {finding['file']}:{finding['line']}: {finding['match']}"
                )

        if patterns_found.get("process_spawn"):
            threats.append("process_spawn")
            for finding in patterns_found["process_spawn"][:3]:
                evidence.append(
                    f"Process spawning in {finding['file']}:{finding['line']}: {finding['match']}"
                )

        if patterns_found.get("crypto_mining"):
            threats.append("crypto_mining")
            for finding in patterns_found["crypto_mining"][:3]:
                evidence.append(
                    f"Crypto mining indicator in {finding['file']}:{finding['line']}: {finding['match']}"
                )

        if patterns_found.get("data_exfil"):
            threats.append("data_exfiltration")
            for finding in patterns_found["data_exfil"][:3]:
                evidence.append(
                    f"Data exfiltration pattern in {finding['file']}:{finding['line']}: {finding['match']}"
                )

        if patterns_found.get("obfuscation"):
            threats.append("obfuscation")
            for finding in patterns_found["obfuscation"][:3]:
                evidence.append(
                    f"Code obfuscation in {finding['file']}:{finding['line']}: {finding['match']}"
                )

        return {
            "suspicious": len(threats) > 0,
            "threats": threats,
            "evidence": evidence,
            "patterns_found": patterns_found,
        }

    def _get_install_scripts(self, package_path: Path, ecosystem: str) -> List[Path]:
        """
        Get list of install/setup scripts to scan based on ecosystem

        Args:
            package_path: Path to extracted package
            ecosystem: Package ecosystem

        Returns:
            List of paths to install scripts
        """
        scripts = []

        try:
            if ecosystem == "npm":
                # Check package.json for scripts
                package_json = package_path / "package" / "package.json"
                if not package_json.exists():
                    package_json = package_path / "package.json"

                if package_json.exists():
                    scripts.append(package_json)

                # Check for common script files
                for pattern in ["**/install.js", "**/preinstall.js", "**/postinstall.js"]:
                    scripts.extend(package_path.rglob(pattern))

            elif ecosystem == "pypi":
                # Check setup.py and setup.cfg
                for pattern in ["**/setup.py", "**/setup.cfg", "**/__init__.py"]:
                    scripts.extend(package_path.rglob(pattern))

            elif ecosystem == "maven":
                # Check pom.xml and build scripts
                for pattern in ["**/pom.xml", "**/build.gradle", "**/build.gradle.kts"]:
                    scripts.extend(package_path.rglob(pattern))

            elif ecosystem == "cargo":
                # Check build.rs and Cargo.toml
                for pattern in ["**/build.rs", "**/Cargo.toml"]:
                    scripts.extend(package_path.rglob(pattern))

            elif ecosystem == "go":
                # Check go.mod and .go files with init functions
                for pattern in ["**/go.mod", "**/*.go"]:
                    scripts.extend(package_path.rglob(pattern))

        except Exception as e:
            logger.debug(f"Error finding install scripts: {e}")

        return scripts

    def _score_package_risk(self, analysis: Dict[str, Any]) -> int:
        """
        Calculate risk score for package based on analysis

        Scoring:
        - Network activity: 30 points
        - Process spawning: 25 points
        - Environment access: 20 points
        - File access: 15 points
        - Obfuscation: 20 points
        - Crypto mining: 40 points
        - Data exfiltration: 35 points

        Args:
            analysis: Analysis results from _analyze_package_behavior

        Returns:
            Risk score from 0-100
        """
        score = 0
        threats = analysis.get("threats", [])

        # Score by threat type
        threat_scores = {
            "network_call": 30,
            "process_spawn": 25,
            "env_access": 20,
            "file_access": 15,
            "obfuscation": 20,
            "crypto_mining": 40,
            "data_exfiltration": 35,
        }

        for threat in threats:
            score += threat_scores.get(threat, 10)

        # Cap at 100
        return min(score, 100)

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((subprocess.SubprocessError, OSError, json.JSONDecodeError)),
    )
    def _fetch_openssf_scorecard(self, api_url: str) -> Dict[str, Any]:
        """Fetch OpenSSF Scorecard data with retry logic

        Args:
            api_url: OpenSSF Scorecard API URL

        Returns:
            Scorecard data

        Raises:
            subprocess.SubprocessError: If curl fails after retries
        """
        # Use subprocess to call curl (avoid adding requests dependency)
        result = subprocess.run(
            ["curl", "-s", "-H", "Accept: application/json", api_url],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            raise subprocess.SubprocessError(f"curl failed with code {result.returncode}: {result.stderr}")

        data = json.loads(result.stdout)
        return data

    def check_openssf_scorecard(self, package_name: str, ecosystem: str) -> Optional[Dict[str, Any]]:
        """
        Check OpenSSF Scorecard score for package

        Args:
            package_name: Name of package
            ecosystem: Package ecosystem

        Returns:
            Dict with score and failed checks if available
        """
        if not self.enable_network:
            return None

        # Map package to GitHub repository
        repo_url = self._map_package_to_repo(package_name, ecosystem)
        if not repo_url:
            logger.debug(f"Could not map {ecosystem}:{package_name} to GitHub repo")
            return None

        try:
            # Parse repo URL: github.com/org/repo
            parts = repo_url.replace("https://", "").replace("http://", "").split("/")
            if len(parts) < 3 or parts[0] != "github.com":
                return None

            org, repo = parts[1], parts[2].replace(".git", "")

            # Query OpenSSF Scorecard API
            api_url = f"https://api.securityscorecards.dev/projects/github.com/{org}/{repo}"

            # Fetch with retry logic
            data = self._fetch_openssf_scorecard(api_url)

            if "score" in data:
                score = data["score"]
                failed_checks = []

                # Extract failed checks
                if "checks" in data:
                    for check in data["checks"]:
                        if check.get("score", 10) < 5:
                            failed_checks.append(check.get("name", "unknown"))

                return {"score": score, "failed_checks": failed_checks[:5]}

        except Exception as e:
            logger.debug(f"OpenSSF Scorecard check failed for {package_name}: {e}")

        return None

    def _map_package_to_repo(self, package_name: str, ecosystem: str) -> Optional[str]:
        """
        Map package name to GitHub repository URL

        This is a simplified heuristic approach. Production implementation
        would use registry APIs to get the actual repository URL.

        Args:
            package_name: Package name
            ecosystem: Package ecosystem

        Returns:
            GitHub repository URL or None
        """
        # For Go modules, the package name IS the repo path
        if ecosystem == "go":
            if package_name.startswith("github.com/"):
                parts = package_name.split("/")
                if len(parts) >= 3:
                    return f"https://github.com/{parts[1]}/{parts[2]}"

        # For other ecosystems, would need registry API integration
        # Examples:
        # - npm: https://registry.npmjs.org/{package}/latest -> repository.url
        # - PyPI: https://pypi.org/pypi/{package}/json -> info.project_urls.Source
        # - Maven: Parse pom.xml from Maven Central

        return None


def main() -> int:
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Supply Chain Attack Detection - Analyze dependency changes for security threats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze changes between main and current branch
  %(prog)s --base main --head HEAD --output threats.json

  # Analyze specific PR
  %(prog)s --base origin/main --head feature-branch

  # Disable network checks (faster, no OpenSSF Scorecard)
  %(prog)s --base main --head HEAD --no-network

  # Enable debug logging
  %(prog)s --base main --head HEAD --debug
        """,
    )

    parser.add_argument(
        "--base",
        default="main",
        help="Base git ref to compare against (default: main)",
    )

    parser.add_argument(
        "--head",
        default="HEAD",
        help="Head git ref to analyze (default: HEAD)",
    )

    parser.add_argument(
        "--repo-path",
        default=".",
        help="Path to git repository (default: current directory)",
    )

    parser.add_argument(
        "--output",
        "-o",
        help="Output file for threat assessment (JSON format)",
    )

    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Disable network checks (OpenSSF Scorecard)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )

    # Initialize analyzer
    analyzer = SupplyChainAnalyzer(
        repo_path=args.repo_path,
        enable_network=not args.no_network,
    )

    # Analyze dependency changes
    threats = analyzer.analyze_dependency_diff(
        base_ref=args.base,
        head_ref=args.head,
    )

    # Output results
    if not threats:
        logger.info("No supply chain threats detected")
        return 0

    # Print summary to console
    print(f"\n{'='*80}")
    print(f"Supply Chain Threat Assessment: {len(threats)} threats detected")
    print(f"{'='*80}\n")

    for threat in threats:
        print(f"Package: {threat.package_name} ({threat.ecosystem})")
        print(f"Threat Level: {threat.threat_level.value.upper()}")
        print(f"Threat Types: {', '.join(threat.threat_types)}")
        print("\nEvidence:")
        for evidence in threat.evidence:
            print(f"  - {evidence}")
        print("\nRecommendations:")
        for rec in threat.recommendations:
            print(f"  - {rec}")
        print(f"\n{'-'*80}\n")

    # Write to output file if specified
    if args.output:
        output_data = {
            "summary": {
                "total_threats": len(threats),
                "critical": sum(1 for t in threats if t.threat_level == ThreatLevel.CRITICAL),
                "high": sum(1 for t in threats if t.threat_level == ThreatLevel.HIGH),
                "medium": sum(1 for t in threats if t.threat_level == ThreatLevel.MEDIUM),
                "low": sum(1 for t in threats if t.threat_level == ThreatLevel.LOW),
            },
            "threats": [threat.to_dict() for threat in threats],
        }

        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)

        logger.info(f"Threat assessment written to {args.output}")

    # Exit with error if critical/high threats found
    critical_or_high = [
        t for t in threats if t.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]
    ]
    if critical_or_high:
        logger.error(f"Found {len(critical_or_high)} critical/high severity threats")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
