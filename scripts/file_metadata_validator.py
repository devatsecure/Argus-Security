#!/usr/bin/env python3
"""
File Metadata Validator for Argus Security
Validates file security posture using metadata when direct file access unavailable
"""

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MetadataValidationResult:
    """Result of metadata-based validation"""
    has_metadata: bool
    permission_indicators: list[str]
    confidence: float  # 0.0-0.7 (lower than direct check)
    reasoning: str
    sources: list[str]  # Which metadata sources were checked


class FileMetadataValidator:
    """
    Validate file security using repository metadata

    When direct file access unavailable (remote repos, CI/CD, containers),
    infer security posture from:
    - .gitattributes (git metadata)
    - .dockerignore / .gitignore (exclusion patterns)
    - Pre-commit hooks configuration
    - Deployment scripts
    - Security policy files (SECURITY.md, security.yml)
    """

    def __init__(self, repo_root: str = "."):
        """
        Initialize metadata validator

        Args:
            repo_root: Repository root directory
        """
        self.repo_root = Path(repo_root)
        self.logger = logging.getLogger(__name__)

    def validate_from_metadata(self, file_path: str) -> MetadataValidationResult:
        """
        Validate file permissions using metadata

        Args:
            file_path: Path to file (may not exist locally)

        Returns:
            MetadataValidationResult with inferred security posture
        """
        indicators = []
        sources = []
        confidence = 0.0

        # Normalize path
        rel_path = self._normalize_path(file_path)

        # Check various metadata sources

        # 1. Git attributes
        gitattributes_result = self._check_gitattributes(rel_path)
        if gitattributes_result:
            indicators.extend(gitattributes_result)
            sources.append(".gitattributes")
            confidence += 0.15

        # 2. Ignore files (exclusion = less sensitive)
        ignore_result = self._check_ignore_files(rel_path)
        if ignore_result:
            indicators.extend(ignore_result)
            sources.append(".gitignore/.dockerignore")
            confidence += 0.10

        # 3. Pre-commit hooks
        precommit_result = self._check_precommit_hooks(rel_path)
        if precommit_result:
            indicators.extend(precommit_result)
            sources.append(".pre-commit-config.yaml")
            confidence += 0.20

        # 4. Deployment configs
        deploy_result = self._check_deployment_configs(rel_path)
        if deploy_result:
            indicators.extend(deploy_result)
            sources.append("deployment configs")
            confidence += 0.15

        # 5. Security policies
        policy_result = self._check_security_policies(rel_path)
        if policy_result:
            indicators.extend(policy_result)
            sources.append("security policies")
            confidence += 0.10

        # Cap confidence at 0.7 (metadata-based never 100% certain)
        confidence = min(confidence, 0.7)

        has_metadata = len(indicators) > 0
        reasoning = self._build_reasoning(indicators, sources, confidence)

        return MetadataValidationResult(
            has_metadata=has_metadata,
            permission_indicators=indicators,
            confidence=confidence,
            reasoning=reasoning,
            sources=sources
        )

    def _normalize_path(self, file_path: str) -> str:
        """Normalize path relative to repo root"""
        path = Path(file_path)
        try:
            return str(path.relative_to(self.repo_root))
        except ValueError:
            return str(path)

    def _check_gitattributes(self, rel_path: str) -> list[str]:
        """Check .gitattributes for permission hints"""
        indicators = []
        gitattributes = self.repo_root / ".gitattributes"

        if not gitattributes.exists():
            return indicators

        try:
            content = gitattributes.read_text()

            # Parse each line and check for pattern matches
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Split into pattern and attributes
                parts = line.split()
                if len(parts) < 2:
                    continue

                pattern = parts[0]
                attributes = ' '.join(parts[1:])

                # Convert gitattributes pattern to regex
                # Simple conversion: * -> .*, ? -> .
                regex_pattern = pattern.replace('.', r'\.').replace('*', '.*').replace('?', '.')

                # Check if path matches the pattern
                if re.match(regex_pattern, rel_path):
                    # Check for secret filter
                    if 'filter=secret' in attributes.lower():
                        indicators.append("Marked as secret in .gitattributes")

                    # Check for encryption markers
                    if 'crypt' in attributes.lower():
                        indicators.append("Encryption configured in .gitattributes")

                    # Check for diff=secret or diff=crypt
                    if re.search(r'diff=(secret|crypt)', attributes, re.IGNORECASE):
                        indicators.append("Hidden from diffs via .gitattributes")

        except Exception as e:
            self.logger.debug(f"Error reading .gitattributes: {e}")

        return indicators

    def _check_ignore_files(self, rel_path: str) -> list[str]:
        """Check .gitignore and .dockerignore"""
        indicators = []

        for ignore_file in [".gitignore", ".dockerignore"]:
            ignore_path = self.repo_root / ignore_file
            if not ignore_path.exists():
                continue

            try:
                content = ignore_path.read_text()

                # If file is ignored, it's likely not sensitive prod data
                if self._matches_ignore_pattern(rel_path, content):
                    indicators.append(f"Excluded by {ignore_file} (less sensitive)")

            except Exception as e:
                self.logger.debug(f"Error reading {ignore_file}: {e}")

        return indicators

    def _matches_ignore_pattern(self, path: str, ignore_content: str) -> bool:
        """Check if path matches any ignore pattern"""
        for line in ignore_content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Simple pattern matching (not full gitignore spec)
            pattern = line.replace('*', '.*')
            if re.match(pattern, path):
                return True

        return False

    def _check_precommit_hooks(self, rel_path: str) -> list[str]:
        """Check .pre-commit-config.yaml for security checks"""
        indicators = []
        precommit = self.repo_root / ".pre-commit-config.yaml"

        if not precommit.exists():
            return indicators

        try:
            content = precommit.read_text()

            # Check for secret scanning hooks
            if "detect-secrets" in content or "gitleaks" in content or "trufflehog" in content:
                indicators.append("Repository has pre-commit secret scanning (validates permissions)")

            # Check for permission checks
            if "check-added-large-files" in content:
                indicators.append("Pre-commit checks large files (may catch sensitive data)")

        except Exception as e:
            self.logger.debug(f"Error reading .pre-commit-config.yaml: {e}")

        return indicators

    def _check_deployment_configs(self, rel_path: str) -> list[str]:
        """Check deployment configs for permission settings"""
        indicators = []

        # Check common deployment files
        deploy_files = [
            "docker-compose.yml",
            "Dockerfile",
            ".github/workflows/*.yml",
            "k8s/*.yaml",
            "terraform/*.tf"
        ]

        for pattern in deploy_files:
            for deploy_file in self.repo_root.glob(pattern):
                if not deploy_file.is_file():
                    continue

                try:
                    content = deploy_file.read_text()

                    # Check for permission-related commands
                    if f"chmod" in content and rel_path in content:
                        indicators.append(f"Permission setting found in {deploy_file.name}")

                    # Check for chown
                    if f"chown" in content and rel_path in content:
                        indicators.append(f"Ownership setting found in {deploy_file.name}")

                    # Check for secrets mounting
                    if "secrets:" in content and rel_path in content:
                        indicators.append(f"Mounted as secret in {deploy_file.name}")

                except Exception as e:
                    self.logger.debug(f"Error reading {deploy_file}: {e}")

        return indicators

    def _check_security_policies(self, rel_path: str) -> list[str]:
        """Check SECURITY.md and security policies"""
        indicators = []

        security_files = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]

        for sec_file in security_files:
            sec_path = self.repo_root / sec_file
            if not sec_path.exists():
                continue

            try:
                content = sec_path.read_text()

                # Check if file mentioned in security policy
                if rel_path in content:
                    indicators.append(f"Referenced in {sec_file}")

            except Exception as e:
                self.logger.debug(f"Error reading {sec_file}: {e}")

        return indicators

    def _build_reasoning(self, indicators: list[str], sources: list[str], confidence: float) -> str:
        """Build reasoning string"""
        if not indicators:
            return "No metadata available for validation (file not found, no repo metadata)"

        reasoning = (
            f"Metadata-based validation (confidence: {confidence:.2f}): "
            f"Found {len(indicators)} indicators from {len(sources)} sources. "
        )

        if confidence >= 0.5:
            reasoning += "Strong metadata evidence suggests proper security controls."
        elif confidence >= 0.3:
            reasoning += "Moderate metadata evidence, recommend manual review."
        else:
            reasoning += "Weak metadata evidence, uncertain security posture."

        return reasoning
