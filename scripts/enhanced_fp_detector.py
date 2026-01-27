#!/usr/bin/env python3
"""
Enhanced False Positive Detection Module for Argus Security
Adds intelligent detection for:
1. OAuth2 public client patterns (no secret protection needed)
2. File permissions validation for plaintext storage
3. Dev-only config flags vs production code
4. Different locking mechanisms (mutex vs file-based)
"""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class EnhancedFPAnalysis:
    """Enhanced false positive analysis result"""
    is_false_positive: bool
    confidence: float  # 0.0-1.0
    category: str
    reasoning: str
    evidence: list[str]


class EnhancedFalsePositiveDetector:
    """Enhanced false positive detection with pattern-specific intelligence"""

    def __init__(self):
        """Initialize detector with common patterns"""
        # OAuth2 public client patterns (no secret needed)
        self.oauth2_public_patterns = [
            r"client_id\s*[:=]\s*['\"][\w-]+['\"]",  # Public client ID
            r"redirect_uri\s*[:=]\s*['\"]https?://",  # Redirect URI
            r"response_type\s*[:=]\s*['\"]code['\"]",  # Auth code flow
            r"grant_type\s*[:=]\s*['\"]authorization_code['\"]",  # Auth grant
            r"scope\s*[:=]\s*['\"][^'\"]+['\"]",  # OAuth scopes
            r"pkce_challenge",  # PKCE for public clients
            r"code_verifier",  # PKCE verifier
            r"implicit.*grant",  # Implicit grant (public)
            r"spa.*application",  # SPA apps are public clients
            r"public.*client",  # Explicitly public client
        ]

        # Dev-only config patterns
        self.dev_config_patterns = [
            r"DEBUG\s*=\s*True",  # Debug mode
            r"DEV_MODE|DEVELOPMENT",  # Dev mode flags
            r"localhost|127\.0\.0\.1|0\.0\.0\.0",  # Local addresses
            r"test.*env|\.env\.test",  # Test environment files
            r"if\s+__name__\s*==\s*['\"]__main__['\"]",  # Python main guard
            r"process\.env\.NODE_ENV.*development",  # Node dev env
            r"flask\.env.*development",  # Flask dev
            r"DJANGO_DEBUG",  # Django debug
            r"--debug|--verbose",  # CLI debug flags
            r"console\.(log|debug|trace)",  # Debug logging
            r"#\s*(TODO|FIXME|HACK|XXX)",  # Development comments
            r"mock_|fake_|dummy_|test_",  # Test prefixes
        ]

        # Locking mechanism patterns
        self.mutex_patterns = [
            r"threading\.(R)?Lock",  # Python thread locks
            r"multiprocessing\.Lock",  # Process locks
            r"asyncio\.Lock",  # Async locks
            r"sync\.Mutex|sync\.RWMutex",  # Go mutexes
            r"std::mutex|std::shared_mutex",  # C++ mutexes
            r"pthread_mutex",  # POSIX mutexes
            r"ReentrantLock|synchronized",  # Java locks
            r"Mutex::new|RwLock::new",  # Rust locks
            r"@synchronized",  # Objective-C
            r"lock\s*\{|with\s+lock:",  # Lock blocks
        ]

        self.file_lock_patterns = [
            r"flock|fcntl",  # Unix file locking
            r"LockFile|FileLock",  # File lock libraries
            r"\.lock$|\.pid$",  # Lock files
            r"advisory.*lock",  # Advisory locking
            r"exclusive.*lock|shared.*lock",  # Lock types
            r"O_EXLOCK|O_SHLOCK",  # BSD lock flags
            r"LOCK_EX|LOCK_SH|LOCK_NB",  # flock constants
            r"lockf|F_SETLK",  # POSIX locking
            r"portalocker",  # Cross-platform file locking
        ]

    def analyze_oauth2_public_client(self, finding: dict[str, Any]) -> EnhancedFPAnalysis:
        """
        Determine if OAuth2 finding is for a public client (no secret needed)

        Args:
            finding: Security finding dictionary

        Returns:
            EnhancedFPAnalysis with OAuth2 public client assessment
        """
        code_snippet = finding.get("evidence", {}).get("snippet", "")
        file_path = finding.get("path", finding.get("file_path", ""))
        message = finding.get("message", "").lower()

        evidence = []
        is_public_client = False
        confidence = 0.0

        # Check for public client indicators
        public_indicators = []

        # Check code patterns
        for pattern in self.oauth2_public_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                public_indicators.append(f"Public client pattern found: {pattern}")

        # Check for absence of client_secret
        if "client_secret" not in code_snippet.lower():
            public_indicators.append("No client_secret found (typical for public clients)")
            confidence += 0.2

        # Check for PKCE (Proof Key for Code Exchange - used by public clients)
        if any(pkce in code_snippet.lower() for pkce in ["pkce", "code_verifier", "code_challenge"]):
            public_indicators.append("PKCE flow detected (secure public client pattern)")
            confidence += 0.3
            is_public_client = True

        # Check for SPA/mobile app patterns
        if any(pattern in file_path.lower() for pattern in ["spa", "mobile", "ios", "android", "frontend", "client"]):
            public_indicators.append(f"Public client context: {file_path}")
            confidence += 0.2

        # Check for implicit grant or authorization code without secret
        if "implicit" in code_snippet.lower() or "response_type=token" in code_snippet.lower():
            public_indicators.append("Implicit grant flow (public client)")
            confidence += 0.3
            is_public_client = True

        # Check message for false positive indicators
        if any(term in message for term in ["client_id", "public", "no secret", "pkce"]):
            if "secret" not in message or "public" in message:
                public_indicators.append("Scanner message indicates public client")
                confidence += 0.1

        # Determine if it's a false positive
        if len(public_indicators) >= 2:
            is_public_client = True
            confidence = min(confidence + 0.3, 0.95)

        reasoning = (
            "OAuth2 public clients (SPAs, mobile apps) don't require client secrets. "
            "They use other security mechanisms like PKCE, state parameters, and redirect URI validation."
            if is_public_client else
            "This appears to be a confidential client that should have proper secret management."
        )

        return EnhancedFPAnalysis(
            is_false_positive=is_public_client,
            confidence=confidence,
            category="oauth2_public_client",
            reasoning=reasoning,
            evidence=public_indicators if public_indicators else ["No public client indicators found"]
        )

    def analyze_file_permissions(self, finding: dict[str, Any]) -> EnhancedFPAnalysis:
        """
        Validate file permissions before flagging plaintext storage

        Args:
            finding: Security finding dictionary

        Returns:
            EnhancedFPAnalysis with file permission assessment
        """
        file_path = finding.get("path", finding.get("file_path", ""))
        message = finding.get("message", "").lower()

        evidence = []
        is_false_positive = False
        confidence = 0.0

        # Check if file exists and get permissions
        if file_path and os.path.exists(file_path):
            try:
                file_stat = os.stat(file_path)
                mode = file_stat.st_mode

                # Check file permissions
                owner_read = bool(mode & stat.S_IRUSR)
                owner_write = bool(mode & stat.S_IWUSR)
                group_read = bool(mode & stat.S_IRGRP)
                group_write = bool(mode & stat.S_IWGRP)
                other_read = bool(mode & stat.S_IROTH)
                other_write = bool(mode & stat.S_IWOTH)

                # Convert to octal for readable format
                octal_perms = oct(mode & 0o777)
                evidence.append(f"File permissions: {octal_perms}")

                # Check if properly restricted
                if not (other_read or other_write or group_write):
                    evidence.append("File has restricted permissions (not world/group writable)")
                    confidence += 0.3

                    # Extra secure if only owner can read
                    if not group_read and not other_read:
                        evidence.append("File is only readable by owner (properly secured)")
                        confidence += 0.3
                        is_false_positive = True
                else:
                    evidence.append("File has overly permissive permissions")
                    confidence = 0.9
                    is_false_positive = False

            except (OSError, IOError) as e:
                evidence.append(f"Could not check file permissions: {str(e)}")

        # Check file location patterns
        secure_locations = [
            r"/etc/[^/]+\.conf$",  # System config files (often have proper perms)
            r"\.ssh/",  # SSH directory (should be 700)
            r"/root/",  # Root directory (restricted)
            r"/var/lib/[^/]+/",  # System service dirs
            r"\.gnupg/",  # GPG directory (should be 700)
        ]

        for pattern in secure_locations:
            if re.search(pattern, file_path):
                evidence.append(f"File in typically secure location: {pattern}")
                confidence += 0.2

        # Check if it's a socket or pipe (not regular file)
        if file_path and os.path.exists(file_path):
            if stat.S_ISSOCK(file_stat.st_mode):
                evidence.append("This is a socket, not a regular file")
                is_false_positive = True
                confidence = 0.9
            elif stat.S_ISFIFO(file_stat.st_mode):
                evidence.append("This is a named pipe, not a regular file")
                is_false_positive = True
                confidence = 0.9

        reasoning = (
            "File has proper restrictive permissions preventing unauthorized access."
            if is_false_positive else
            "File permissions allow unauthorized access to sensitive data."
        )

        return EnhancedFPAnalysis(
            is_false_positive=is_false_positive,
            confidence=confidence,
            category="file_permissions",
            reasoning=reasoning,
            evidence=evidence if evidence else ["Could not validate file permissions"]
        )

    def analyze_dev_config_flag(self, finding: dict[str, Any]) -> EnhancedFPAnalysis:
        """
        Distinguish dev-only config flags from production code

        Args:
            finding: Security finding dictionary

        Returns:
            EnhancedFPAnalysis with dev config assessment
        """
        code_snippet = finding.get("evidence", {}).get("snippet", "")
        file_path = finding.get("path", finding.get("file_path", ""))
        line_number = finding.get("line", finding.get("line_number", 0))

        evidence = []
        is_dev_only = False
        confidence = 0.0

        # Check for dev config patterns
        dev_indicators = []

        for pattern in self.dev_config_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                dev_indicators.append(f"Dev pattern found: {pattern[:30]}...")

        # Check file path for dev indicators
        dev_path_patterns = [
            "test", "tests", "spec", "mock", "fixture", "example",
            "sample", "demo", "tutorial", "development", "dev",
            "__pycache__", "node_modules", ".git", "docs"
        ]

        for pattern in dev_path_patterns:
            if pattern in file_path.lower():
                dev_indicators.append(f"Dev path indicator: {pattern}")
                confidence += 0.2

        # Check for environment-based conditionals
        env_conditionals = [
            r"if.*NODE_ENV.*production",
            r"if.*DEBUG",
            r"if.*DEV_MODE",
            r"ifdef.*DEBUG",
            r"#if.*DEBUG",
            r"if.*__debug__",
        ]

        for pattern in env_conditionals:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                dev_indicators.append("Code is wrapped in environment conditional")
                confidence += 0.3
                is_dev_only = True

        # Check for build/compile time exclusion
        exclusion_patterns = [
            r"//\s*@ts-ignore",
            r"#\s*pragma:\s*no\s*cover",
            r"#\s*type:\s*ignore",
            r"/\*\s*istanbul\s+ignore",
            r"//\s*eslint-disable",
        ]

        for pattern in exclusion_patterns:
            if re.search(pattern, code_snippet):
                dev_indicators.append("Code has linter/coverage exclusions")
                confidence += 0.2

        # Check for dead code indicators
        if re.search(r"^\s*#|^\s*//|^\s*/\*", code_snippet, re.MULTILINE):
            # Check if entire snippet is commented
            lines = code_snippet.split('\n')
            commented_lines = sum(1 for line in lines if re.match(r'^\s*[#/]', line))
            if commented_lines > len(lines) * 0.8:
                dev_indicators.append("Code appears to be mostly commented out")
                confidence += 0.4
                is_dev_only = True

        # Determine if it's dev-only
        if len(dev_indicators) >= 2:
            is_dev_only = True
            confidence = min(confidence + 0.3, 0.95)

        reasoning = (
            "This is development-only code that won't run in production."
            if is_dev_only else
            "This code appears to be production code that needs proper security."
        )

        return EnhancedFPAnalysis(
            is_false_positive=is_dev_only,
            confidence=confidence,
            category="dev_config",
            reasoning=reasoning,
            evidence=dev_indicators if dev_indicators else ["No dev-only indicators found"]
        )

    def analyze_locking_mechanism(self, finding: dict[str, Any]) -> EnhancedFPAnalysis:
        """
        Distinguish between different locking mechanisms (mutex vs file-based)

        Args:
            finding: Security finding dictionary

        Returns:
            EnhancedFPAnalysis with locking mechanism assessment
        """
        code_snippet = finding.get("evidence", {}).get("snippet", "")
        message = finding.get("message", "").lower()
        category = finding.get("category", "").lower()

        evidence = []
        is_false_positive = False
        confidence = 0.0
        lock_type = None

        # Check for mutex patterns
        mutex_found = []
        for pattern in self.mutex_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                mutex_found.append(f"In-memory mutex pattern: {pattern[:30]}...")

        # Check for file lock patterns
        file_lock_found = []
        for pattern in self.file_lock_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                file_lock_found.append(f"File lock pattern: {pattern[:30]}...")

        # Determine lock type
        if mutex_found and not file_lock_found:
            lock_type = "mutex"
            evidence.extend(mutex_found)
            evidence.append("This is an in-memory synchronization primitive")
        elif file_lock_found and not mutex_found:
            lock_type = "file_lock"
            evidence.extend(file_lock_found)
            evidence.append("This is a file-based lock for inter-process coordination")
        elif mutex_found and file_lock_found:
            lock_type = "hybrid"
            evidence.extend(mutex_found[:2] + file_lock_found[:2])
            evidence.append("Both in-memory and file-based locking detected")
        else:
            lock_type = "unknown"
            evidence.append("No clear locking pattern detected")

        # Assess if it's a false positive based on the finding type
        if "race" in category or "race" in message:
            if lock_type == "mutex":
                evidence.append("Mutex properly prevents race conditions in multi-threaded code")
                is_false_positive = True
                confidence = 0.8
            elif lock_type == "file_lock":
                evidence.append("File lock prevents race conditions across processes")
                is_false_positive = True
                confidence = 0.8

        elif "deadlock" in category or "deadlock" in message:
            if lock_type in ["mutex", "file_lock", "hybrid"]:
                # Check for proper lock ordering or timeout
                if re.search(r"timeout|timed|try_lock|acquire.*timeout", code_snippet, re.IGNORECASE):
                    evidence.append("Lock has timeout mechanism to prevent deadlocks")
                    is_false_positive = True
                    confidence = 0.7

        elif "synchron" in category or "thread" in message:
            if lock_type == "mutex":
                evidence.append("Proper thread synchronization mechanism in use")
                is_false_positive = True
                confidence = 0.8

        # Check for proper lock usage patterns
        proper_patterns = [
            r"with\s+.*lock",  # Context manager (Python)
            r"lock\s*\(\s*\)",  # RAII lock (C++)
            r"defer.*unlock",  # Deferred unlock (Go)
            r"finally.*unlock",  # Finally block unlock
            r"using.*lock",  # Using statement (C#)
            r"synchronized",  # Synchronized block (Java)
        ]

        for pattern in proper_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                evidence.append("Lock uses proper acquisition/release pattern")
                confidence += 0.1

        reasoning = {
            "mutex": "In-memory mutex for thread synchronization - appropriate for multi-threaded code.",
            "file_lock": "File-based lock for inter-process coordination - appropriate for distributed systems.",
            "hybrid": "Uses both in-memory and file-based locking for comprehensive synchronization.",
            "unknown": "Locking mechanism unclear - may need manual review."
        }.get(lock_type, "Unknown locking pattern.")

        if is_false_positive:
            reasoning = f"Proper locking mechanism in place. {reasoning}"

        return EnhancedFPAnalysis(
            is_false_positive=is_false_positive,
            confidence=confidence,
            category=f"locking_{lock_type}",
            reasoning=reasoning,
            evidence=evidence
        )

    def analyze(self, finding: dict[str, Any]) -> Optional[EnhancedFPAnalysis]:
        """
        Analyze finding with all enhanced detectors

        Args:
            finding: Security finding dictionary

        Returns:
            Most relevant EnhancedFPAnalysis or None
        """
        category = finding.get("category", "").lower()
        message = finding.get("message", "").lower()
        rule_id = finding.get("rule_id", "").lower()

        # Route to appropriate analyzer based on finding type
        if any(term in f"{category} {message} {rule_id}" for term in ["oauth", "client_id", "authorization"]):
            return self.analyze_oauth2_public_client(finding)

        elif any(term in f"{category} {message} {rule_id}" for term in ["plaintext", "permission", "file", "storage"]):
            return self.analyze_file_permissions(finding)

        elif any(term in f"{category} {message} {rule_id}" for term in ["debug", "dev", "config", "flag", "environment"]):
            return self.analyze_dev_config_flag(finding)

        elif any(term in f"{category} {message} {rule_id}" for term in ["lock", "mutex", "synchron", "race", "thread"]):
            return self.analyze_locking_mechanism(finding)

        return None


def integrate_with_agent_personas(finding: dict[str, Any], llm_manager) -> dict[str, Any]:
    """
    Integrate enhanced FP detection with existing agent personas

    Args:
        finding: Security finding dictionary
        llm_manager: LLM manager for AI analysis

    Returns:
        Enhanced finding with FP analysis
    """
    detector = EnhancedFalsePositiveDetector()
    enhanced_analysis = detector.analyze(finding)

    if enhanced_analysis and enhanced_analysis.is_false_positive:
        # Add enhanced analysis to finding metadata
        finding["enhanced_fp_analysis"] = {
            "is_false_positive": enhanced_analysis.is_false_positive,
            "confidence": enhanced_analysis.confidence,
            "category": enhanced_analysis.category,
            "reasoning": enhanced_analysis.reasoning,
            "evidence": enhanced_analysis.evidence
        }

        # Adjust severity if high confidence false positive
        if enhanced_analysis.confidence > 0.7:
            finding["original_severity"] = finding.get("severity", "unknown")
            finding["severity"] = "info"
            finding["suppressed"] = True
            finding["suppression_reason"] = enhanced_analysis.reasoning

    return finding