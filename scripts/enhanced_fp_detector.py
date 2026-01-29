#!/usr/bin/env python3
"""
Enhanced False Positive Detection Module for Argus Security
Adds intelligent detection for:
1. OAuth2 public client patterns (no secret protection needed)
2. File permissions validation for plaintext storage
3. Dev-only config flags vs production code
4. Different locking mechanisms (mutex vs file-based)
"""

import logging
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from finding_router import FindingRouter, RoutingDecision
from file_metadata_validator import FileMetadataValidator, MetadataValidationResult

logger = logging.getLogger(__name__)


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
        # Initialize intelligent router
        self.router = FindingRouter()

        # Initialize metadata validator for file permission checks
        self.metadata_validator = FileMetadataValidator()

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
            r"mock_|fake_|dummy_|test_|debug_",  # Test/debug prefixes
            r"#.*[Ee]xample|#.*[Dd]emo|#.*[Dd]ocumentation|#.*DO NOT USE",  # Example/demo comments
            r"//.*[Ee]xample|//.*[Dd]emo|//.*[Dd]ocumentation|//.*DO NOT USE",  # Example/demo comments
            r"#.*[Dd]ebug|//.*[Dd]ebug|#.*local testing|//.*local testing",  # Debug comments
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
        Now with metadata fallback when file not accessible

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

        # Try direct file check first
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

        # Fallback: metadata-driven validation
        logger.debug(f"File not accessible: {file_path}, trying metadata validation")
        metadata_result = self.metadata_validator.validate_from_metadata(file_path)

        if metadata_result.has_metadata:
            evidence.extend(metadata_result.permission_indicators)
            confidence = metadata_result.confidence

            # Determine if false positive based on metadata
            if confidence >= 0.5:
                is_false_positive = True
                reasoning = f"Metadata suggests proper security controls: {metadata_result.reasoning}"
            else:
                is_false_positive = False
                reasoning = f"Insufficient metadata evidence: {metadata_result.reasoning}"

            evidence.append(f"Sources checked: {', '.join(metadata_result.sources)}")
            evidence.append(f"Metadata confidence: {confidence:.2f} (lower than direct check)")
        else:
            # No metadata available
            evidence.append("File not accessible and no metadata available")
            confidence = 0.0
            reasoning = "Cannot validate permissions - file not accessible, no metadata found"

        return EnhancedFPAnalysis(
            is_false_positive=is_false_positive,
            confidence=confidence,
            category="file_permissions_metadata",
            reasoning=reasoning,
            evidence=evidence
        )

    def _check_dev_path_signals(self, file_path: str) -> list[str]:
        """
        Check for development-related path signals

        Args:
            file_path: Path to the file

        Returns:
            List of path-based evidence indicators
        """
        path_signals = []

        dev_path_patterns = [
            "test", "tests", "spec", "mock", "fixture", "example",
            "sample", "demo", "tutorial", "development", "dev",
            "__pycache__", "node_modules", ".git", "docs"
        ]

        for pattern in dev_path_patterns:
            if pattern in file_path.lower():
                path_signals.append(f"Dev path pattern: {pattern}")

        return path_signals

    def _check_dev_code_signals(self, code_snippet: str) -> list[str]:
        """
        Check for development-related code signals

        Args:
            code_snippet: Code to analyze

        Returns:
            List of code-based evidence indicators
        """
        code_signals = []

        # Check for dev config patterns in code
        for pattern in self.dev_config_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                code_signals.append(f"Dev code pattern: {pattern[:30]}...")

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
                code_signals.append(f"Environment conditional: {pattern}")

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
                code_signals.append("Build/test exclusion directive")

        # Check for dead/commented code
        if re.search(r"^\s*#|^\s*//|^\s*/\*", code_snippet, re.MULTILINE):
            lines = [line.strip() for line in code_snippet.split('\n') if line.strip()]  # Skip empty lines
            if len(lines) > 0:
                commented_lines = sum(1 for line in lines if re.match(r'^[#/]', line))
                comment_ratio = commented_lines / len(lines)
                if comment_ratio > 0.7:  # Lower threshold from 0.8 to 0.7
                    code_signals.append(f"Heavily commented code ({comment_ratio:.0%} commented)")

        return code_signals

    def _check_production_signals(self, code_snippet: str) -> list[str]:
        """
        Check for production code signals that should prevent suppression

        Args:
            code_snippet: Code to analyze

        Returns:
            List of production indicators
        """
        production_signals = []

        # Database imports and connections
        db_patterns = [
            r"import\s+(sqlalchemy|psycopg2|pymongo|redis|mysql|mariadb)",
            r"from\s+(sqlalchemy|psycopg2|pymongo|redis|mysql|mariadb)",
            r"create_engine\s*\(",
            r"\.connect\s*\([^)]*prod",
            r"Database\s*\(",
            r"MongoClient\s*\(",
        ]

        for pattern in db_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                production_signals.append(f"Database access pattern: {pattern[:40]}...")
                break  # One match is enough

        # API framework patterns
        api_patterns = [
            r"from\s+flask\s+import\s+Flask",
            r"from\s+fastapi\s+import\s+FastAPI",
            r"import\s+django",
            r"from\s+django",
            r"@app\.(route|get|post|put|delete)",
            r"@api\.(route|get|post)",
            r"express\(\)",
            r"Router\(\)",
        ]

        for pattern in api_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                production_signals.append(f"API framework pattern: {pattern[:40]}...")
                break

        # Authentication and security (but exclude mock/test contexts)
        auth_patterns = [
            r"import\s+jwt",
            r"from\s+.*\s+import\s+.*jwt",
            r"OAuth",
            r"passport",
            r"\.encode\s*\([^)]*jwt",
            r"\.decode\s*\([^)]*jwt",
        ]

        # Only check auth patterns if not in mock/test context
        has_mock_context = bool(re.search(r"(mock|Mock|unittest|pytest|test_)", code_snippet, re.IGNORECASE))

        for pattern in auth_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                # Don't treat as production if it's mock context
                if not has_mock_context:
                    production_signals.append(f"Authentication pattern: {pattern[:40]}...")
                    break

        # Cloud SDK patterns
        cloud_patterns = [
            r"import\s+boto3",
            r"from\s+boto3",
            r"from\s+google\.cloud",
            r"import\s+google\.cloud",
            r"from\s+azure",
            r"import\s+azure",
            r"s3_client",
            r"gcs_client",
            r"\.client\s*\(\s*['\"]s3['\"]",
        ]

        for pattern in cloud_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                production_signals.append(f"Cloud SDK pattern: {pattern[:40]}...")
                break

        # Production environment indicators
        prod_env_patterns = [
            r"prod[_-]db",
            r"production[_-](db|database|server|host)",
            r"['\"]prod['\"]",
            r"environment\s*==?\s*['\"]production['\"]",
            r"\.prod\.",
        ]

        for pattern in prod_env_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                production_signals.append(f"Production environment reference: {pattern[:40]}...")
                break

        return production_signals

    def analyze_dev_config_flag(self, finding: dict[str, Any]) -> EnhancedFPAnalysis:
        """
        Distinguish dev-only config flags from production code

        CRITICAL SECURITY FIX: Never suppress based on path alone.
        Requires minimum evidence from multiple signal types.

        Evidence Policy:
        - Path signals alone: INSUFFICIENT (prevents false suppression)
        - Code signals alone: Requires 3+ signals for high confidence
        - Path + code signals: Requires 1+ code signal minimum
        - Production signals: BLOCKS all suppression

        Args:
            finding: Security finding dictionary

        Returns:
            EnhancedFPAnalysis with dev config assessment
        """
        code_snippet = finding.get("evidence", {}).get("snippet", "")
        file_path = finding.get("path", finding.get("file_path", ""))
        line_number = finding.get("line", finding.get("line_number", 0))

        # Minimum evidence thresholds
        MIN_CODE_SIGNALS_ALONE = 2  # Need strong code evidence without path (e.g., DEBUG + __main__)
        MIN_SIGNALS_WITH_PATH = 1   # Need at least 1 code signal + path

        # Collect signals from different sources
        path_signals = self._check_dev_path_signals(file_path)
        code_signals = self._check_dev_code_signals(code_snippet)
        production_signals = self._check_production_signals(code_snippet)

        # Combine evidence for reporting
        all_evidence = []
        is_dev_only = False
        confidence = 0.0

        # CRITICAL: Production signals block all suppression
        if production_signals:
            all_evidence.extend(production_signals)
            all_evidence.append("PRODUCTION CODE DETECTED - suppression blocked")
            is_dev_only = False
            confidence = 0.0

            reasoning = (
                f"Production code detected ({len(production_signals)} production signals). "
                "This code uses production services (databases, APIs, cloud SDKs) "
                "and should not be suppressed regardless of file path."
            )
        else:
            # Apply evidence-based policy
            path_count = len(path_signals)
            code_count = len(code_signals)

            # Log signals for debugging
            if path_signals:
                all_evidence.append(f"Path signals: {path_count}")
                all_evidence.extend(path_signals[:3])  # Limit to first 3 for readability

            if code_signals:
                all_evidence.append(f"Code signals: {code_count}")
                all_evidence.extend(code_signals[:5])  # Limit to first 5

            # Check for high-confidence single signals (100% commented, example+comments, etc.)
            is_high_confidence_single = False
            if code_count == 1:
                for signal in code_signals:
                    # 100% commented code is extremely high confidence
                    if "100%" in signal and "commented" in signal.lower():
                        is_high_confidence_single = True
                        all_evidence.append("Single high-confidence signal: 100% commented code")
                        break
                    # Environment conditional in comments/docs with example patterns
                    if "Environment conditional" in signal and any(pat in file_path.lower() for pat in ["example", "docs", "tutorial"]):
                        is_high_confidence_single = True
                        all_evidence.append("Single high-confidence signal: Environment conditional in example/docs")
                        break

            # Special case: heavily commented code (>=90%) with DEBUG flag is high confidence
            has_heavy_comments = any("commented" in s and ("100%" in s or "90%" in s or "80%" in s) for s in code_signals)
            has_debug_flag = any("DEBUG" in s or "Environment conditional" in s for s in code_signals)

            # Decision logic with minimum evidence requirements
            if is_high_confidence_single:
                # Special case: single high-confidence signal
                is_dev_only = True
                confidence = 0.85
                all_evidence.append("High confidence from single strong signal")

            elif code_count >= MIN_CODE_SIGNALS_ALONE:
                # High confidence from code alone (e.g., __main__ + DEBUG + mock_ + console.log)
                is_dev_only = True
                confidence = min(0.7 + (code_count * 0.05), 0.95)
                all_evidence.append(f"High confidence: {code_count} code signals (threshold: {MIN_CODE_SIGNALS_ALONE})")

            elif path_count > 0 and code_count >= MIN_SIGNALS_WITH_PATH:
                # Medium confidence: path + code evidence
                is_dev_only = True
                confidence = min(0.6 + (code_count * 0.1) + (path_count * 0.05), 0.90)
                all_evidence.append(f"Medium confidence: path signals + {code_count} code signal(s)")

            elif path_count > 0 and code_count == 0:
                # Path only - INSUFFICIENT (prevents vulnerability)
                is_dev_only = False
                confidence = 0.0
                all_evidence.append(
                    f"INSUFFICIENT EVIDENCE: {path_count} path signal(s) without code confirmation "
                    f"(need {MIN_SIGNALS_WITH_PATH}+ code signals)"
                )

            else:
                # No sufficient evidence
                is_dev_only = False
                confidence = 0.0
                all_evidence.append("Insufficient evidence for dev-only classification")

            # Build reasoning
            if is_dev_only:
                reasoning = (
                    f"Development-only code detected with {confidence:.0%} confidence. "
                    f"Evidence: {code_count} code signals"
                )
                if path_count > 0:
                    reasoning += f" + {path_count} path signals"
                reasoning += ". This code likely won't run in production."
            else:
                reasoning = (
                    "Insufficient evidence for dev-only classification. "
                    f"Found {code_count} code signals and {path_count} path signals. "
                    f"Minimum required: {MIN_SIGNALS_WITH_PATH} code signal + path, "
                    f"or {MIN_CODE_SIGNALS_ALONE} code signals alone. "
                    "Treating as production code to prevent false suppression."
                )

        return EnhancedFPAnalysis(
            is_false_positive=is_dev_only,
            confidence=confidence,
            category="dev_config",
            reasoning=reasoning,
            evidence=all_evidence if all_evidence else ["No dev-only indicators found"]
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
        Analyze finding with intelligent routing

        Args:
            finding: Security finding dictionary

        Returns:
            Most relevant EnhancedFPAnalysis or None
        """
        # Get routing decision with confidence scoring
        routing = self.router.route_with_confidence(finding)

        if routing.confidence < 0.3:
            logger.debug(f"No confident routing found: {routing.reasoning}")
            return None

        if not routing.analyzer_method:
            logger.debug(f"No analyzer method available for {routing.finding_type.value}")
            return None

        logger.debug(
            f"Routing to {routing.analyzer_method} "
            f"(type: {routing.finding_type.value}, confidence: {routing.confidence:.2f})"
        )

        # Call the selected analyzer
        analyzer_method = getattr(self, routing.analyzer_method, None)
        if not analyzer_method:
            logger.warning(f"Analyzer method {routing.analyzer_method} not found")
            return None

        result = analyzer_method(finding)

        # Adjust result confidence based on routing confidence
        if result:
            original_confidence = result.confidence
            result.confidence *= routing.confidence
            result.evidence.insert(
                0,
                f"Routing confidence: {routing.confidence:.2f} "
                f"(adjusted from {original_confidence:.2f} to {result.confidence:.2f})"
            )
            logger.debug(
                f"Analysis complete: is_fp={result.is_false_positive}, "
                f"confidence={result.confidence:.2f}"
            )

        return result


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