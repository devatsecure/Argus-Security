#!/usr/bin/env python3
"""
Unit tests for Enhanced False Positive Detector
Tests OAuth2 public clients, file permissions, dev configs, and locking mechanisms
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../scripts'))

from enhanced_fp_detector import (
    EnhancedFalsePositiveDetector,
    EnhancedFPAnalysis,
    integrate_with_agent_personas
)


class TestOAuth2PublicClientDetection(unittest.TestCase):
    """Test OAuth2 public client pattern detection"""

    def setUp(self):
        self.detector = EnhancedFalsePositiveDetector()

    def test_detect_oauth2_public_client_with_pkce(self):
        """Test detection of OAuth2 public client using PKCE"""
        finding = {
            "path": "/app/frontend/auth.js",
            "category": "hardcoded-secret",
            "message": "Potential OAuth client_id exposed",
            "evidence": {
                "snippet": """
                const authConfig = {
                    client_id: 'spa-client-123',
                    redirect_uri: 'https://app.example.com/callback',
                    response_type: 'code',
                    code_challenge: generateChallenge(),
                    code_challenge_method: 'S256'
                };
                """
            }
        }

        result = self.detector.analyze_oauth2_public_client(finding)

        self.assertTrue(result.is_false_positive)
        self.assertGreater(result.confidence, 0.7)
        self.assertEqual(result.category, "oauth2_public_client")
        self.assertIn("PKCE", " ".join(result.evidence))

    def test_detect_oauth2_spa_client(self):
        """Test detection of SPA OAuth2 client"""
        finding = {
            "path": "/spa/src/auth/config.js",
            "category": "hardcoded-secret",
            "message": "OAuth client_id found",
            "evidence": {
                "snippet": """
                // SPA OAuth configuration
                export const oauthConfig = {
                    client_id: 'my-spa-app',
                    grant_type: 'authorization_code',
                    scope: 'openid profile email'
                };
                // Note: No client_secret needed for public clients
                """
            }
        }

        result = self.detector.analyze_oauth2_public_client(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("No client_secret found", " ".join(result.evidence))
        self.assertIn("spa", result.evidence[0].lower() if result.evidence else "")

    def test_detect_oauth2_mobile_client(self):
        """Test detection of mobile OAuth2 client"""
        finding = {
            "path": "/mobile/ios/AuthManager.swift",
            "category": "hardcoded-secret",
            "message": "OAuth configuration exposed",
            "evidence": {
                "snippet": """
                let clientId = "mobile-app-client"
                let redirectUri = "myapp://callback"
                let responseType = "code"
                // Using PKCE for mobile OAuth
                let codeVerifier = generateVerifier()
                """
            }
        }

        result = self.detector.analyze_oauth2_public_client(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("mobile", " ".join(result.evidence).lower())

    def test_detect_oauth2_confidential_client(self):
        """Test that confidential clients are NOT marked as false positives"""
        finding = {
            "path": "/backend/api/oauth.py",
            "category": "hardcoded-secret",
            "message": "OAuth credentials exposed",
            "evidence": {
                "snippet": """
                oauth_config = {
                    'client_id': 'backend-service',
                    'client_secret': 'super-secret-key-123',  # DANGER!
                    'grant_type': 'client_credentials'
                }
                """
            }
        }

        result = self.detector.analyze_oauth2_public_client(finding)

        self.assertFalse(result.is_false_positive)
        self.assertLess(result.confidence, 0.5)

    def test_implicit_grant_flow(self):
        """Test detection of implicit grant flow (public client)"""
        finding = {
            "path": "/frontend/auth.js",
            "category": "security",
            "message": "OAuth implicit flow detected",
            "evidence": {
                "snippet": """
                const implicitAuth = {
                    client_id: 'spa-implicit',
                    response_type: 'token',
                    redirect_uri: window.location.origin
                };
                """
            }
        }

        result = self.detector.analyze_oauth2_public_client(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("Implicit grant flow", " ".join(result.evidence))


class TestFilePermissionValidation(unittest.TestCase):
    """Test file permission validation for plaintext storage"""

    def setUp(self):
        self.detector = EnhancedFalsePositiveDetector()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temp files"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_secure_file_permissions(self):
        """Test detection of properly secured files"""
        # Create a file with secure permissions (600)
        secure_file = Path(self.temp_dir) / "secrets.conf"
        secure_file.write_text("api_key=secret123")
        os.chmod(secure_file, 0o600)  # Owner read/write only

        finding = {
            "path": str(secure_file),
            "category": "plaintext-storage",
            "message": "Sensitive data in plaintext file",
            "evidence": {"snippet": "api_key=secret123"}
        }

        result = self.detector.analyze_file_permissions(finding)

        self.assertTrue(result.is_false_positive)
        self.assertGreater(result.confidence, 0.5)
        self.assertIn("0o600", " ".join(result.evidence))

    def test_insecure_file_permissions(self):
        """Test detection of insecure file permissions"""
        # Create a world-readable file
        insecure_file = Path(self.temp_dir) / "passwords.txt"
        insecure_file.write_text("password=admin123")
        os.chmod(insecure_file, 0o644)  # World-readable

        finding = {
            "path": str(insecure_file),
            "category": "plaintext-storage",
            "message": "Passwords stored in plaintext",
            "evidence": {"snippet": "password=admin123"}
        }

        result = self.detector.analyze_file_permissions(finding)

        self.assertFalse(result.is_false_positive)
        self.assertIn("0o644", " ".join(result.evidence))

    @patch('os.path.exists')
    @patch('os.stat')
    def test_socket_file(self, mock_stat, mock_exists):
        """Test that socket files are marked as false positives"""
        mock_exists.return_value = True

        # Mock a socket file
        mock_stat_result = MagicMock()
        mock_stat_result.st_mode = stat.S_IFSOCK | 0o600
        mock_stat.return_value = mock_stat_result

        finding = {
            "path": "/var/run/app.sock",
            "category": "plaintext-storage",
            "message": "Data exposed in file",
            "evidence": {"snippet": ""}
        }

        result = self.detector.analyze_file_permissions(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("socket", " ".join(result.evidence).lower())

    def test_ssh_directory_file(self):
        """Test files in .ssh directory are recognized as secure"""
        finding = {
            "path": "/home/user/.ssh/id_rsa",
            "category": "plaintext-storage",
            "message": "Private key stored in plaintext",
            "evidence": {"snippet": "-----BEGIN RSA PRIVATE KEY-----"}
        }

        result = self.detector.analyze_file_permissions(finding)

        # Even without checking actual permissions, .ssh files should be noted
        self.assertIn(".ssh", " ".join(result.evidence).lower())


class TestDevConfigDetection(unittest.TestCase):
    """Test dev-only configuration flag detection"""

    def setUp(self):
        self.detector = EnhancedFalsePositiveDetector()

    def test_detect_debug_flag_in_dev_check(self):
        """Test detection of DEBUG flag wrapped in environment check"""
        finding = {
            "path": "/app/settings.py",
            "category": "security-misconfiguration",
            "message": "DEBUG mode enabled",
            "evidence": {
                "snippet": """
                import os

                if os.getenv('ENV') != 'production':
                    DEBUG = True
                else:
                    DEBUG = False
                """
            }
        }

        result = self.detector.analyze_dev_config_flag(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("environment conditional", " ".join(result.evidence).lower())

    def test_detect_localhost_in_dev(self):
        """Test detection of localhost configuration"""
        finding = {
            "path": "/test/config.js",
            "category": "hardcoded-host",
            "message": "Hardcoded localhost found",
            "evidence": {
                "snippet": """
                const config = {
                    apiUrl: 'http://localhost:3000',
                    database: '127.0.0.1:5432'
                };
                """
            }
        }

        result = self.detector.analyze_dev_config_flag(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("localhost", " ".join(result.evidence).lower())

    def test_detect_console_log(self):
        """Test detection of console.log statements"""
        finding = {
            "path": "/src/debug.js",
            "category": "information-disclosure",
            "message": "Console logging found",
            "evidence": {
                "snippet": """
                function debugUser(user) {
                    console.log('User data:', user);
                    console.debug('Detailed info:', user.details);
                }
                """
            }
        }

        result = self.detector.analyze_dev_config_flag(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("console", " ".join(result.evidence).lower())

    def test_detect_node_env_check(self):
        """Test detection of NODE_ENV production check"""
        finding = {
            "path": "/app/server.js",
            "category": "security",
            "message": "Sensitive operation",
            "evidence": {
                "snippet": """
                if (process.env.NODE_ENV !== 'production') {
                    app.use(morgan('dev'));
                    app.use(debugMiddleware);
                }
                """
            }
        }

        result = self.detector.analyze_dev_config_flag(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("NODE_ENV", " ".join(result.evidence))

    def test_detect_test_prefix(self):
        """Test detection of test/mock prefixes"""
        finding = {
            "path": "/lib/helpers.py",
            "category": "hardcoded-secret",
            "message": "Hardcoded credentials",
            "evidence": {
                "snippet": """
                def get_test_credentials():
                    mock_user = "test_admin"
                    fake_password = "dummy_pass123"
                    return mock_user, fake_password
                """
            }
        }

        result = self.detector.analyze_dev_config_flag(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("mock_", " ".join(result.evidence).lower())

    def test_production_code_not_flagged(self):
        """Test that production code is NOT marked as false positive"""
        finding = {
            "path": "/app/production.py",
            "category": "security",
            "message": "Security issue",
            "evidence": {
                "snippet": """
                # Production configuration
                API_KEY = os.getenv('PROD_API_KEY')
                DATABASE_URL = os.getenv('PROD_DB_URL')
                """
            }
        }

        result = self.detector.analyze_dev_config_flag(finding)

        self.assertFalse(result.is_false_positive)


class TestLockingMechanismDetection(unittest.TestCase):
    """Test locking mechanism detection (mutex vs file-based)"""

    def setUp(self):
        self.detector = EnhancedFalsePositiveDetector()

    def test_detect_python_threading_lock(self):
        """Test detection of Python threading locks"""
        finding = {
            "category": "race-condition",
            "message": "Potential race condition",
            "evidence": {
                "snippet": """
                import threading

                lock = threading.Lock()

                def critical_section():
                    with lock:
                        # Protected code
                        shared_resource.update()
                """
            }
        }

        result = self.detector.analyze_locking_mechanism(finding)

        self.assertTrue(result.is_false_positive)
        self.assertEqual(result.category, "locking_mutex")
        self.assertIn("threading", " ".join(result.evidence).lower())

    def test_detect_file_lock(self):
        """Test detection of file-based locking"""
        finding = {
            "category": "race-condition",
            "message": "File access race condition",
            "evidence": {
                "snippet": """
                import fcntl

                with open('/var/lock/app.lock', 'w') as lockfile:
                    fcntl.flock(lockfile, fcntl.LOCK_EX)
                    # Critical section
                    process_shared_file()
                    fcntl.flock(lockfile, fcntl.LOCK_UN)
                """
            }
        }

        result = self.detector.analyze_locking_mechanism(finding)

        self.assertTrue(result.is_false_positive)
        self.assertEqual(result.category, "locking_file_lock")
        self.assertIn("flock", " ".join(result.evidence).lower())

    def test_detect_go_mutex(self):
        """Test detection of Go mutex"""
        finding = {
            "category": "race-condition",
            "message": "Concurrent access issue",
            "evidence": {
                "snippet": """
                var mu sync.Mutex

                func updateCounter() {
                    mu.Lock()
                    defer mu.Unlock()
                    counter++
                }
                """
            }
        }

        result = self.detector.analyze_locking_mechanism(finding)

        self.assertTrue(result.is_false_positive)
        self.assertEqual(result.category, "locking_mutex")
        self.assertIn("sync.Mutex", " ".join(result.evidence))

    def test_detect_java_synchronized(self):
        """Test detection of Java synchronized blocks"""
        finding = {
            "category": "thread-safety",
            "message": "Thread safety issue",
            "evidence": {
                "snippet": """
                public class Counter {
                    private int count = 0;

                    public synchronized void increment() {
                        count++;
                    }
                }
                """
            }
        }

        result = self.detector.analyze_locking_mechanism(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("synchronized", " ".join(result.evidence).lower())

    def test_detect_lock_with_timeout(self):
        """Test detection of locks with timeout (deadlock prevention)"""
        finding = {
            "category": "deadlock",
            "message": "Potential deadlock",
            "evidence": {
                "snippet": """
                import threading

                lock = threading.Lock()

                if lock.acquire(timeout=5):
                    try:
                        do_work()
                    finally:
                        lock.release()
                """
            }
        }

        result = self.detector.analyze_locking_mechanism(finding)

        self.assertTrue(result.is_false_positive)
        self.assertIn("timeout", " ".join(result.evidence).lower())

    def test_no_lock_detected(self):
        """Test when no locking mechanism is detected"""
        finding = {
            "category": "race-condition",
            "message": "Unsafe concurrent access",
            "evidence": {
                "snippet": """
                global_counter = 0

                def increment():
                    global global_counter
                    global_counter += 1  # Not thread-safe!
                """
            }
        }

        result = self.detector.analyze_locking_mechanism(finding)

        self.assertFalse(result.is_false_positive)
        self.assertEqual(result.category, "locking_unknown")


class TestIntegrationWithAgentPersonas(unittest.TestCase):
    """Test integration with agent personas"""

    def test_integrate_oauth2_finding(self):
        """Test integration adds OAuth2 analysis to finding"""
        finding = {
            "id": "test-001",
            "path": "/spa/auth.js",
            "category": "hardcoded-secret",
            "severity": "high",
            "message": "OAuth client_id exposed",
            "evidence": {
                "snippet": "client_id: 'spa-app', code_challenge: challenge"
            }
        }

        mock_llm = MagicMock()
        enhanced_finding = integrate_with_agent_personas(finding, mock_llm)

        self.assertIn("enhanced_fp_analysis", enhanced_finding)
        self.assertTrue(enhanced_finding["enhanced_fp_analysis"]["is_false_positive"])
        self.assertEqual(enhanced_finding["severity"], "info")
        self.assertTrue(enhanced_finding.get("suppressed", False))

    def test_integrate_preserves_original_severity(self):
        """Test that original severity is preserved"""
        finding = {
            "id": "test-002",
            "path": "/backend/api.py",
            "category": "sql-injection",
            "severity": "critical",
            "message": "SQL injection vulnerability",
            "evidence": {"snippet": "query = 'SELECT * FROM users WHERE id=' + user_id"}
        }

        mock_llm = MagicMock()
        enhanced_finding = integrate_with_agent_personas(finding, mock_llm)

        # Should not be marked as FP, so severity unchanged
        self.assertEqual(enhanced_finding.get("severity"), "critical")
        self.assertFalse(enhanced_finding.get("suppressed", False))


class TestEnhancedDetectorRouting(unittest.TestCase):
    """Test that the detector routes to correct analyzers"""

    def setUp(self):
        self.detector = EnhancedFalsePositiveDetector()

    def test_route_oauth_finding(self):
        """Test OAuth findings are routed correctly"""
        finding = {
            "category": "oauth-issue",
            "message": "OAuth configuration",
            "evidence": {"snippet": "client_id: 'app'"}
        }

        result = self.detector.analyze(finding)

        self.assertIsNotNone(result)
        self.assertEqual(result.category, "oauth2_public_client")

    def test_route_file_permission_finding(self):
        """Test file permission findings are routed correctly"""
        finding = {
            "category": "plaintext-storage",
            "message": "Sensitive data in file",
            "path": "/tmp/test.txt",
            "evidence": {"snippet": "password=123"}
        }

        result = self.detector.analyze(finding)

        self.assertIsNotNone(result)
        self.assertEqual(result.category, "file_permissions")

    def test_route_debug_finding(self):
        """Test debug/dev findings are routed correctly"""
        finding = {
            "category": "debug-enabled",
            "message": "Debug mode active",
            "evidence": {"snippet": "DEBUG = True"}
        }

        result = self.detector.analyze(finding)

        self.assertIsNotNone(result)
        self.assertEqual(result.category, "dev_config")

    def test_route_lock_finding(self):
        """Test lock/mutex findings are routed correctly"""
        finding = {
            "category": "race-condition",
            "message": "Thread safety issue",
            "evidence": {"snippet": "threading.Lock()"}
        }

        result = self.detector.analyze(finding)

        self.assertIsNotNone(result)
        self.assertIn("locking_", result.category)

    def test_no_route_for_unrelated_finding(self):
        """Test unrelated findings return None"""
        finding = {
            "category": "xss",
            "message": "Cross-site scripting",
            "evidence": {"snippet": "<script>alert('xss')</script>"}
        }

        result = self.detector.analyze(finding)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()