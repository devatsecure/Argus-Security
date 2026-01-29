#!/usr/bin/env python3
"""
Test suite for Enhanced False Positive Detector security fix
Tests the path-only dev suppression vulnerability fix
"""

import pytest
from scripts.enhanced_fp_detector import EnhancedFalsePositiveDetector


class TestDevConfigSecurityFix:
    """Test cases for the critical security fix"""

    def test_production_code_in_test_path_not_suppressed(self):
        """
        CRITICAL: Production code in test paths should NOT be suppressed
        Example: tests/integration/api_server.py with real DB connections
        """
        detector = EnhancedFalsePositiveDetector()

        # Real production API server that happens to be in tests/integration
        finding = {
            "path": "tests/integration/api_server.py",
            "file_path": "tests/integration/api_server.py",
            "line": 42,
            "message": "Hardcoded database password",
            "evidence": {
                "snippet": """
import psycopg2
from flask import Flask

app = Flask(__name__)

# Production database connection
conn = psycopg2.connect(
    host="prod-db.company.com",
    database="users",
    user="admin",
    password="SuperSecret123!"
)

@app.route('/api/users')
def get_users():
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # MUST NOT suppress production code just because of path
        assert result.is_false_positive == False, (
            "Production code with real DB connections should NOT be suppressed "
            "even if in 'tests/' path"
        )

    def test_real_test_code_with_multiple_signals_suppressed(self):
        """
        Test code with multiple dev signals should be suppressed
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "tests/unit/test_auth.py",
            "file_path": "tests/unit/test_auth.py",
            "line": 15,
            "message": "Hardcoded password",
            "evidence": {
                "snippet": """
import pytest
from unittest.mock import Mock

def test_login_success():
    # Mock user for testing
    mock_user = Mock()
    mock_user.username = "test_user"
    mock_user.password = "test_password_123"

    # Test authentication
    result = authenticate(mock_user)
    assert result is True
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # Should suppress: has test path + mock imports + test_ prefix
        assert result.is_false_positive == True, (
            "Test code with multiple dev signals should be suppressed"
        )
        assert result.confidence >= 0.6

    def test_production_api_not_suppressed(self):
        """
        Production API code should never be suppressed
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "src/api/auth.py",
            "file_path": "src/api/auth.py",
            "line": 23,
            "message": "Hardcoded JWT secret",
            "evidence": {
                "snippet": """
from fastapi import FastAPI, Depends
from sqlalchemy import create_engine
import jwt

app = FastAPI()

JWT_SECRET = "prod-secret-key-12345"

@app.post("/api/login")
async def login(credentials: dict):
    engine = create_engine("postgresql://prod-db:5432/users")
    # Authenticate and return JWT
    token = jwt.encode({"user": credentials["username"]}, JWT_SECRET)
    return {"token": token}
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # MUST NOT suppress production API code
        assert result.is_false_positive == False, (
            "Production API code with real JWT and DB should NOT be suppressed"
        )

    def test_example_in_production_path_suppressed(self):
        """
        Example/demo code in docs should be suppressed
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "docs/examples/authentication_example.py",
            "file_path": "docs/examples/authentication_example.py",
            "line": 10,
            "message": "Hardcoded credentials",
            "evidence": {
                "snippet": """
# Example authentication code for documentation
# This is a simplified example for demonstration purposes

def example_login():
    # Example credentials - DO NOT USE IN PRODUCTION
    username = "demo_user"
    password = "example_password_123"

    print("This is just an example!")
    return authenticate(username, password)
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # Should suppress: example path + example_ prefix + comments indicating demo
        assert result.is_false_positive == True
        assert result.confidence >= 0.6

    def test_commented_code_suppressed(self):
        """
        Heavily commented/dead code should be suppressed
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "src/legacy/old_auth.py",
            "file_path": "src/legacy/old_auth.py",
            "line": 5,
            "message": "Hardcoded password",
            "evidence": {
                "snippet": """
# # Old authentication system - deprecated
# def old_login():
#     password = "old_password_123"
#     # This code is no longer used
#     # return check_password(password)
#
# # Commented out for now - will delete later
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # Should suppress: heavily commented (dead code)
        assert result.is_false_positive == True
        assert result.confidence >= 0.7

    def test_insufficient_signals_not_suppressed(self):
        """
        Code with only path signal (no code signals) should NOT be suppressed
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "tests/fixtures/production_config.py",
            "file_path": "tests/fixtures/production_config.py",
            "line": 3,
            "message": "Hardcoded API key",
            "evidence": {
                "snippet": """
# Production configuration loaded during integration tests
PRODUCTION_API_KEY = "prod-key-abc123"
PRODUCTION_DB_HOST = "prod-db.company.com"
PRODUCTION_SECRET = "real-secret-value"
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # MUST NOT suppress: only path signals, no code signals indicating dev/test
        assert result.is_false_positive == False, (
            "Production config should not be suppressed based on path alone"
        )

    def test_cloud_sdk_production_signal(self):
        """
        Code using cloud SDKs should be treated as production
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "tests/integration/aws_upload.py",
            "file_path": "tests/integration/aws_upload.py",
            "line": 8,
            "message": "Hardcoded AWS credentials",
            "evidence": {
                "snippet": """
import boto3

# AWS S3 client for production uploads
s3_client = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)

def upload_file(file_path):
    s3_client.upload_file(file_path, 'production-bucket', 'file.txt')
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # MUST NOT suppress: boto3 indicates production cloud operations
        assert result.is_false_positive == False, (
            "Code using boto3/cloud SDKs should not be suppressed as dev-only"
        )

    def test_debug_flag_with_conditional(self):
        """
        Code wrapped in debug conditional should be suppressed
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "src/utils/logger.py",
            "file_path": "src/utils/logger.py",
            "line": 12,
            "message": "Debug logging enabled",
            "evidence": {
                "snippet": """
import os

if os.environ.get('DEBUG') == 'true':
    # Debug-only credentials for local testing
    debug_user = "debug_user"
    debug_pass = "debug_password_123"
    print(f"DEBUG MODE: Using {debug_user}:{debug_pass}")
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # Should suppress: wrapped in DEBUG environment check
        assert result.is_false_positive == True
        assert result.confidence >= 0.6

    def test_main_guard_with_test_code(self):
        """
        Code in __main__ guard with test patterns should be suppressed
        """
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "src/service.py",
            "file_path": "src/service.py",
            "line": 50,
            "message": "Hardcoded password",
            "evidence": {
                "snippet": """
if __name__ == "__main__":
    # Quick test of the service
    test_password = "test123"
    print(f"Testing with password: {test_password}")
    service = MyService(test_password)
    service.run()
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)

        # Should suppress: __main__ guard + test_ prefix + local testing comment
        assert result.is_false_positive == True
        assert result.confidence >= 0.6


class TestSignalCounting:
    """Test the signal counting logic"""

    def test_path_signal_only_insufficient(self):
        """Only path signal should not trigger suppression"""
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "tests/production_secrets.py",
            "file_path": "tests/production_secrets.py",
            "evidence": {"snippet": "PASSWORD = 'real_prod_password'"}
        }

        result = detector.analyze_dev_config_flag(finding)
        assert result.is_false_positive == False

    def test_code_signal_only_insufficient(self):
        """Single code signal without path should not trigger suppression"""
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "src/config.py",
            "file_path": "src/config.py",
            "evidence": {"snippet": "# TODO: move to env var\nPASSWORD = 'secret123'"}
        }

        result = detector.analyze_dev_config_flag(finding)
        assert result.is_false_positive == False

    def test_path_plus_code_signal_sufficient(self):
        """Path signal + code signal should trigger suppression"""
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "tests/test_auth.py",
            "file_path": "tests/test_auth.py",
            "evidence": {"snippet": "mock_password = 'test123'  # TODO: fix"}
        }

        result = detector.analyze_dev_config_flag(finding)
        assert result.is_false_positive == True

    def test_multiple_code_signals_sufficient(self):
        """Multiple code signals alone should trigger suppression"""
        detector = EnhancedFalsePositiveDetector()

        finding = {
            "path": "src/validator.py",
            "file_path": "src/validator.py",
            "evidence": {
                "snippet": """
if __name__ == "__main__":
    # TODO: Remove this test code
    DEBUG = True
    mock_user = "test_user"
    console.log("Testing validation")
"""
            }
        }

        result = detector.analyze_dev_config_flag(finding)
        # Multiple code signals: __main__, TODO, DEBUG, mock_, console.log
        assert result.is_false_positive == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
