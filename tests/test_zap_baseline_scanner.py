"""Tests for zap_baseline_scanner.py - ZAP Baseline Scanner Module.

Covers:
- ZAPBaselineScanner initialization (binary discovery, docker mode)
- Source analysis (info disclosure, missing headers, cookies, server config, verbose errors)
- Live scanning (command building, subprocess handling, report parsing)
- ZAP report parsing (JSON and XML formats)
- Helper methods (finding ID generation, test file detection, OWASP mapping)
- Edge cases (empty files, comments, non-existent paths)
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.zap_baseline_scanner import (
    SCANNABLE_EXTENSIONS,
    ZAP_RISK_TO_SEVERITY,
    ZAP_SEARCH_PATHS,
    ZAPBaselineScanner,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    """Create a ZAPBaselineScanner with no ZAP binary found."""
    with patch.object(ZAPBaselineScanner, "_find_zap_binary", return_value=None):
        return ZAPBaselineScanner()


@pytest.fixture
def scanner_with_zap():
    """Create a ZAPBaselineScanner with a ZAP binary path set."""
    return ZAPBaselineScanner(zap_path="/usr/share/zaproxy/zap-baseline.py")


@pytest.fixture
def scanner_docker():
    """Create a ZAPBaselineScanner in docker mode."""
    return ZAPBaselineScanner(docker_mode=True)


@pytest.fixture
def source_tree(tmp_path):
    """Create a sample source tree for scanning."""
    # Python file with info disclosure
    py_file = tmp_path / "app.py"
    py_file.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/debug')\n"
        "def debug():\n"
        "    DEBUG = True\n"
        "    return str(e)\n"
    )

    # PHP file with phpinfo
    php_file = tmp_path / "info.php"
    php_file.write_text(
        "<?php\n"
        "phpinfo();\n"
        "?>\n"
    )

    # Config file with server misconfiguration
    htaccess = tmp_path / ".htaccess"
    htaccess.write_text("Options +Indexes\n")

    # Nginx config
    nginx_dir = tmp_path / "config"
    nginx_dir.mkdir()
    nginx_conf = nginx_dir / "nginx.conf"
    nginx_conf.write_text(
        "server {\n"
        "    autoindex on;\n"
        "    server_tokens on;\n"
        "}\n"
    )

    # JavaScript with cookie setting
    js_file = tmp_path / "server.js"
    js_file.write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "\n"
        "app.get('/login', (req, res) => {\n"
        "    res.cookie('session', token);\n"
        "    res.send('ok');\n"
        "});\n"
    )

    # Empty file (should be skipped)
    empty = tmp_path / "empty.py"
    empty.write_text("")

    # Test file (should be skipped)
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    test_file = test_dir / "test_app.py"
    test_file.write_text("phpinfo()\nDEBUG = True\n")

    # node_modules (should be skipped)
    nm = tmp_path / "node_modules"
    nm.mkdir()
    nm_file = nm / "module.js"
    nm_file.write_text("phpinfo();\n")

    return tmp_path


@pytest.fixture
def zap_json_report(tmp_path):
    """Create a sample ZAP JSON report."""
    report = {
        "site": [
            {
                "alerts": [
                    {
                        "alert": "Missing X-Frame-Options Header",
                        "riskcode": "2",
                        "cweid": "1021",
                        "pluginid": "10020",
                        "alertRef": "10020",
                        "desc": "X-Frame-Options header missing",
                        "solution": "Set X-Frame-Options header",
                        "instances": [
                            {"uri": "https://example.com/page1"}
                        ],
                    },
                    {
                        "alert": "Server Leaks Version",
                        "riskcode": "1",
                        "cweid": "200",
                        "pluginid": "10036",
                        "alertRef": "10036",
                        "desc": "Server version disclosed",
                        "solution": "Remove version info",
                        "instances": [
                            {"uri": "https://example.com/"}
                        ],
                    },
                    {
                        "alert": "Informational Notice",
                        "riskcode": "0",
                        "cweid": "200",
                        "pluginid": "10000",
                        "desc": "Just info",
                        "solution": "N/A",
                        "instances": [],
                    },
                ]
            }
        ]
    }
    path = tmp_path / "zap_report.json"
    path.write_text(json.dumps(report))
    return str(path)


@pytest.fixture
def zap_xml_report(tmp_path):
    """Create a sample ZAP XML report."""
    xml_content = """<?xml version="1.0"?>
<OWASPZAPReport>
  <site name="https://example.com">
    <alerts>
      <alertitem>
        <alert>SQL Injection</alert>
        <riskcode>3</riskcode>
        <cweid>89</cweid>
        <pluginid>40018</pluginid>
        <desc>SQL injection found</desc>
        <solution>Use parameterized queries</solution>
        <instances>
          <instance>
            <uri>https://example.com/search?q=test</uri>
          </instance>
        </instances>
      </alertitem>
      <alertitem>
        <alert>Info Only</alert>
        <riskcode>0</riskcode>
        <cweid>200</cweid>
        <pluginid>10000</pluginid>
        <desc>Just informational</desc>
        <solution>N/A</solution>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""
    path = tmp_path / "zap_report.xml"
    path.write_text(xml_content)
    return str(path)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_no_zap(self):
        with patch.object(ZAPBaselineScanner, "_find_zap_binary", return_value=None):
            s = ZAPBaselineScanner()
        assert s.zap_path is None
        assert s.docker_mode is False

    def test_init_with_zap_path(self):
        s = ZAPBaselineScanner(zap_path="/usr/share/zaproxy/zap-baseline.py")
        assert s.zap_path == "/usr/share/zaproxy/zap-baseline.py"

    def test_init_docker_mode(self):
        s = ZAPBaselineScanner(docker_mode=True)
        assert s.docker_mode is True
        assert s.zap_path is None  # Not searched in docker mode

    def test_init_finding_counter(self, scanner):
        assert scanner._finding_counter == 0

    def test_init_patterns_compiled(self, scanner):
        assert len(scanner._info_disclosure_patterns) > 0
        assert len(scanner._cookie_patterns) > 0
        assert len(scanner._server_config_patterns) > 0
        assert len(scanner._verbose_error_patterns) > 0
        assert scanner._response_indicators is not None


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

class TestFindZapBinary:
    def test_find_in_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/zap-baseline.py"):
            s = ZAPBaselineScanner()
        assert s.zap_path == "/usr/local/bin/zap-baseline.py"

    def test_find_in_search_paths(self):
        with patch("shutil.which", return_value=None), \
             patch("os.path.isfile") as mock_isfile, \
             patch("os.access") as mock_access:
            mock_isfile.side_effect = lambda p: p == "/opt/zaproxy/zap-baseline.py"
            mock_access.side_effect = lambda p, m: p == "/opt/zaproxy/zap-baseline.py"
            s = ZAPBaselineScanner()
        assert s.zap_path == "/opt/zaproxy/zap-baseline.py"

    def test_not_found_anywhere(self):
        with patch("shutil.which", return_value=None), \
             patch("os.path.isfile", return_value=False):
            s = ZAPBaselineScanner()
        assert s.zap_path is None


# ---------------------------------------------------------------------------
# Finding ID generation
# ---------------------------------------------------------------------------

class TestFindingIdGeneration:
    def test_deterministic(self, scanner):
        id1 = scanner._generate_finding_id("INFO", "app.py", 10)
        id2 = scanner._generate_finding_id("INFO", "app.py", 10)
        assert id1 == id2

    def test_different_for_different_inputs(self, scanner):
        id1 = scanner._generate_finding_id("INFO", "app.py", 10)
        id2 = scanner._generate_finding_id("INFO", "app.py", 20)
        assert id1 != id2

    def test_format(self, scanner):
        fid = scanner._generate_finding_id("HDR", "views.py", 5)
        assert fid.startswith("ZAP-HDR-")
        assert len(fid) == len("ZAP-HDR-") + 8  # 8 hex chars


# ---------------------------------------------------------------------------
# Test file detection
# ---------------------------------------------------------------------------

class TestIsTestFile:
    def test_test_directory(self):
        assert ZAPBaselineScanner._is_test_file("/project/tests/test_app.py") is True

    def test_test_prefix(self):
        assert ZAPBaselineScanner._is_test_file("/project/test_utils.py") is True

    def test_test_suffix(self):
        assert ZAPBaselineScanner._is_test_file("/project/app.test.js") is True

    def test_spec_file(self):
        assert ZAPBaselineScanner._is_test_file("/project/app.spec.ts") is True

    def test_not_test_file(self):
        assert ZAPBaselineScanner._is_test_file("/project/src/app.py") is False

    def test_jest_tests_dir(self):
        assert ZAPBaselineScanner._is_test_file("/project/__tests__/app.js") is True


# ---------------------------------------------------------------------------
# Source analysis: information disclosure
# ---------------------------------------------------------------------------

class TestInfoDisclosure:
    def test_detect_phpinfo(self, scanner):
        findings = scanner._detect_info_disclosure("info.php", "<?php\nphpinfo();\n?>")
        assert len(findings) >= 1
        assert any("phpinfo" in f["title"] for f in findings)

    def test_detect_var_dump(self, scanner):
        findings = scanner._detect_info_disclosure("debug.php", "var_dump($data);")
        assert len(findings) >= 1

    def test_detect_debug_mode(self, scanner):
        findings = scanner._detect_info_disclosure("settings.py", "DEBUG = True")
        assert len(findings) >= 1
        assert any("CWE-489" in f["cwe_id"] for f in findings)

    def test_detect_flask_debug(self, scanner):
        findings = scanner._detect_info_disclosure("app.py", "app.debug = True")
        assert len(findings) >= 1

    def test_detect_debug_in_config(self, scanner):
        findings = scanner._detect_info_disclosure("config.json", "'debug': True")
        assert len(findings) >= 1

    def test_detect_traceback_exposure(self, scanner):
        findings = scanner._detect_info_disclosure("handler.py", "traceback.format_exc()")
        assert len(findings) >= 1
        assert any("CWE-209" in f["cwe_id"] for f in findings)

    def test_detect_server_version_header(self, scanner):
        code = '"Server": "Apache/2.4.41"'
        findings = scanner._detect_info_disclosure("headers.py", code)
        assert len(findings) >= 1

    def test_detect_x_powered_by(self, scanner):
        code = '"X-Powered-By": "Express"'
        findings = scanner._detect_info_disclosure("middleware.js", code)
        assert len(findings) >= 1

    def test_skip_comments(self, scanner):
        code = "# phpinfo() is disabled\n// var_dump is off"
        findings = scanner._detect_info_disclosure("safe.py", code)
        assert len(findings) == 0

    def test_detect_display_errors(self, scanner):
        findings = scanner._detect_info_disclosure("php.ini", "display_errors = On")
        assert len(findings) >= 1

    def test_detect_db_error_exposure(self, scanner):
        findings = scanner._detect_info_disclosure("db.php", "mysql_error()")
        assert len(findings) >= 1

    def test_finding_structure(self, scanner):
        findings = scanner._detect_info_disclosure("test.php", "phpinfo();")
        assert len(findings) >= 1
        f = findings[0]
        assert "finding_id" in f
        assert f["source_tool"] == "zap-baseline"
        assert f["category"] == "security"
        assert f["file_path"] == "test.php"
        assert f["line_number"] >= 1
        assert "owasp_category" in f


# ---------------------------------------------------------------------------
# Source analysis: missing security headers
# ---------------------------------------------------------------------------

class TestMissingHeaders:
    def test_detect_missing_headers_in_response_code(self, scanner):
        code = (
            "@app.route('/api/data')\n"
            "def get_data():\n"
            "    return Response('hello')\n"
        )
        findings = scanner._detect_missing_headers("views.py", code)
        # Should find multiple missing headers
        assert len(findings) >= 3  # CSP, HSTS, X-Frame-Options, etc.

    def test_no_findings_for_non_response_code(self, scanner):
        code = "def compute(x, y):\n    return x + y\n"
        findings = scanner._detect_missing_headers("utils.py", code)
        assert len(findings) == 0

    def test_no_finding_when_header_present(self, scanner):
        code = (
            "@app.route('/api/data')\n"
            "def get_data():\n"
            "    resp = Response('hello')\n"
            "    resp.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
            "    resp.headers['Strict-Transport-Security'] = 'max-age=31536000'\n"
            "    resp.headers['X-Frame-Options'] = 'DENY'\n"
            "    resp.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "    resp.headers['Referrer-Policy'] = 'strict-origin'\n"
            "    resp.headers['Permissions-Policy'] = 'camera=()'\n"
            "    return resp\n"
        )
        findings = scanner._detect_missing_headers("secure.py", code)
        assert len(findings) == 0

    def test_detect_missing_csp(self, scanner):
        code = (
            "@app.route('/page')\n"
            "def page():\n"
            "    resp = Response('page')\n"
            "    resp.headers['X-Frame-Options'] = 'DENY'\n"
            "    resp.headers['Strict-Transport-Security'] = 'max-age=31536000'\n"
            "    resp.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "    resp.headers['Referrer-Policy'] = 'strict-origin'\n"
            "    resp.headers['Permissions-Policy'] = 'camera=()'\n"
            "    return resp\n"
        )
        findings = scanner._detect_missing_headers("views.py", code)
        titles = [f["title"] for f in findings]
        assert any("Content-Security-Policy" in t for t in titles)

    def test_finding_structure_headers(self, scanner):
        code = "res.send('hello');\n"
        findings = scanner._detect_missing_headers("handler.js", code)
        for f in findings:
            assert f["source_tool"] == "zap-baseline"
            assert "owasp_category" in f
            assert f["owasp_category"] == "A05:2021-Security Misconfiguration"


# ---------------------------------------------------------------------------
# Source analysis: insecure cookies
# ---------------------------------------------------------------------------

class TestInsecureCookies:
    def test_detect_php_setcookie_missing_flags(self, scanner):
        code = "setcookie('session', $value);"
        findings = scanner._detect_insecure_cookies("login.php", code)
        assert len(findings) >= 1
        assert any("Cookie" in f["title"] for f in findings)

    def test_detect_session_httponly_disabled(self, scanner):
        code = "session.cookie_httponly = false"
        findings = scanner._detect_insecure_cookies("php.ini", code)
        assert len(findings) >= 1

    def test_detect_session_secure_disabled(self, scanner):
        code = "session.cookie_secure = off"
        findings = scanner._detect_insecure_cookies("php.ini", code)
        assert len(findings) >= 1

    def test_detect_express_cookie_missing_flags(self, scanner):
        code = "res.cookie('token', value);\n"
        findings = scanner._detect_insecure_cookies("server.js", code)
        assert len(findings) >= 1
        assert any("CWE-614" in f["cwe_id"] for f in findings)

    def test_detect_python_set_cookie(self, scanner):
        code = "response.set_cookie('session', value)\n"
        findings = scanner._detect_insecure_cookies("views.py", code)
        assert len(findings) >= 1

    def test_skip_cookie_in_comment(self, scanner):
        code = "// res.cookie('token', value);\n"
        findings = scanner._detect_insecure_cookies("safe.js", code)
        assert len(findings) == 0

    def test_no_finding_when_secure_flags_present(self, scanner):
        code = (
            "res.cookie('token', value, {\n"
            "    httpOnly: true,\n"
            "    secure: true,\n"
            "    sameSite: 'strict'\n"
            "});\n"
        )
        findings = scanner._detect_insecure_cookies("server.js", code)
        # The cookie pattern matches but context has all flags, so no issue
        assert len(findings) == 0

    def test_detect_java_cookie(self, scanner):
        code = 'new Cookie("session", value);\n'
        findings = scanner._detect_insecure_cookies("Auth.java", code)
        assert len(findings) >= 1

    def test_detect_go_cookie(self, scanner):
        code = "http.SetCookie(w, cookie)\n"
        findings = scanner._detect_insecure_cookies("handler.go", code)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Source analysis: server config issues
# ---------------------------------------------------------------------------

class TestServerConfigIssues:
    def test_detect_apache_directory_listing(self, scanner):
        code = "Options +Indexes\n"
        findings = scanner._detect_server_config_issues(".htaccess", code)
        assert len(findings) >= 1
        assert any("CWE-548" in f["cwe_id"] for f in findings)

    def test_detect_nginx_autoindex(self, scanner):
        code = "autoindex on;\n"
        findings = scanner._detect_server_config_issues("nginx.conf", code)
        assert len(findings) >= 1

    def test_detect_server_signature(self, scanner):
        code = "ServerSignature On\n"
        findings = scanner._detect_server_config_issues("httpd.conf", code)
        assert len(findings) >= 1

    def test_detect_nginx_server_tokens(self, scanner):
        code = "server_tokens on;\n"
        findings = scanner._detect_server_config_issues("nginx.conf", code)
        assert len(findings) >= 1

    def test_detect_cgi_handler(self, scanner):
        code = "AddHandler cgi-script .cgi\n"
        findings = scanner._detect_server_config_issues(".htaccess", code)
        assert len(findings) >= 1
        assert any("CWE-94" in f["cwe_id"] for f in findings)

    def test_detect_sensitive_directory_exposure(self, scanner):
        code = "location /.git {\n    allow all;\n}\n"
        findings = scanner._detect_server_config_issues("nginx.conf", code)
        assert len(findings) >= 1
        assert any("CWE-538" in f["cwe_id"] for f in findings)

    def test_detect_cors_wildcard(self, scanner):
        code = 'Access-Control-Allow-Origin *\n'
        findings = scanner._detect_server_config_issues("config.conf", code)
        assert len(findings) >= 1
        assert any("CWE-942" in f["cwe_id"] for f in findings)

    def test_skip_comments_in_config(self, scanner):
        code = "# Options +Indexes\n"
        findings = scanner._detect_server_config_issues(".htaccess", code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Source analysis: verbose errors
# ---------------------------------------------------------------------------

class TestVerboseErrors:
    def test_detect_python_exception_in_response(self, scanner):
        code = (
            "except Exception as e:\n"
            "    return str(e)\n"
        )
        findings = scanner._detect_verbose_errors("handler.py", code)
        assert len(findings) >= 1
        assert any("CWE-209" in f["cwe_id"] for f in findings)

    def test_detect_php_catch_echo(self, scanner):
        code = (
            "try {\n"
            "    doSomething();\n"
            "} catch (Exception $ex) {\n"
            "echo $ex->getMessage();\n"
            "}\n"
        )
        findings = scanner._detect_verbose_errors("handler.php", code)
        assert len(findings) >= 1

    def test_detect_php_catch_echo_variable(self, scanner):
        """PHP echo without parens: echo $error;-style via getMessage."""
        code = (
            "try {\n"
            "    riskyOperation();\n"
            "} catch (Exception $error) {\n"
            "    echo $error->getMessage();\n"
            "}\n"
        )
        findings = scanner._detect_verbose_errors("error.php", code)
        assert len(findings) >= 1
        assert any("CWE-209" in f["cwe_id"] for f in findings)

    def test_detect_php_catch_echo_with_parens(self, scanner):
        """PHP echo with parens: echo($error) is also valid."""
        code = (
            "try {\n"
            "    doWork();\n"
            "} catch (RuntimeException $error) {\n"
            "    echo($error->getMessage());\n"
            "}\n"
        )
        findings = scanner._detect_verbose_errors("runtime.php", code)
        assert len(findings) >= 1

    def test_detect_php_catch_echo_concat(self, scanner):
        """PHP echo with string concatenation: echo 'Error: ' . $e->getMessage();"""
        code = (
            "try {\n"
            "    query($sql);\n"
            '} catch (PDOException $e) {\n'
            '    echo "Error: " . $e->getMessage();\n'
            "}\n"
        )
        findings = scanner._detect_verbose_errors("db.php", code)
        assert len(findings) >= 1

    def test_detect_java_printStackTrace(self, scanner):
        code = (
            "catch (Exception e) {\n"
            "    e.printStackTrace();\n"
            "}\n"
        )
        findings = scanner._detect_verbose_errors("Handler.java", code)
        assert len(findings) >= 1

    def test_detect_express_error_in_response(self, scanner):
        code = (
            "catch (err) {\n"
            "    res.json(err.message);\n"
            "}\n"
        )
        findings = scanner._detect_verbose_errors("routes.js", code)
        assert len(findings) >= 1

    def test_finding_structure_verbose(self, scanner):
        code = "catch (Exception e) {\n    e.printStackTrace();\n}\n"
        findings = scanner._detect_verbose_errors("App.java", code)
        if findings:
            f = findings[0]
            assert "finding_id" in f
            assert f["source_tool"] == "zap-baseline"
            assert f["owasp_category"] == "A05:2021-Security Misconfiguration"


# ---------------------------------------------------------------------------
# Full source scan
# ---------------------------------------------------------------------------

class TestScanSource:
    def _scan_with_test_bypass(self, scanner, source_tree):
        """Run scan_source with _is_test_file patched to only match tests/ dir inside source tree."""
        original_is_test = ZAPBaselineScanner._is_test_file

        def patched_is_test(file_path):
            # Only consider files inside the explicit tests/ subdirectory as test files
            rel = os.path.relpath(file_path, str(source_tree))
            return rel.startswith("tests/") or rel.startswith("tests" + os.sep)

        with patch.object(ZAPBaselineScanner, "_is_test_file", staticmethod(patched_is_test)):
            return scanner.scan_source(str(source_tree))

    def test_scan_source_returns_findings(self, scanner, source_tree):
        findings = self._scan_with_test_bypass(scanner, source_tree)
        assert len(findings) > 0

    def test_scan_source_skips_test_files(self, scanner, source_tree):
        findings = self._scan_with_test_bypass(scanner, source_tree)
        # No finding should reference a file in tests/ directory
        for f in findings:
            assert "tests/" not in f.get("file_path", "")

    def test_scan_source_skips_node_modules(self, scanner, source_tree):
        findings = self._scan_with_test_bypass(scanner, source_tree)
        for f in findings:
            assert "node_modules" not in f.get("file_path", "")

    def test_scan_source_skips_empty_files(self, scanner, source_tree):
        findings = self._scan_with_test_bypass(scanner, source_tree)
        for f in findings:
            assert f.get("file_path") != "empty.py"

    def test_scan_source_not_a_directory(self, scanner, tmp_path):
        fake_file = tmp_path / "not_a_dir.txt"
        fake_file.write_text("hello")
        findings = scanner.scan_source(str(fake_file))
        assert findings == []

    def test_scan_source_empty_directory(self, scanner, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        findings = scanner.scan_source(str(empty_dir))
        assert findings == []

    def test_scan_source_detects_phpinfo(self, scanner, source_tree):
        findings = self._scan_with_test_bypass(scanner, source_tree)
        assert any("phpinfo" in f.get("title", "").lower() for f in findings)

    def test_scan_source_detects_server_config(self, scanner, source_tree):
        findings = self._scan_with_test_bypass(scanner, source_tree)
        # Should find nginx autoindex and/or server_tokens
        config_findings = [f for f in findings if "Server Configuration" in f.get("title", "")]
        assert len(config_findings) >= 1

    def test_scan_source_unreadable_file(self, scanner, tmp_path):
        """Files that can't be read are gracefully skipped."""
        py_file = tmp_path / "unreadable.py"
        py_file.write_text("phpinfo()")

        with patch("builtins.open", side_effect=PermissionError("denied")):
            # Should not raise
            findings = scanner.scan_source(str(tmp_path))
        # May or may not have findings depending on which open call is mocked
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Live scanning
# ---------------------------------------------------------------------------

class TestScanLive:
    def test_scan_live_no_zap_available(self, scanner):
        findings = scanner.scan_live("https://example.com")
        assert findings == []

    def test_scan_live_success(self, scanner_with_zap, tmp_path, zap_json_report):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "ZAP completed"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result), \
             patch("os.path.isfile", return_value=True), \
             patch.object(scanner_with_zap, "_parse_zap_report", return_value=[
                 {"finding_id": "ZAP-LIVE-1", "title": "Test Finding"}
             ]):
            findings = scanner_with_zap.scan_live("https://example.com")

        assert len(findings) >= 1

    def test_scan_live_zap_warning_exit(self, scanner_with_zap):
        """ZAP returns 1 or 2 for warnings, which is expected."""
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = "warnings found"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result), \
             patch("os.path.isfile", return_value=False):
            findings = scanner_with_zap.scan_live("https://example.com")
        # No report file found
        assert findings == []

    def test_scan_live_binary_not_found(self, scanner_with_zap):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = scanner_with_zap.scan_live("https://example.com")
        assert findings == []

    def test_scan_live_timeout(self, scanner_with_zap):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="zap", timeout=180)):
            findings = scanner_with_zap.scan_live("https://example.com", timeout=120)
        assert findings == []

    def test_scan_live_os_error(self, scanner_with_zap):
        with patch("subprocess.run", side_effect=OSError("Permission denied")):
            findings = scanner_with_zap.scan_live("https://example.com")
        assert findings == []

    def test_scan_live_xml_fallback(self, scanner_with_zap):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        def isfile_side_effect(path):
            return path.endswith(".xml")

        with patch("subprocess.run", return_value=mock_result), \
             patch("os.path.isfile", side_effect=isfile_side_effect), \
             patch.object(scanner_with_zap, "_parse_zap_report", return_value=[{"title": "XML finding"}]):
            findings = scanner_with_zap.scan_live("https://example.com")
        assert len(findings) >= 1

    def test_scan_live_docker_mode(self, scanner_docker):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result), \
             patch("os.path.isfile", return_value=False):
            findings = scanner_docker.scan_live("https://example.com")
        assert findings == []


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------

class TestBuildZapCommand:
    def test_build_native_command(self, scanner_with_zap):
        cmd = scanner_with_zap._build_zap_command(
            "https://example.com", "/tmp/report.json", 120, False
        )
        assert cmd[0] == "python3"
        assert scanner_with_zap.zap_path in cmd
        assert "-t" in cmd
        assert "https://example.com" in cmd
        assert "-J" in cmd
        assert "-I" in cmd

    def test_build_docker_command(self, scanner_docker):
        cmd = scanner_docker._build_zap_command(
            "https://example.com", "/tmp/scan/report.json", 120, False
        )
        assert cmd[0] == "docker"
        assert "run" in cmd
        assert "ghcr.io/zaproxy/zaproxy:stable" in cmd
        assert "zap-baseline.py" in cmd

    def test_build_command_with_ajax_spider(self, scanner_with_zap):
        cmd = scanner_with_zap._build_zap_command(
            "https://example.com", "/tmp/report.json", 120, True
        )
        assert "-j" in cmd

    def test_build_command_with_timeout(self, scanner_with_zap):
        cmd = scanner_with_zap._build_zap_command(
            "https://example.com", "/tmp/report.json", 300, False
        )
        assert "-m" in cmd
        idx = cmd.index("-m")
        assert cmd[idx + 1] == "5"  # 300 // 60


# ---------------------------------------------------------------------------
# Report parsing: JSON
# ---------------------------------------------------------------------------

class TestParseJsonReport:
    def test_parse_json_report(self, scanner, zap_json_report):
        findings = scanner._parse_json_report(zap_json_report)
        # 3 alerts but one is informational (riskcode=0), so 2 findings
        assert len(findings) == 2
        assert findings[0]["title"] == "Missing X-Frame-Options Header"
        assert findings[0]["severity"] == "medium"
        assert findings[0]["cwe_id"] == "CWE-1021"

    def test_parse_json_report_single_site_dict(self, scanner, tmp_path):
        """Handle case where site is a dict instead of list."""
        report = {
            "site": {
                "alerts": [
                    {
                        "alert": "Test Alert",
                        "riskcode": "2",
                        "cweid": "200",
                        "pluginid": "10001",
                        "desc": "Test",
                        "solution": "Fix it",
                        "instances": [{"uri": "https://example.com"}],
                    }
                ]
            }
        }
        path = tmp_path / "single_site.json"
        path.write_text(json.dumps(report))
        findings = scanner._parse_json_report(str(path))
        assert len(findings) == 1

    def test_parse_json_report_invalid_json(self, scanner, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json{{{")
        findings = scanner._parse_json_report(str(path))
        assert findings == []

    def test_parse_json_report_file_not_found(self, scanner):
        findings = scanner._parse_json_report("/nonexistent/path.json")
        assert findings == []

    def test_parse_json_report_permission_denied(self, scanner, tmp_path):
        path = tmp_path / "denied.json"
        path.write_text("{}")
        with patch("builtins.open", side_effect=PermissionError("denied")):
            findings = scanner._parse_json_report(str(path))
        assert findings == []

    def test_parse_json_report_empty_alerts(self, scanner, tmp_path):
        report = {"site": [{"alerts": []}]}
        path = tmp_path / "empty_alerts.json"
        path.write_text(json.dumps(report))
        findings = scanner._parse_json_report(str(path))
        assert findings == []

    def test_parse_json_report_no_instances(self, scanner, tmp_path):
        report = {
            "site": [{
                "alerts": [{
                    "alert": "No Instances",
                    "riskcode": "2",
                    "cweid": "",
                    "pluginid": "10001",
                    "desc": "Test",
                    "solution": "Fix",
                    "url": "https://fallback.com",
                }]
            }]
        }
        path = tmp_path / "no_instances.json"
        path.write_text(json.dumps(report))
        findings = scanner._parse_json_report(str(path))
        assert len(findings) == 1
        assert "https://fallback.com" in findings[0]["description"]


# ---------------------------------------------------------------------------
# Report parsing: XML
# ---------------------------------------------------------------------------

class TestParseXmlReport:
    def test_parse_xml_report(self, scanner, zap_xml_report):
        findings = scanner._parse_xml_report(zap_xml_report)
        # 2 alerts but one is informational (riskcode=0), so 1 finding
        assert len(findings) == 1
        assert findings[0]["title"] == "SQL Injection"
        assert findings[0]["severity"] == "high"
        assert findings[0]["cwe_id"] == "CWE-89"

    def test_parse_xml_report_invalid(self, scanner, tmp_path):
        path = tmp_path / "bad.xml"
        path.write_text("not valid xml<<<")
        findings = scanner._parse_xml_report(str(path))
        assert findings == []

    def test_parse_xml_report_file_not_found(self, scanner):
        findings = scanner._parse_xml_report("/nonexistent/report.xml")
        assert findings == []

    def test_parse_xml_report_permission_denied(self, scanner, tmp_path):
        path = tmp_path / "denied.xml"
        path.write_text("<root/>")
        with patch("xml.etree.ElementTree.parse", side_effect=PermissionError("denied")):
            findings = scanner._parse_xml_report(str(path))
        assert findings == []

    def test_parse_xml_no_et_module(self, scanner, zap_xml_report):
        """When xml.etree is unavailable, return empty."""
        original_et = __import__("scripts.zap_baseline_scanner")
        with patch.object(
            __import__("scripts.zap_baseline_scanner", fromlist=["ET"]),
            "ET",
            None,
        ):
            # Re-import trick won't work, but we can test the guard
            import scripts.zap_baseline_scanner as mod
            old_et = mod.ET
            mod.ET = None
            try:
                findings = scanner._parse_xml_report(zap_xml_report)
                assert findings == []
            finally:
                mod.ET = old_et


# ---------------------------------------------------------------------------
# Report dispatch
# ---------------------------------------------------------------------------

class TestParseZapReport:
    def test_dispatch_json(self, scanner, zap_json_report):
        findings = scanner._parse_zap_report(zap_json_report)
        assert len(findings) >= 1

    def test_dispatch_xml(self, scanner, zap_xml_report):
        findings = scanner._parse_zap_report(zap_xml_report)
        assert len(findings) >= 1

    def test_dispatch_unknown_extension(self, scanner, tmp_path):
        path = tmp_path / "report.txt"
        path.write_text(json.dumps({"site": [{"alerts": []}]}))
        with patch.object(scanner, "_parse_json_report", return_value=[]) as mock_json, \
             patch.object(scanner, "_parse_xml_report", return_value=[]) as mock_xml:
            findings = scanner._parse_zap_report(str(path))
        mock_json.assert_called_once()


# ---------------------------------------------------------------------------
# OWASP mapping
# ---------------------------------------------------------------------------

class TestOwaspMapping:
    def test_header_keywords(self):
        assert "A05" in ZAPBaselineScanner._map_zap_to_owasp("Missing CSP Header", "")
        assert "A05" in ZAPBaselineScanner._map_zap_to_owasp("HSTS Missing", "")

    def test_disclosure_keywords(self):
        assert "A01" in ZAPBaselineScanner._map_zap_to_owasp("Information Disclosure", "")

    def test_cookie_keywords(self):
        assert "A07" in ZAPBaselineScanner._map_zap_to_owasp("Cookie without flags", "")

    def test_injection_keywords(self):
        assert "A03" in ZAPBaselineScanner._map_zap_to_owasp("SQL Injection", "")
        assert "A03" in ZAPBaselineScanner._map_zap_to_owasp("Cross-Site XSS", "")

    def test_crypto_keywords(self):
        assert "A02" in ZAPBaselineScanner._map_zap_to_owasp("Weak TLS Config", "")

    def test_cwe_based_fallback(self):
        assert "A01" in ZAPBaselineScanner._map_zap_to_owasp("Unknown Alert", "200")
        assert "A02" in ZAPBaselineScanner._map_zap_to_owasp("Unknown Alert", "319")
        assert "A05" in ZAPBaselineScanner._map_zap_to_owasp("Unknown Alert", "614")

    def test_default_fallback(self):
        result = ZAPBaselineScanner._map_zap_to_owasp("Unknown Alert Name", "99999")
        assert "A05" in result


# ---------------------------------------------------------------------------
# XML helper
# ---------------------------------------------------------------------------

class TestXmlText:
    def test_xml_text_found(self):
        elem = ET.fromstring("<parent><child>text value</child></parent>")
        assert ZAPBaselineScanner._xml_text(elem, "child") == "text value"

    def test_xml_text_not_found(self):
        elem = ET.fromstring("<parent><child>text</child></parent>")
        assert ZAPBaselineScanner._xml_text(elem, "missing", "default") == "default"

    def test_xml_text_empty(self):
        elem = ET.fromstring("<parent><child></child></parent>")
        assert ZAPBaselineScanner._xml_text(elem, "child", "default") == "default"

    def test_xml_text_whitespace(self):
        elem = ET.fromstring("<parent><child>  spaced  </child></parent>")
        assert ZAPBaselineScanner._xml_text(elem, "child") == "spaced"


# ---------------------------------------------------------------------------
# Constants / module-level values
# ---------------------------------------------------------------------------

class TestConstants:
    def test_scannable_extensions(self):
        assert ".py" in SCANNABLE_EXTENSIONS
        assert ".php" in SCANNABLE_EXTENSIONS
        assert ".js" in SCANNABLE_EXTENSIONS
        assert ".go" in SCANNABLE_EXTENSIONS

    def test_risk_to_severity_mapping(self):
        assert ZAP_RISK_TO_SEVERITY["0"] == "info"
        assert ZAP_RISK_TO_SEVERITY["3"] == "high"
        assert ZAP_RISK_TO_SEVERITY["Informational"] == "info"
        assert ZAP_RISK_TO_SEVERITY["High"] == "high"

    def test_zap_search_paths_are_strings(self):
        for path in ZAP_SEARCH_PATHS:
            assert isinstance(path, str)
            assert path.endswith("zap-baseline.py")
