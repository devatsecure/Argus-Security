"""Tests for the Nuclei Template Scanner module.

Covers NucleiTemplateScanner: initialization, live scanning, source-aware
scanning (CSRF, open redirect, rate-limit gaps, security header gaps, weak
sessions), Nuclei JSONL parsing, and edge cases.

All external dependencies (subprocess, filesystem) are mocked.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.nuclei_template_scanner import NucleiTemplateScanner, _make_finding_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    """Default scanner with nuclei availability unchecked."""
    s = NucleiTemplateScanner()
    return s


@pytest.fixture
def scanner_with_templates(tmp_path):
    """Scanner configured with a custom templates directory."""
    return NucleiTemplateScanner(
        nuclei_path="/usr/local/bin/nuclei",
        templates_dir=str(tmp_path / "templates"),
    )


# ---------------------------------------------------------------------------
# Helper: write a temp source file
# ---------------------------------------------------------------------------

def _write_source(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

class TestInit:
    def test_default_init(self, scanner):
        assert scanner.nuclei_path == "nuclei"
        assert scanner.templates_dir is None
        assert scanner._nuclei_available is None

    def test_custom_init(self, scanner_with_templates):
        assert scanner_with_templates.nuclei_path == "/usr/local/bin/nuclei"
        assert "templates" in scanner_with_templates.templates_dir


# ---------------------------------------------------------------------------
# 2. _is_nuclei_installed
# ---------------------------------------------------------------------------

class TestNucleiInstalled:
    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_nuclei_available(self, mock_run, scanner):
        mock_run.return_value = MagicMock(returncode=0)
        assert scanner._is_nuclei_installed() is True
        # Cached on second call
        assert scanner._is_nuclei_installed() is True
        mock_run.assert_called_once()

    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_nuclei_not_found(self, mock_run, scanner):
        mock_run.side_effect = FileNotFoundError("no such binary")
        assert scanner._is_nuclei_installed() is False

    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_nuclei_unexpected_error(self, mock_run, scanner):
        mock_run.side_effect = OSError("permission denied")
        assert scanner._is_nuclei_installed() is False


# ---------------------------------------------------------------------------
# 3. _build_live_command
# ---------------------------------------------------------------------------

class TestBuildLiveCommand:
    def test_basic_command(self, scanner):
        cmd = scanner._build_live_command("https://example.com", "high,critical", None)
        assert cmd[:4] == ["nuclei", "-u", "https://example.com", "-jsonl"]
        assert "-severity" in cmd
        assert "high,critical" in cmd

    def test_with_tags(self, scanner):
        cmd = scanner._build_live_command("https://example.com", "", ["cve", "oast"])
        assert "-tags" in cmd
        assert "cve,oast" in cmd

    def test_with_templates_dir(self, scanner_with_templates):
        cmd = scanner_with_templates._build_live_command("https://x.com", "medium", None)
        assert "-t" in cmd
        assert scanner_with_templates.templates_dir in cmd


# ---------------------------------------------------------------------------
# 4. scan_live – happy path and error paths
# ---------------------------------------------------------------------------

class TestScanLive:
    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_scan_live_success(self, mock_run, scanner):
        scanner._nuclei_available = True
        nuclei_line = json.dumps({
            "template-id": "cve-2021-44228",
            "matched-at": "https://target.com/path",
            "info": {
                "name": "Log4Shell RCE",
                "severity": "critical",
                "description": "Remote code execution via Log4j",
                "tags": ["cve", "rce"],
                "classification": {"cwe-id": ["CWE-502"]},
            },
        })
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=nuclei_line + "\n",
            stderr="",
        )
        findings = scanner.scan_live("https://target.com")
        assert len(findings) == 1
        assert findings[0]["source_tool"] == "nuclei-live"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["cwe_id"] == "CWE-502"

    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_scan_live_nuclei_not_installed(self, mock_run, scanner):
        scanner._nuclei_available = False
        with pytest.raises(RuntimeError, match="Nuclei binary not found"):
            scanner.scan_live("https://target.com")

    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_scan_live_timeout(self, mock_run, scanner):
        scanner._nuclei_available = True
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=300)
        with pytest.raises(RuntimeError, match="timed out"):
            scanner.scan_live("https://target.com", timeout=300)

    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_scan_live_bad_returncode(self, mock_run, scanner):
        scanner._nuclei_available = True
        mock_run.return_value = MagicMock(returncode=2, stderr="fatal error")
        with pytest.raises(RuntimeError, match="exited with code 2"):
            scanner.scan_live("https://target.com")

    @patch("scripts.nuclei_template_scanner.subprocess.run")
    def test_scan_live_file_not_found(self, mock_run, scanner):
        scanner._nuclei_available = True
        mock_run.side_effect = FileNotFoundError("nuclei not on PATH")
        with pytest.raises(RuntimeError, match="not found"):
            scanner.scan_live("https://target.com")


# ---------------------------------------------------------------------------
# 5. _parse_nuclei_output
# ---------------------------------------------------------------------------

class TestParseNucleiOutput:
    def test_valid_jsonl(self, scanner):
        line = json.dumps({
            "template-id": "tpl-1",
            "matched-at": "https://x.com/login",
            "info": {
                "name": "Test Finding",
                "severity": "High",
                "description": "A test",
                "tags": ["tag1"],
                "classification": {},
            },
        })
        findings = scanner._parse_nuclei_output([line])
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["title"] == "Test Finding"

    def test_malformed_json_skipped(self, scanner):
        findings = scanner._parse_nuclei_output(["not valid json{{{"])
        assert findings == []

    def test_empty_lines_skipped(self, scanner):
        findings = scanner._parse_nuclei_output(["", "  ", "\n"])
        assert findings == []

    def test_cwe_as_string(self, scanner):
        line = json.dumps({
            "template-id": "tpl-2",
            "matched-at": "https://x.com",
            "info": {
                "severity": "medium",
                "classification": {"cwe-id": "CWE-79"},
            },
        })
        findings = scanner._parse_nuclei_output([line])
        assert findings[0]["cwe_id"] == "CWE-79"


# ---------------------------------------------------------------------------
# 6. scan_source – CSRF detection
# ---------------------------------------------------------------------------

class TestDetectCSRF:
    def test_form_without_csrf_token(self, scanner, tmp_path):
        src = _write_source(tmp_path, "form.php", '<form action="/delete" method="POST">\n<input type="submit">\n</form>')
        findings = scanner.scan_source(str(src))
        csrf_findings = [f for f in findings if "CSRF" in f["title"]]
        assert len(csrf_findings) >= 1
        assert csrf_findings[0]["cwe_id"] == "CWE-352"

    def test_form_with_csrf_token_no_finding(self, scanner, tmp_path):
        src = _write_source(
            tmp_path,
            "form_safe.php",
            '<form action="/delete" method="POST">\n<input type="hidden" name="csrf_token" value="abc">\n</form>',
        )
        findings = scanner.scan_source(str(src))
        csrf_form_findings = [f for f in findings if "Form without CSRF" in f["title"]]
        assert len(csrf_form_findings) == 0

    def test_state_change_via_get(self, scanner, tmp_path):
        src = _write_source(tmp_path, "routes.js", "app.get('/delete-user', handler);")
        findings = scanner.scan_source(str(src))
        get_findings = [f for f in findings if "State-changing" in f["title"]]
        assert len(get_findings) >= 1


# ---------------------------------------------------------------------------
# 7. scan_source – Open Redirect detection
# ---------------------------------------------------------------------------

class TestDetectOpenRedirects:
    def test_express_redirect(self, scanner, tmp_path):
        code = "res.redirect(req.query.next);"
        src = _write_source(tmp_path, "redirect.js", code)
        findings = scanner.scan_source(str(src))
        redirect_findings = [f for f in findings if "Open Redirect" in f["title"]]
        assert len(redirect_findings) >= 1
        assert redirect_findings[0]["severity"] == "high"

    def test_redirect_with_whitelist_lowers_severity(self, scanner, tmp_path):
        code = "const allowed_hosts = ['example.com'];\nres.redirect(req.query.next);"
        src = _write_source(tmp_path, "safe_redirect.js", code)
        findings = scanner.scan_source(str(src))
        redirect_findings = [f for f in findings if "Open Redirect" in f["title"]]
        assert len(redirect_findings) >= 1
        assert redirect_findings[0]["severity"] == "low"


# ---------------------------------------------------------------------------
# 8. scan_source – Rate limit gap detection
# ---------------------------------------------------------------------------

class TestDetectRateLimitGaps:
    def test_auth_endpoint_without_rate_limit(self, scanner, tmp_path):
        code = "def login(request):\n    pass"
        src = _write_source(tmp_path, "auth.py", code)
        findings = scanner.scan_source(str(src))
        brute_findings = [f for f in findings if "Brute Force" in f["title"]]
        assert len(brute_findings) >= 1
        assert brute_findings[0]["cwe_id"] == "CWE-307"

    def test_auth_endpoint_with_rate_limit_no_finding(self, scanner, tmp_path):
        code = "@rate_limit\ndef login(request):\n    pass"
        src = _write_source(tmp_path, "auth_safe.py", code)
        findings = scanner.scan_source(str(src))
        brute_findings = [f for f in findings if "Brute Force" in f["title"]]
        assert len(brute_findings) == 0


# ---------------------------------------------------------------------------
# 9. scan_source – Security header gap detection
# ---------------------------------------------------------------------------

class TestDetectSecurityHeaderGaps:
    def test_missing_headers_in_flask_app(self, scanner, tmp_path):
        code = "@app.route('/api')\ndef index():\n    return 'hello'"
        src = _write_source(tmp_path, "app.py", code)
        findings = scanner.scan_source(str(src))
        header_findings = [f for f in findings if "Missing Security Headers" in f["title"]]
        assert len(header_findings) >= 1
        assert header_findings[0]["cwe_id"] == "CWE-693"

    def test_no_finding_when_not_http_handler(self, scanner, tmp_path):
        code = "def compute(x):\n    return x * 2"
        src = _write_source(tmp_path, "util.py", code)
        findings = scanner.scan_source(str(src))
        header_findings = [f for f in findings if "Missing Security Headers" in f["title"]]
        assert len(header_findings) == 0


# ---------------------------------------------------------------------------
# 10. scan_source – Weak session detection
# ---------------------------------------------------------------------------

class TestDetectWeakSessions:
    def test_weak_cookie_flags(self, scanner, tmp_path):
        code = "resp.set_cookie('session', value='abc', httponly=False)"
        src = _write_source(tmp_path, "session.py", code)
        findings = scanner.scan_source(str(src))
        session_findings = [f for f in findings if "Weak Session" in f["title"]]
        assert len(session_findings) >= 1
        assert session_findings[0]["cwe_id"] == "CWE-384"


# ---------------------------------------------------------------------------
# 11. scan_source – edge cases
# ---------------------------------------------------------------------------

class TestScanSourceEdgeCases:
    def test_nonexistent_path_returns_empty(self, scanner):
        findings = scanner.scan_source("/nonexistent/path/12345")
        assert findings == []

    def test_unsupported_extension_skipped(self, scanner, tmp_path):
        # .txt is not in _SOURCE_EXTENSIONS
        _write_source(tmp_path, "readme.txt", "<form action='/delete'>")
        findings = scanner.scan_source(str(tmp_path))
        assert findings == []

    def test_directory_scan(self, scanner, tmp_path):
        _write_source(tmp_path, "a.py", "def login(request):\n    pass")
        _write_source(tmp_path, "b.js", "res.redirect(req.query.next);")
        findings = scanner.scan_source(str(tmp_path))
        assert len(findings) >= 2

    @patch("pathlib.Path.read_text", side_effect=PermissionError("no read"))
    def test_permission_denied_skipped(self, mock_read, scanner, tmp_path):
        _write_source(tmp_path, "secret.py", "stuff")
        # scan_source should not raise — it logs and continues
        findings = scanner.scan_source(str(tmp_path))
        assert findings == []


# ---------------------------------------------------------------------------
# 12. _make_finding_id determinism
# ---------------------------------------------------------------------------

class TestMakeFindingId:
    def test_deterministic(self):
        id1 = _make_finding_id("csrf", "file.py", 10)
        id2 = _make_finding_id("csrf", "file.py", 10)
        assert id1 == id2

    def test_different_inputs_different_ids(self):
        id1 = _make_finding_id("csrf", "file.py", 10)
        id2 = _make_finding_id("csrf", "file.py", 11)
        assert id1 != id2
