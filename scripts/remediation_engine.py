#!/usr/bin/env python3
"""
Automated Remediation Engine for Argus
AI-powered fix generation for security vulnerabilities

This module generates fix suggestions for security findings using AI (Claude/GPT/Ollama)
with template-based fallback. It provides code patches, explanations, and testing
recommendations for common vulnerability types.

Features:
- AI-powered fix generation using LLMManager
- Template-based fallback for common vulnerabilities
- Unified diff generation for easy patching
- CWE references and compliance mapping
- Multi-language support (Python, JavaScript, Java, Go, etc.)
- Batch processing of findings
- Markdown and JSON export formats
- Confidence scoring for fix suggestions

Supported Vulnerability Types:
- SQL Injection → Parameterized queries
- XSS → Output escaping, CSP
- Command Injection → Avoid shell=True, sanitize input
- Path Traversal → Path validation, os.path.join
- SSRF → URL whitelisting, input validation
- Secrets in Code → Environment variables
- Insecure Crypto → Modern algorithms
- XXE → Disable external entities
- Insecure Deserialization → Safe serialization
- CSRF → Token validation

Usage:
    # From code
    from remediation_engine import RemediationEngine
    engine = RemediationEngine()
    suggestions = engine.generate_batch_fixes(findings)
    engine.export_as_markdown(suggestions, "report.md")

    # From CLI
    python remediation_engine.py --findings findings.json --output report.md
"""

import argparse
import datetime
import difflib
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class RemediationSuggestion:
    """A suggested fix for a security vulnerability

    Attributes:
        finding_id: Unique identifier for the finding
        vulnerability_type: Type of vulnerability (e.g., "sql-injection")
        file_path: Path to the vulnerable file
        line_number: Line number of the vulnerability
        original_code: Original vulnerable code snippet
        fixed_code: Suggested fixed code
        diff: Unified diff between original and fixed code
        explanation: Human-readable explanation of the fix
        testing_recommendations: List of testing approaches
        confidence: Confidence level ("high", "medium", "low")
        cwe_references: List of relevant CWE identifiers
        metadata: Additional metadata about the fix
    """

    finding_id: str
    vulnerability_type: str
    file_path: str
    line_number: int
    original_code: str
    fixed_code: str
    diff: str
    explanation: str
    testing_recommendations: List[str]
    confidence: str  # "high", "medium", "low"
    cwe_references: List[str]
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        """Initialize metadata if not provided"""
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "RemediationSuggestion":
        """Create RemediationSuggestion from dictionary"""
        return cls(**data)


class RemediationEngine:
    """Generate fix suggestions using AI and templates

    The engine attempts AI-powered fix generation first using LLMManager,
    then falls back to template-based fixes if AI is unavailable or fails.
    """

    # Fix templates for common vulnerabilities
    FIX_TEMPLATES = {
        "sql_injection": {
            "pattern": r"execute\([\"'].*[\%\+].*[\"']\)",
            "template": "Use parameterized queries instead of string formatting",
            "example": {
                "python": {
                    "before": 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
                    "after": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
                },
                "javascript": {
                    "before": 'db.query(`SELECT * FROM users WHERE id=${userId}`)',
                    "after": "db.query('SELECT * FROM users WHERE id=?', [userId])",
                },
            },
            "testing": [
                "Test with SQL injection payloads (e.g., ' OR 1=1 --)",
                "Verify parameterized queries are used",
                "Test with normal input to ensure functionality",
                "Run SQLMap or similar tool to verify fix",
            ],
        },
        "xss": {
            "pattern": r"innerHTML|dangerouslySetInnerHTML|document\.write",
            "template": "Escape user input before rendering to prevent XSS",
            "context_aware": True,  # Enable context-aware remediation
            "example": {
                "javascript": {
                    "before": "element.innerHTML = userInput",
                    "after": "element.textContent = userInput  // Auto-escapes HTML",
                },
                "python": {
                    "before": "return f'<div>{user_data}</div>'",
                    "after": "from html import escape\nreturn f'<div>{escape(user_data)}</div>'",
                },
            },
            "cli_context": {
                "explanation": "False positive - terminal output in CLI tool. No browser rendering. Mark as suppressed.",
                "confidence": "high",
                "fixed_code": "# No fix needed - CLI output is safe from XSS\n{original_code}",
            },
            "web_context": {
                "explanation": "Escape user input before rendering to prevent XSS. Use textContent or template engine auto-escaping.",
                "confidence": "high",
            },
            "testing": [
                "Test with XSS payloads (e.g., <script>alert(1)</script>)",
                "Verify output is properly escaped",
                "Test with normal HTML-like input",
                "Use XSS scanner to verify fix",
            ],
        },
        "command_injection": {
            "pattern": r"subprocess.*shell=True|os\.system|exec",
            "template": "Never use shell=True with user input; use array form",
            "example": {
                "python": {
                    "before": "subprocess.run(f'ls {user_dir}', shell=True)",
                    "after": "subprocess.run(['ls', user_dir], shell=False, check=True)",
                },
            },
            "testing": [
                "Test with command injection payloads (e.g., ; rm -rf /)",
                "Verify shell=False is used",
                "Test with normal input containing spaces/special chars",
                "Run static analysis to verify no shell execution",
            ],
        },
        "path_traversal": {
            "pattern": r"open\(.*\+|os\.path\.join.*\+",
            "template": "Validate file paths to prevent directory traversal",
            "example": {
                "python": {
                    "before": "open(base_dir + '/' + filename)",
                    "after": """import os
filename = os.path.basename(filename)  # Strip path components
safe_path = os.path.join(base_dir, filename)
# Ensure resolved path is still within base_dir
if not os.path.realpath(safe_path).startswith(os.path.realpath(base_dir)):
    raise ValueError('Invalid path')
open(safe_path)""",
                },
            },
            "testing": [
                "Test with path traversal payloads (e.g., ../../etc/passwd)",
                "Verify paths are validated and normalized",
                "Test with normal filenames",
                "Test with absolute paths (should be rejected)",
            ],
        },
        "ssrf": {
            "pattern": r"requests\.(get|post)|urllib\.request",
            "template": "Whitelist allowed URLs/domains to prevent SSRF",
            "example": {
                "python": {
                    "before": "requests.get(user_url)",
                    "after": """from urllib.parse import urlparse

# Whitelist allowed domains
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_DOMAINS:
    raise ValueError('Domain not allowed')

# Block internal/private IPs
import ipaddress
try:
    ip = ipaddress.ip_address(parsed.hostname)
    if ip.is_private or ip.is_loopback:
        raise ValueError('Private IPs not allowed')
except ValueError:
    pass  # Not an IP, continue with domain check

requests.get(user_url, timeout=5)""",
                },
            },
            "testing": [
                "Test with internal URLs (e.g., http://localhost, http://169.254.169.254)",
                "Test with whitelisted domains (should succeed)",
                "Test with non-whitelisted domains (should fail)",
                "Test with URL redirects to internal IPs",
            ],
        },
        "hard_coded_secrets": {
            "pattern": r"(password|secret|api[_-]?key|token)\s*=\s*[\"'][^\"']{8,}[\"']",
            "template": "Move secrets to environment variables",
            "example": {
                "python": {
                    "before": 'API_KEY = "sk_live_abc123def456"',
                    "after": """import os
API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    raise ValueError('API_KEY environment variable not set')""",
                },
                "javascript": {
                    "before": "const apiKey = 'sk_live_abc123def456';",
                    "after": """const apiKey = process.env.API_KEY;
if (!apiKey) {
    throw new Error('API_KEY environment variable not set');
}""",
                },
            },
            "testing": [
                "Verify secret is removed from code",
                "Test with environment variable set",
                "Test with environment variable missing (should error)",
                "Scan repository for any remaining secrets",
            ],
        },
        "insecure_crypto": {
            "pattern": r"md5|sha1|DES|RC4",
            "template": "Use modern cryptographic algorithms",
            "example": {
                "python": {
                    "before": "hashlib.md5(password.encode()).hexdigest()",
                    "after": """import hashlib
import secrets

# Use PBKDF2 or Argon2 for password hashing
salt = secrets.token_bytes(16)
key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
# Or use: from argon2 import PasswordHasher; PasswordHasher().hash(password)""",
                },
            },
            "testing": [
                "Verify modern algorithms are used (SHA-256+, AES-256, etc.)",
                "Test password hashing with salt",
                "Test key derivation function parameters",
                "Run security audit to verify no weak crypto",
            ],
        },
        "xxe": {
            "pattern": r"xml\.etree|lxml|xmltodict",
            "template": "Disable external entity processing to prevent XXE",
            "example": {
                "python": {
                    "before": "import xml.etree.ElementTree as ET\ntree = ET.parse(xml_file)",
                    "after": """import defusedxml.ElementTree as ET
# defusedxml disables dangerous features by default
tree = ET.parse(xml_file)""",
                },
            },
            "testing": [
                "Test with XXE payloads (e.g., <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>)",
                "Verify external entities are disabled",
                "Test with normal XML input",
                "Use XXE scanner to verify fix",
            ],
        },
        "insecure_deserialization": {
            "pattern": r"pickle\.loads|yaml\.load\(|marshal\.loads",
            "template": "Use safe serialization or validate input",
            "example": {
                "python": {
                    "before": "data = pickle.loads(user_input)",
                    "after": """import json
# Use JSON instead of pickle for untrusted data
data = json.loads(user_input)

# If pickle is required, use restricted unpickler
# import pickle
# class RestrictedUnpickler(pickle.Unpickler):
#     def find_class(self, module, name):
#         # Only allow safe classes
#         if module == 'builtins' and name in ['list', 'dict', 'str', 'int']:
#             return getattr(builtins, name)
#         raise pickle.UnpicklingError(f'Forbidden class: {module}.{name}')
# data = RestrictedUnpickler(io.BytesIO(user_input)).load()""",
                },
            },
            "testing": [
                "Test with malicious serialized payloads",
                "Verify only safe serialization is used",
                "Test with normal data",
                "Run code execution tests to verify fix",
            ],
        },
        "csrf": {
            "pattern": r"@app\.route.*methods=\[.*POST",
            "template": "Implement CSRF token validation for state-changing operations",
            "example": {
                "python": {
                    "before": "@app.route('/transfer', methods=['POST'])\ndef transfer():\n    amount = request.form['amount']",
                    "after": """from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
@csrf.protect  # Validates CSRF token
def transfer():
    amount = request.form['amount']
    # ... rest of logic""",
                },
            },
            "testing": [
                "Test POST request without CSRF token (should fail)",
                "Test POST request with valid CSRF token (should succeed)",
                "Test POST request with invalid CSRF token (should fail)",
                "Test GET requests (should not require CSRF token)",
            ],
        },
    }

    # CWE mapping for vulnerability types
    CWE_MAP = {
        "sql_injection": ["CWE-89"],
        "xss": ["CWE-79"],
        "command_injection": ["CWE-78"],
        "path_traversal": ["CWE-22"],
        "ssrf": ["CWE-918"],
        "xxe": ["CWE-611"],
        "insecure_crypto": ["CWE-327", "CWE-328"],
        "hard_coded_secrets": ["CWE-798"],
        "insecure_deserialization": ["CWE-502"],
        "csrf": ["CWE-352"],
        "open_redirect": ["CWE-601"],
        "ldap_injection": ["CWE-90"],
        "xml_injection": ["CWE-91"],
        "code_injection": ["CWE-94"],
        "file_upload": ["CWE-434"],
        "buffer_overflow": ["CWE-120", "CWE-787"],
    }

    # CLI tool safe patterns for XSS context detection
    CLI_SAFE_PATTERNS = [
        r"console\.(log|info|warn|error|debug)",
        r"print\(",
        r"logger\.",
        r"logging\.",
        r"sys\.stdout\.write",
        r"sys\.stderr\.write",
        r"process\.stdout\.write",
        r"process\.stderr\.write",
        r"fmt\.Print",
        r"System\.out\.print",
        r"System\.err\.print",
    ]

    def __init__(self, llm_manager=None, config: Dict = None):
        """Initialize RemediationEngine

        Args:
            llm_manager: Optional LLMManager instance for AI-powered fixes
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.llm = llm_manager

        # Try to initialize LLMManager if not provided
        if self.llm is None:
            try:
                # Add scripts dir to path
                scripts_dir = Path(__file__).parent
                if str(scripts_dir) not in sys.path:
                    sys.path.insert(0, str(scripts_dir))

                from orchestrator.llm_manager import LLMManager

                # Try to initialize with config from environment
                llm_config = {
                    "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY"),
                    "openai_api_key": os.environ.get("OPENAI_API_KEY"),
                    "ollama_endpoint": os.environ.get("OLLAMA_ENDPOINT"),
                    "ai_provider": os.environ.get("AI_PROVIDER", "auto"),
                }

                self.llm = LLMManager(llm_config)
                if not self.llm.initialize():
                    logger.warning("LLM initialization failed, will use template-based fixes only")
                    self.llm = None
                else:
                    logger.info(f"Initialized LLM: {self.llm.provider} / {self.llm.model}")
            except Exception as e:
                logger.warning(f"LLMManager not available: {e}")
                logger.info("Will use template-based fixes only")
                self.llm = None

    def _get_finding_attr(self, finding, *attrs, default=None):
        """Get attribute from finding, supporting both dict and dataclass objects.
        
        Args:
            finding: Finding dict or dataclass object
            *attrs: Attribute names to try in order
            default: Default value if none found
            
        Returns:
            First found attribute value or default
        """
        for attr in attrs:
            if isinstance(finding, dict):
                if attr in finding:
                    return finding[attr]
            else:
                # Dataclass/object - use getattr
                if hasattr(finding, attr):
                    val = getattr(finding, attr, None)
                    if val is not None:
                        return val
        return default

    def suggest_fix(self, finding) -> RemediationSuggestion:
        """Generate fix suggestion for a finding

        Args:
            finding: Finding dictionary or HybridFinding dataclass

        Returns:
            RemediationSuggestion with fix details
        """
        # Extract finding details (support both Finding dataclass and dict)
        finding_id = self._get_finding_attr(finding, "id", "finding_id", default="unknown")
        vuln_type = self._get_finding_attr(finding, "type", "rule_id", "title", default="unknown")
        file_path = self._get_finding_attr(finding, "path", "file_path", default="")
        line_number = self._get_finding_attr(finding, "line", "line_number", default=0)
        description = self._get_finding_attr(finding, "description", "message", default="")
        code_snippet = self._get_finding_attr(finding, "code_snippet", default="")
        
        # Handle nested evidence dict
        if not code_snippet and isinstance(finding, dict):
            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict):
                code_snippet = evidence.get("snippet", "")

        logger.info(f"Generating fix for {vuln_type} in {file_path}:{line_number}")

        # Try AI-powered fix generation first
        if self.llm:
            try:
                return self._ai_generate_fix(finding)
            except Exception as e:
                logger.warning(f"AI fix generation failed: {e}, falling back to templates")

        # Fallback to template-based fixes
        return self._template_generate_fix(finding)

    def _ai_generate_fix(self, finding) -> RemediationSuggestion:
        """Use AI to generate fix suggestion

        Args:
            finding: Finding dictionary or HybridFinding dataclass

        Returns:
            RemediationSuggestion with AI-generated fix
        """
        vuln_type = self._get_finding_attr(finding, "type", "rule_id", "title", default="")
        file_path = self._get_finding_attr(finding, "path", "file_path", default="")
        line_number = self._get_finding_attr(finding, "line", "line_number", default=0)
        description = self._get_finding_attr(finding, "description", "message", default="")
        code_snippet = self._get_finding_attr(finding, "code_snippet", default="")
        severity = self._get_finding_attr(finding, "severity", default="medium")
        language = self._detect_language(file_path)
        
        # Handle nested evidence dict for code_snippet
        if not code_snippet and isinstance(finding, dict):
            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict):
                code_snippet = evidence.get("snippet", "")

        # Build comprehensive prompt
        prompt = f"""You are a security engineer fixing a vulnerability in production code.

**Vulnerability Details:**
- Type: {vuln_type}
- Severity: {severity}
- File: {file_path}
- Line: {line_number}
- Description: {description}

**Vulnerable Code:**
```{language}
{code_snippet}
```

**Task:** Provide a secure fix for this vulnerability following security best practices.

**Requirements:**
1. The fix must completely eliminate the vulnerability
2. Preserve the original functionality
3. Use secure libraries and patterns specific to {language}
4. Include error handling where appropriate
5. Add security-relevant comments

**Response Format (JSON only):**
{{
  "fixed_code": "The corrected code with proper indentation",
  "explanation": "Clear 2-3 sentence explanation of what the fix does and why it's secure",
  "testing_recommendations": [
    "Specific test case 1 to verify the fix",
    "Specific test case 2 to verify security",
    "Specific test case 3 for edge cases"
  ],
  "confidence": "high|medium|low"
}}

Generate ONLY the JSON response, no markdown code blocks or additional text.
"""

        # Call LLM API
        response_text, _input_tokens, _output_tokens = self.llm.call_llm_api(prompt, max_tokens=1500)

        # Parse JSON response (handle markdown code blocks)
        response_text = re.sub(r"^```json\s*\n?", "", response_text.strip())
        response_text = re.sub(r"\n?```\s*$", "", response_text.strip())

        try:
            data = json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Response was: {response_text[:200]}")
            raise

        # Generate unified diff
        original_lines = code_snippet.split("\n")
        fixed_lines = data["fixed_code"].split("\n")
        diff = "\n".join(
            difflib.unified_diff(
                original_lines,
                fixed_lines,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="",
            )
        )

        return RemediationSuggestion(
            finding_id=finding.get("id", "unknown"),
            vulnerability_type=vuln_type,
            file_path=file_path,
            line_number=line_number,
            original_code=code_snippet,
            fixed_code=data["fixed_code"],
            diff=diff,
            explanation=data["explanation"],
            testing_recommendations=data.get("testing_recommendations", []),
            confidence=data.get("confidence", "medium"),
            cwe_references=self._get_cwe_references(vuln_type),
            metadata={"generator": "ai", "model": self.llm.model, "provider": self.llm.provider},
        )

    def _template_generate_fix(self, finding: Dict) -> RemediationSuggestion:
        """Generate fix using predefined templates

        Args:
            finding: Finding dictionary

        Returns:
            RemediationSuggestion with template-based fix
        """
        vuln_type = finding.get("type") or finding.get("rule_id", "")
        file_path = finding.get("path", "")
        line_number = finding.get("line", 0)
        code_snippet = finding.get("code_snippet") or finding.get("evidence", {}).get("snippet", "")
        language = self._detect_language(file_path)

        # Normalize vulnerability type (convert hyphens to underscores, lowercase)
        normalized_type = vuln_type.lower().replace("-", "_")

        # Get template
        template = self.FIX_TEMPLATES.get(normalized_type)

        if not template:
            # Generic fallback template
            fixed_code = f"# TODO: Fix {vuln_type} vulnerability\n# Review and apply security best practices\n{code_snippet}"
            explanation = (
                f"Manual review required for {vuln_type}. "
                "Consult security documentation and apply appropriate fixes."
            )
            testing = ["Manual security testing required", "Consult OWASP guidelines"]
            confidence = "low"
        else:
            # Check for context-aware remediation (e.g., XSS in CLI vs web)
            if template.get("context_aware") and normalized_type == "xss":
                output_dest = self._detect_output_destination(code_snippet, file_path)

                if output_dest == "terminal":
                    # CLI context - likely false positive
                    cli_context = template.get("cli_context", {})
                    fixed_code = cli_context.get("fixed_code", "{original_code}").format(original_code=code_snippet)
                    explanation = cli_context.get("explanation", template["template"])
                    confidence = cli_context.get("confidence", "high")
                    testing = [
                        "Verify output destination is terminal/console only",
                        "Confirm no browser rendering occurs",
                        "Mark as false positive if CLI tool context confirmed",
                    ]
                elif output_dest in ["browser", "http-response"]:
                    # Web context - real XSS vulnerability
                    web_context = template.get("web_context", {})
                    # Use language-specific example
                    examples = template["example"]
                    if language in examples:
                        fixed_code = examples[language]["after"]
                    elif "python" in examples:
                        fixed_code = examples["python"]["after"]
                    else:
                        first_lang = next(iter(examples.keys()))
                        fixed_code = examples[first_lang]["after"]

                    explanation = web_context.get("explanation", template["template"])
                    confidence = web_context.get("confidence", "high")
                    testing = template.get("testing", ["Test with malicious input", "Test with normal input"])
                else:
                    # Unknown context - use default template behavior
                    examples = template["example"]
                    if language in examples:
                        fixed_code = examples[language]["after"]
                        explanation = template["template"]
                    elif "python" in examples:
                        fixed_code = examples["python"]["after"]
                        explanation = template["template"] + f" (Note: Example is in Python, adapt for {language})"
                    else:
                        first_lang = next(iter(examples.keys()))
                        fixed_code = examples[first_lang]["after"]
                        explanation = template["template"] + f" (Note: Example is in {first_lang}, adapt for {language})"

                    explanation += f" Context: {output_dest}"
                    confidence = "medium"
                    testing = template.get("testing", ["Test with malicious input", "Test with normal input"])
            else:
                # Non-context-aware template - use standard behavior
                examples = template["example"]
                if language in examples:
                    fixed_code = examples[language]["after"]
                    explanation = template["template"]
                elif "python" in examples:
                    # Default to Python example
                    fixed_code = examples["python"]["after"]
                    explanation = template["template"] + f" (Note: Example is in Python, adapt for {language})"
                else:
                    # Use first available example
                    first_lang = next(iter(examples.keys()))
                    fixed_code = examples[first_lang]["after"]
                    explanation = template["template"] + f" (Note: Example is in {first_lang}, adapt for {language})"

                testing = template.get("testing", ["Test with malicious input", "Test with normal input"])
                confidence = "medium"

        # Generate unified diff
        original_lines = code_snippet.split("\n") if code_snippet else [""]
        fixed_lines = fixed_code.split("\n")
        diff = "\n".join(
            difflib.unified_diff(
                original_lines,
                fixed_lines,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="",
            )
        )

        # Add context metadata for XSS findings
        metadata = {"generator": "template"}
        if normalized_type == "xss":
            output_dest = self._detect_output_destination(code_snippet, file_path)
            metadata["output_destination"] = output_dest
            metadata["context_aware"] = True

        return RemediationSuggestion(
            finding_id=finding.get("id", "unknown"),
            vulnerability_type=vuln_type,
            file_path=file_path,
            line_number=line_number,
            original_code=code_snippet,
            fixed_code=fixed_code,
            diff=diff,
            explanation=explanation,
            testing_recommendations=testing,
            confidence=confidence,
            cwe_references=self._get_cwe_references(vuln_type),
            metadata=metadata,
        )

    def generate_batch_fixes(self, findings: List[Dict], max_findings: int = None) -> List[RemediationSuggestion]:
        """Generate fixes for multiple findings

        Args:
            findings: List of finding dictionaries
            max_findings: Optional limit on number of findings to process

        Returns:
            List of RemediationSuggestion objects
        """
        if max_findings:
            findings = findings[:max_findings]

        logger.info(f"Generating fixes for {len(findings)} findings")

        suggestions = []
        for i, finding in enumerate(findings, 1):
            try:
                logger.debug(f"Processing finding {i}/{len(findings)}: {finding.get('id', 'unknown')}")
                suggestion = self.suggest_fix(finding)
                suggestions.append(suggestion)
            except Exception as e:
                logger.error(f"Failed to generate fix for {finding.get('id', 'unknown')}: {e}")

        logger.info(f"Generated {len(suggestions)} fix suggestions")
        return suggestions

    def export_as_markdown(self, suggestions: List[RemediationSuggestion], output_file: str):
        """Export suggestions as markdown report

        Args:
            suggestions: List of RemediationSuggestion objects
            output_file: Path to output markdown file
        """
        with open(output_file, "w") as f:
            f.write("# Security Remediation Recommendations\n\n")
            f.write(f"**Generated:** {datetime.datetime.utcnow().isoformat()}Z\n\n")
            f.write(f"**Total Vulnerabilities:** {len(suggestions)}\n\n")

            # Summary by confidence
            confidence_counts = {"high": 0, "medium": 0, "low": 0}
            for s in suggestions:
                confidence_counts[s.confidence] = confidence_counts.get(s.confidence, 0) + 1

            f.write("**Confidence Distribution:**\n")
            f.write(f"- High: {confidence_counts['high']}\n")
            f.write(f"- Medium: {confidence_counts['medium']}\n")
            f.write(f"- Low: {confidence_counts['low']}\n\n")

            f.write("---\n\n")

            # Individual suggestions
            for i, suggestion in enumerate(suggestions, 1):
                f.write(f"## {i}. {suggestion.vulnerability_type}\n\n")
                f.write(f"**File:** `{suggestion.file_path}:{suggestion.line_number}`  \n")
                f.write(f"**Confidence:** {suggestion.confidence.upper()}  \n")
                f.write(f"**CWE:** {', '.join(suggestion.cwe_references)}  \n")
                if suggestion.metadata:
                    generator = suggestion.metadata.get("generator", "unknown")
                    f.write(f"**Generator:** {generator}")
                    if generator == "ai":
                        f.write(f" ({suggestion.metadata.get('provider')}/{suggestion.metadata.get('model')})")
                    f.write("  \n")
                f.write("\n")

                f.write("### Explanation\n\n")
                f.write(f"{suggestion.explanation}\n\n")

                f.write("### Original Code\n\n")
                lang = self._detect_language(suggestion.file_path)
                f.write(f"```{lang}\n{suggestion.original_code}\n```\n\n")

                f.write("### Fixed Code\n\n")
                f.write(f"```{lang}\n{suggestion.fixed_code}\n```\n\n")

                f.write("### Diff\n\n")
                f.write(f"```diff\n{suggestion.diff}\n```\n\n")

                f.write("### Testing Recommendations\n\n")
                for rec in suggestion.testing_recommendations:
                    f.write(f"- {rec}\n")
                f.write("\n")

                f.write("---\n\n")

        logger.info(f"Exported remediation report to {output_file}")

    def export_as_json(self, suggestions: List[RemediationSuggestion], output_file: str):
        """Export suggestions as JSON

        Args:
            suggestions: List of RemediationSuggestion objects
            output_file: Path to output JSON file
        """
        data = {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "total_suggestions": len(suggestions),
            "suggestions": [s.to_dict() for s in suggestions],
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported remediation suggestions to {output_file}")

    def _detect_output_destination(self, code_snippet: str, file_path: str = "") -> str:
        """Detect the output destination for code snippet

        Analyzes the code to determine if output goes to terminal, browser, HTTP response, etc.
        This helps identify false positives (e.g., XSS in CLI tools that output to terminal).

        Args:
            code_snippet: Code to analyze
            file_path: Optional file path for additional context

        Returns:
            One of: "terminal", "browser", "http-response", "file", "unknown"
        """
        if not code_snippet:
            return "unknown"

        code_lower = code_snippet.lower()

        # Check for CLI/terminal output patterns
        for pattern in self.CLI_SAFE_PATTERNS:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return "terminal"

        # Check for browser DOM manipulation
        browser_patterns = [
            r"innerHTML",
            r"dangerouslySetInnerHTML",
            r"document\.write",
            r"\.html\(",  # jQuery .html()
            r"outerHTML",
        ]
        for pattern in browser_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return "browser"

        # Check for HTTP response patterns
        http_patterns = [
            r"res\.send",
            r"res\.write",
            r"response\.write",
            r"HttpResponse",
            r"render_template",
            r"render\(",
            r"\.render",
        ]
        for pattern in http_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return "http-response"

        # Check for file output
        file_patterns = [
            r"\.write\(",
            r"file\.write",
            r"fs\.writeFile",
            r"fwrite\(",
        ]
        for pattern in file_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return "file"

        # Use file path as additional context
        if file_path:
            path_lower = file_path.lower()
            # CLI tools often have these patterns in path
            if any(indicator in path_lower for indicator in ["cli", "cmd", "console", "terminal", "bin/"]):
                return "terminal"
            # Web apps often have these patterns
            if any(indicator in path_lower for indicator in ["web", "http", "server", "api", "routes", "controllers", "views"]):
                return "http-response"

        return "unknown"

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension

        Args:
            file_path: Path to file

        Returns:
            Language name (lowercase)
        """
        ext = Path(file_path).suffix.lower()

        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".c": "c",
            ".h": "c",
            ".rs": "rust",
            ".kt": "kotlin",
            ".swift": "swift",
            ".scala": "scala",
            ".sh": "bash",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".tf": "terraform",
        }

        return lang_map.get(ext, "text")

    def _get_cwe_references(self, vuln_type: str) -> List[str]:
        """Get relevant CWE IDs for vulnerability type

        Args:
            vuln_type: Vulnerability type string

        Returns:
            List of CWE identifiers
        """
        normalized_type = vuln_type.lower().replace("-", "_")
        return self.CWE_MAP.get(normalized_type, ["CWE-Unknown"])


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Automated Remediation Engine - Generate AI-powered security fixes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate fixes from findings JSON
  python remediation_engine.py --findings findings.json --output report.md

  # Generate JSON output instead of markdown
  python remediation_engine.py --findings findings.json --output fixes.json --format json

  # Limit number of findings to process
  python remediation_engine.py --findings findings.json --max-findings 10

  # Enable debug logging
  python remediation_engine.py --findings findings.json --debug
        """,
    )

    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--output", default="remediation_report.md", help="Output file path (default: remediation_report.md)")
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument("--max-findings", type=int, help="Maximum number of findings to process")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Configure logging
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Load findings
    logger.info(f"Loading findings from {args.findings}")
    try:
        with open(args.findings) as f:
            data = json.load(f)

        # Handle different input formats
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            # Try common keys
            findings = data.get("findings") or data.get("results") or data.get("vulnerabilities") or []
        else:
            logger.error(f"Unexpected findings format: {type(data)}")
            sys.exit(1)

        logger.info(f"Loaded {len(findings)} findings")

    except FileNotFoundError:
        logger.error(f"Findings file not found: {args.findings}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in findings file: {e}")
        sys.exit(1)

    if not findings:
        logger.warning("No findings to process")
        sys.exit(0)

    # Initialize engine
    logger.info("Initializing Remediation Engine")
    engine = RemediationEngine()

    # Generate fixes
    suggestions = engine.generate_batch_fixes(findings, max_findings=args.max_findings)

    if not suggestions:
        logger.warning("No remediation suggestions generated")
        sys.exit(0)

    # Export results
    if args.format == "json":
        engine.export_as_json(suggestions, args.output)
    else:
        engine.export_as_markdown(suggestions, args.output)

    # Print summary
    print(f"\n✅ Generated {len(suggestions)} fix suggestions")
    print(f"📄 Report saved to: {args.output}")

    # Print confidence breakdown
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    for s in suggestions:
        confidence_counts[s.confidence] = confidence_counts.get(s.confidence, 0) + 1

    print(f"\n📊 Confidence Breakdown:")
    print(f"   High:   {confidence_counts['high']}")
    print(f"   Medium: {confidence_counts['medium']}")
    print(f"   Low:    {confidence_counts['low']}")


if __name__ == "__main__":
    main()
