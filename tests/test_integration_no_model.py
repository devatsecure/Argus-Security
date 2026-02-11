#!/usr/bin/env python3
"""
Test Foundation-Sec Integration WITHOUT requiring the model
Tests the integration code, not the actual AI model
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from hybrid_analyzer import HybridFinding, HybridSecurityAnalyzer


def test_prompt_generation():
    """Test that enrichment prompts are generated correctly (no model needed)"""

    print("🧪 Testing Prompt Generation (No Model Required)")
    print("=" * 80)
    print()

    # Create test finding
    mock_finding = HybridFinding(
        finding_id="test-sql-injection-001",
        source_tool="semgrep",
        severity="high",
        category="security",
        title="SQL Injection via String Concatenation",
        description="Direct string concatenation in SQL query: query = f'SELECT * FROM users WHERE id={user_id}'",
        file_path="app/database.py",
        line_number=42,
        cve_id="CVE-2024-1234",
        cvss_score=9.8,
    )

    print("📝 Test Finding:")
    print(f"   ID: {mock_finding.finding_id}")
    print(f"   Title: {mock_finding.title}")
    print(f"   Severity: {mock_finding.severity}")
    print()

    try:
        # Initialize analyzer WITHOUT Foundation-Sec (just for prompt generation)
        analyzer = HybridSecurityAnalyzer(
            enable_semgrep=True,  # Need at least one enabled
            enable_trivy=False,
            enable_foundation_sec=False,  # Don't load model
        )

        # Generate prompt
        prompt = analyzer._build_enrichment_prompt(mock_finding)

        print("✅ Generated Prompt:")
        print("=" * 80)
        print(prompt)
        print("=" * 80)
        print()

        # Validate prompt structure
        checks = [
            ("Finding Details", "Finding Details:" in prompt),
            ("Finding ID", mock_finding.finding_id in prompt),
            ("CVE ID", mock_finding.cve_id in prompt),
            ("CVSS Score", str(mock_finding.cvss_score) in prompt),
            ("CWE Mapping", "CWE Mapping" in prompt),
            ("Exploitability", "Exploitability" in prompt),
            ("Severity Assessment", "Severity Assessment" in prompt),
            ("Remediation", "Remediation" in prompt),
            ("JSON Format", "JSON" in prompt),
            ("Response Structure", '"cwe_id"' in prompt),
        ]

        print("📋 Validation Checks:")
        all_passed = True
        for check_name, passed in checks:
            status = "✅" if passed else "❌"
            print(f"   {status} {check_name}")
            if not passed:
                all_passed = False

        print()
        if all_passed:
            print("🎉 All checks PASSED!")
            print()
            print("✅ Phase 1.2 Integration Code: WORKING")
            print("ℹ️  Note: Actual AI enrichment requires Foundation-Sec model")
            return True
        else:
            print("❌ Some checks failed")
            return False

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_response_parsing():
    """Test JSON response parsing (no model needed)"""

    print("\n")
    print("🧪 Testing Response Parsing (No Model Required)")
    print("=" * 80)
    print()

    try:
        analyzer = HybridSecurityAnalyzer(enable_semgrep=True, enable_trivy=False, enable_foundation_sec=False)

        # Mock AI response with JSON
        mock_response = """{
  "cwe_id": "CWE-89",
  "cwe_name": "SQL Injection",
  "exploitability": "trivial",
  "exploitability_reason": "Direct string concatenation allows trivial SQL injection",
  "severity_assessment": "critical",
  "severity_reason": "Allows complete database compromise",
  "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
  "references": [
    "https://cwe.mitre.org/data/definitions/89.html",
    "https://owasp.org/www-community/attacks/SQL_Injection"
  ]
}"""

        print("📝 Mock AI Response:")
        print(mock_response[:200] + "...")
        print()

        # Parse response
        analysis = analyzer._parse_ai_response(mock_response)

        if analysis:
            print("✅ Successfully parsed JSON response")
            print()
            print("📊 Extracted Data:")
            print(f"   CWE ID: {analysis.get('cwe_id')}")
            print(f"   Exploitability: {analysis.get('exploitability')}")
            print(f"   Severity: {analysis.get('severity_assessment')}")
            print(f"   Recommendation: {analysis.get('recommendation')[:60]}...")
            print()
            print("🎉 Response parsing: WORKING")
            return True
        else:
            print("❌ Failed to parse response")
            return False

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False


if __name__ == "__main__":
    print("\n")
    print("🚀 Foundation-Sec Integration Test (Without Model)")
    print("=" * 80)
    print()
    print("ℹ️  These tests verify the integration code works")
    print("ℹ️  Actual AI enrichment requires downloading the model")
    print()

    test1 = test_prompt_generation()
    test2 = test_response_parsing()

    print("\n")
    print("=" * 80)
    print("📊 Summary")
    print("=" * 80)
    print(f"   {'✅' if test1 else '❌'} Prompt Generation")
    print(f"   {'✅' if test2 else '❌'} Response Parsing")
    print()

    if test1 and test2:
        print("🎉 Phase 1.2 Integration: COMPLETE & WORKING")
        print()
        print("📝 Next Steps:")
        print("   1. Install dependencies: pip install transformers torch accelerate bitsandbytes")
        print("   2. Download model: python3 scripts/providers/foundation_sec.py")
        print("   3. Run with AI: python3 scripts/hybrid_analyzer.py . --enable-semgrep --enable-foundation-sec")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed")
        sys.exit(1)





