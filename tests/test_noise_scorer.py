#!/usr/bin/env python3
"""
Test Suite for NoiseScorer

Comprehensive tests covering:
- Initialization with and without history file
- Historical fix rate calculation
- Pattern-based noise detection
- ML noise calculation (mocked)
- FP probability parsing
- FP prediction prompt building
- Finding scoring
- History updates
- Edge cases and error handling
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# We need to mock imports before importing the module under test
# because noise_scorer.py imports from normalizer.base and providers.anthropic_provider

# Create mock modules
mock_anthropic_provider_module = MagicMock()
mock_anthropic_provider_class = MagicMock()
mock_anthropic_provider_module.AnthropicProvider = mock_anthropic_provider_class

# We need the real Finding class if available, or mock it
scripts_dir = str(Path(__file__).parent.parent / "scripts")
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from normalizer.base import Finding


class TestNoiseScorer(unittest.TestCase):
    """Base class with common setup for NoiseScorer tests"""

    def _make_finding(self, **kwargs):
        """Helper to create a Finding with required fields"""
        defaults = {
            "id": "test-finding-1",
            "origin": "semgrep",
            "repo": "test-repo",
            "commit_sha": "abc123",
            "branch": "main",
            "path": "src/app.py",
            "rule_id": "python.lang.security.audit.exec",
            "rule_name": "exec-detected",
            "category": "SAST",
            "severity": "high",
            "confidence": 0.9,
        }
        defaults.update(kwargs)
        return Finding(**defaults)


class TestNoiseScorerInit(TestNoiseScorer):
    """Tests for NoiseScorer initialization"""

    @patch("noise_scorer.AnthropicProvider")
    def test_init_no_history_file(self, mock_provider):
        """Init with non-existent history file should have empty history"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent_history.jsonl")
        self.assertEqual(scorer.history, [])

    @patch("noise_scorer.AnthropicProvider")
    def test_init_with_history_file(self, mock_provider):
        """Init with existing history file should load records"""
        from noise_scorer import NoiseScorer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"rule_id": "R1", "status": "fixed"}) + "\n")
            f.write(json.dumps({"rule_id": "R2", "status": "open"}) + "\n")
            tmppath = f.name

        try:
            scorer = NoiseScorer(history_file=tmppath)
            self.assertEqual(len(scorer.history), 2)
            self.assertEqual(scorer.history[0]["rule_id"], "R1")
        finally:
            os.unlink(tmppath)

    @patch("noise_scorer.AnthropicProvider", side_effect=Exception("No API key"))
    def test_init_llm_not_available(self, mock_provider):
        """Init should handle LLM initialization failure gracefully"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        self.assertIsNone(scorer.llm)

    @patch("noise_scorer.AnthropicProvider")
    def test_init_llm_available(self, mock_provider):
        """Init should set self.llm when provider is available"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        self.assertIsNotNone(scorer.llm)

    @patch("noise_scorer.AnthropicProvider")
    def test_init_default_history_path(self, mock_provider):
        """Default history file should be .argus/finding_history.jsonl"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer()
        self.assertEqual(scorer.history_file, Path(".argus/finding_history.jsonl"))


class TestCalculateHistoricalFixRate(TestNoiseScorer):
    """Tests for _calculate_historical_fix_rate"""

    @patch("noise_scorer.AnthropicProvider")
    def test_no_history_returns_0_5(self, mock_provider):
        """No history -> 50% fix rate default"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding()
        rate = scorer._calculate_historical_fix_rate(finding)
        self.assertEqual(rate, 0.5)

    @patch("noise_scorer.AnthropicProvider")
    def test_no_similar_findings_returns_0_5(self, mock_provider):
        """History exists but no matching findings -> 50%"""
        from noise_scorer import NoiseScorer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({
                "rule_id": "OTHER_RULE",
                "category": "VULN",
                "severity": "low",
                "status": "fixed",
            }) + "\n")
            tmppath = f.name
        try:
            scorer = NoiseScorer(history_file=tmppath)
            finding = self._make_finding(rule_id="MY_RULE", category="SAST", severity="high")
            rate = scorer._calculate_historical_fix_rate(finding)
            self.assertEqual(rate, 0.5)
        finally:
            os.unlink(tmppath)

    @patch("noise_scorer.AnthropicProvider")
    def test_all_fixed_returns_1_0(self, mock_provider):
        """All similar findings fixed -> 100% fix rate"""
        from noise_scorer import NoiseScorer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for _ in range(5):
                f.write(json.dumps({
                    "rule_id": "R1",
                    "category": "SAST",
                    "severity": "high",
                    "status": "fixed",
                }) + "\n")
            tmppath = f.name
        try:
            scorer = NoiseScorer(history_file=tmppath)
            finding = self._make_finding(rule_id="R1", category="SAST", severity="high")
            rate = scorer._calculate_historical_fix_rate(finding)
            self.assertEqual(rate, 1.0)
        finally:
            os.unlink(tmppath)

    @patch("noise_scorer.AnthropicProvider")
    def test_none_fixed_returns_0(self, mock_provider):
        """No similar findings fixed -> 0% fix rate"""
        from noise_scorer import NoiseScorer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for _ in range(3):
                f.write(json.dumps({
                    "rule_id": "R1",
                    "category": "SAST",
                    "severity": "high",
                    "status": "open",
                }) + "\n")
            tmppath = f.name
        try:
            scorer = NoiseScorer(history_file=tmppath)
            finding = self._make_finding(rule_id="R1", category="SAST", severity="high")
            rate = scorer._calculate_historical_fix_rate(finding)
            self.assertEqual(rate, 0.0)
        finally:
            os.unlink(tmppath)

    @patch("noise_scorer.AnthropicProvider")
    def test_partial_fix_rate(self, mock_provider):
        """Mix of fixed and open -> proportional rate"""
        from noise_scorer import NoiseScorer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for status in ["fixed", "fixed", "open", "open"]:
                f.write(json.dumps({
                    "rule_id": "R1",
                    "category": "SAST",
                    "severity": "high",
                    "status": status,
                }) + "\n")
            tmppath = f.name
        try:
            scorer = NoiseScorer(history_file=tmppath)
            finding = self._make_finding(rule_id="R1", category="SAST", severity="high")
            rate = scorer._calculate_historical_fix_rate(finding)
            self.assertEqual(rate, 0.5)
        finally:
            os.unlink(tmppath)

    @patch("noise_scorer.AnthropicProvider")
    def test_fix_rate_requires_exact_match(self, mock_provider):
        """Similar = same rule_id + category + severity; different severity should not match"""
        from noise_scorer import NoiseScorer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({
                "rule_id": "R1",
                "category": "SAST",
                "severity": "low",  # different severity
                "status": "fixed",
            }) + "\n")
            tmppath = f.name
        try:
            scorer = NoiseScorer(history_file=tmppath)
            finding = self._make_finding(rule_id="R1", category="SAST", severity="high")
            rate = scorer._calculate_historical_fix_rate(finding)
            self.assertEqual(rate, 0.5)  # No match -> default 0.5
        finally:
            os.unlink(tmppath)


class TestCalculatePatternNoise(TestNoiseScorer):
    """Tests for _calculate_pattern_noise"""

    @patch("noise_scorer.AnthropicProvider")
    def test_test_file_adds_noise(self, mock_provider):
        """Findings in test files should get +0.3 noise"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(path="tests/test_app.py")
        noise = scorer._calculate_pattern_noise(finding)
        self.assertGreaterEqual(noise, 0.3)

    @patch("noise_scorer.AnthropicProvider")
    def test_spec_file_adds_noise(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(path="app.spec.js")
        noise = scorer._calculate_pattern_noise(finding)
        self.assertGreaterEqual(noise, 0.3)

    @patch("noise_scorer.AnthropicProvider")
    def test_mock_file_adds_noise(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(path="__mocks__/mock_service.py")
        noise = scorer._calculate_pattern_noise(finding)
        self.assertGreaterEqual(noise, 0.3)

    @patch("noise_scorer.AnthropicProvider")
    def test_low_severity_no_cve_adds_noise(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(severity="low", cve=None)
        noise = scorer._calculate_pattern_noise(finding)
        self.assertGreaterEqual(noise, 0.2)

    @patch("noise_scorer.AnthropicProvider")
    def test_info_severity_adds_noise(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(severity="info", cve=None)
        noise = scorer._calculate_pattern_noise(finding)
        # info severity adds 0.3 + low severity no CVE adds 0.2
        self.assertGreaterEqual(noise, 0.5)

    @patch("noise_scorer.AnthropicProvider")
    def test_deps_without_reachability_adds_noise(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(category="DEPS", reachability="no")
        noise = scorer._calculate_pattern_noise(finding)
        self.assertGreaterEqual(noise, 0.4)

    @patch("noise_scorer.AnthropicProvider")
    def test_unverified_secrets_adds_noise(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(category="SECRETS", secret_verified="false")
        noise = scorer._calculate_pattern_noise(finding)
        self.assertGreaterEqual(noise, 0.5)

    @patch("noise_scorer.AnthropicProvider")
    def test_low_confidence_adds_noise(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(confidence=0.3)
        noise = scorer._calculate_pattern_noise(finding)
        self.assertGreaterEqual(noise, 0.3)

    @patch("noise_scorer.AnthropicProvider")
    def test_noise_capped_at_1_0(self, mock_provider):
        """Maximum noise score is 1.0 even with many indicators"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        # Finding with many noise indicators
        finding = self._make_finding(
            path="test/mock_file.py",
            severity="info",
            cve=None,
            category="SECRETS",
            secret_verified="false",
            confidence=0.1,
        )
        noise = scorer._calculate_pattern_noise(finding)
        self.assertLessEqual(noise, 1.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_clean_finding_low_noise(self, mock_provider):
        """Clean high-confidence finding should have low noise"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(
            path="src/main.py",
            severity="high",
            cve="CVE-2023-1234",
            category="SAST",
            confidence=0.95,
        )
        noise = scorer._calculate_pattern_noise(finding)
        self.assertEqual(noise, 0.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_verified_secret_no_noise_from_verification(self, mock_provider):
        """Verified secrets should NOT get the unverified noise penalty"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(category="SECRETS", secret_verified="true")
        noise = scorer._calculate_pattern_noise(finding)
        # Should not have the 0.5 penalty for unverified secrets
        self.assertLess(noise, 0.5)


class TestParseFpProbability(TestNoiseScorer):
    """Tests for _parse_fp_probability"""

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_json_response(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = '{"false_positive_probability": 0.75, "reasoning": "test code"}'
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.75)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_json_embedded_in_text(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = 'Analysis: {"false_positive_probability": 0.6, "reasoning": "test"} end'
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.6)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_high_probability_text(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = "There is a high probability this is a false positive"
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.8)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_likely_false_positive_text(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = "This is likely false positive due to test code"
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.8)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_medium_probability_text(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = "medium probability this is noise"
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.5)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_possibly_false_positive_text(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = "This is possibly false positive"
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.5)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_low_probability_text(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = "low probability of false positive"
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.2)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_unlikely_false_positive_text(self, mock_provider):
        """'unlikely false positive' contains 'likely false positive' as a substring,
        so the source code matches it as 0.8 (the first text check wins).
        This documents the existing behavior."""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = "This is unlikely false positive - real vulnerability"
        prob = scorer._parse_fp_probability(response)
        # "likely false positive" substring matches first -> 0.8
        self.assertEqual(prob, 0.8)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_unparseable_returns_0(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = "I cannot determine the probability"
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_empty_response_returns_0(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        prob = scorer._parse_fp_probability("")
        self.assertEqual(prob, 0.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_invalid_json_falls_through(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = '{invalid json here}'
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_parse_json_missing_key_returns_0(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        response = '{"other_key": 0.5}'
        prob = scorer._parse_fp_probability(response)
        self.assertEqual(prob, 0.0)


class TestBuildFpPredictionPrompt(TestNoiseScorer):
    """Tests for _build_fp_prediction_prompt"""

    @patch("noise_scorer.AnthropicProvider")
    def test_prompt_contains_finding_details(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding(
            rule_id="python.security.eval",
            rule_name="eval-detected",
            category="SAST",
            severity="high",
            path="src/app.py",
            line=42,
        )
        finding.historical_fix_rate = 0.75
        prompt = scorer._build_fp_prediction_prompt(finding)
        self.assertIn("python.security.eval", prompt)
        self.assertIn("eval-detected", prompt)
        self.assertIn("SAST", prompt)
        self.assertIn("high", prompt)
        self.assertIn("src/app.py", prompt)
        self.assertIn("42", prompt)

    @patch("noise_scorer.AnthropicProvider")
    def test_prompt_asks_for_json(self, mock_provider):
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        finding = self._make_finding()
        finding.historical_fix_rate = 0.5
        prompt = scorer._build_fp_prediction_prompt(finding)
        self.assertIn("JSON", prompt)
        self.assertIn("false_positive_probability", prompt)


class TestCalculateMlNoise(TestNoiseScorer):
    """Tests for _calculate_ml_noise"""

    @patch("noise_scorer.AnthropicProvider")
    def test_ml_noise_exception_returns_0(self, mock_provider):
        """If ML prediction fails, should return 0.0"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        # Set llm to a mock that will fail
        scorer.llm = MagicMock()
        scorer.llm.analyze_code.side_effect = Exception("API Error")
        finding = self._make_finding()
        result = scorer._calculate_ml_noise(finding)
        self.assertEqual(result, 0.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_ml_noise_parses_response(self, mock_provider):
        """ML prediction should parse response for FP probability"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        scorer.llm = MagicMock()
        scorer.llm.analyze_code.return_value = (
            '{"false_positive_probability": 0.65, "reasoning": "test"}'
        )
        finding = self._make_finding()
        finding.historical_fix_rate = 0.5
        result = scorer._calculate_ml_noise(finding)
        self.assertEqual(result, 0.65)


class TestUpdateHistory(TestNoiseScorer):
    """Tests for update_history"""

    @patch("noise_scorer.AnthropicProvider")
    def test_creates_directory_if_not_exists(self, mock_provider):
        from noise_scorer import NoiseScorer

        with tempfile.TemporaryDirectory() as tmpdir:
            history_path = os.path.join(tmpdir, "subdir", "history.jsonl")
            scorer = NoiseScorer(history_file=history_path)
            finding = self._make_finding()
            finding.noise_score = 0.3
            scorer.update_history([finding])
            self.assertTrue(os.path.exists(history_path))

    @patch("noise_scorer.AnthropicProvider")
    def test_writes_jsonl_records(self, mock_provider):
        from noise_scorer import NoiseScorer

        with tempfile.TemporaryDirectory() as tmpdir:
            history_path = os.path.join(tmpdir, "history.jsonl")
            scorer = NoiseScorer(history_file=history_path)
            findings = [
                self._make_finding(rule_id="R1", category="SAST", severity="high"),
                self._make_finding(rule_id="R2", category="VULN", severity="low"),
            ]
            for f in findings:
                f.noise_score = 0.5
            scorer.update_history(findings)

            with open(history_path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)

            record1 = json.loads(lines[0])
            self.assertEqual(record1["rule_id"], "R1")
            self.assertIn("timestamp", record1)

    @patch("noise_scorer.AnthropicProvider")
    def test_appends_to_existing_history(self, mock_provider):
        from noise_scorer import NoiseScorer

        with tempfile.TemporaryDirectory() as tmpdir:
            history_path = os.path.join(tmpdir, "history.jsonl")
            # Write initial record
            with open(history_path, "w") as f:
                f.write(json.dumps({"rule_id": "EXISTING", "status": "fixed"}) + "\n")

            scorer = NoiseScorer(history_file=history_path)
            finding = self._make_finding(rule_id="NEW")
            finding.noise_score = 0.4
            scorer.update_history([finding])

            with open(history_path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)

    @patch("noise_scorer.AnthropicProvider")
    def test_empty_findings_writes_nothing(self, mock_provider):
        from noise_scorer import NoiseScorer

        with tempfile.TemporaryDirectory() as tmpdir:
            history_path = os.path.join(tmpdir, "history.jsonl")
            scorer = NoiseScorer(history_file=history_path)
            scorer.update_history([])
            with open(history_path) as f:
                content = f.read()
            self.assertEqual(content, "")

    @patch("noise_scorer.AnthropicProvider")
    def test_record_has_required_fields(self, mock_provider):
        from noise_scorer import NoiseScorer

        with tempfile.TemporaryDirectory() as tmpdir:
            history_path = os.path.join(tmpdir, "history.jsonl")
            scorer = NoiseScorer(history_file=history_path)
            finding = self._make_finding(rule_id="R1", category="SAST", severity="high")
            finding.noise_score = 0.5
            finding.status = "open"
            scorer.update_history([finding])

            with open(history_path) as f:
                record = json.loads(f.readline())
            self.assertIn("rule_id", record)
            self.assertIn("category", record)
            self.assertIn("severity", record)
            self.assertIn("status", record)
            self.assertIn("noise_score", record)
            self.assertIn("timestamp", record)


class TestScoreFindings(TestNoiseScorer):
    """Tests for score_findings"""

    @patch("noise_scorer.AnthropicProvider")
    def test_score_findings_without_llm(self, mock_provider):
        """score_findings should work when self.llm is None (no LLM available).
        Previously this raised AttributeError because the code referenced
        self.foundation_sec instead of self.llm."""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        scorer.llm = None  # No LLM, pattern_noise + historical only
        finding = self._make_finding(path="src/main.py", severity="high", confidence=0.9)
        results = scorer.score_findings([finding])
        self.assertEqual(len(results), 1)
        # noise_score should be set
        self.assertIsNotNone(results[0].noise_score)

    @patch("noise_scorer.AnthropicProvider")
    def test_score_findings_with_llm_set(self, mock_provider):
        """score_findings should use self.llm for ML noise prediction"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        mock_llm = MagicMock()
        mock_llm.analyze_code.return_value = '{"false_positive_probability": 0.3, "reasoning": "moderate risk"}'
        scorer.llm = mock_llm
        finding = self._make_finding(path="src/main.py", severity="high", confidence=0.9)
        finding.historical_fix_rate = 0.5
        results = scorer.score_findings([finding])
        self.assertEqual(len(results), 1)
        # LLM should have been called
        mock_llm.analyze_code.assert_called_once()
        # false_positive_probability should be set from LLM response
        self.assertAlmostEqual(results[0].false_positive_probability, 0.3)

    @patch("noise_scorer.AnthropicProvider")
    def test_score_findings_high_noise_suppressed(self, mock_provider):
        """Findings with noise_score > 0.7 should be suppressed.
        Without ML (llm=None), max noise is 0.4*1.0 + 0.4*0.0 + 0.2*0.5 = 0.5,
        so we need to provide a mock llm that returns high FP probability."""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        mock_llm = MagicMock()
        mock_llm.analyze_code.return_value = '{"false_positive_probability": 0.95, "reasoning": "test"}'
        scorer.llm = mock_llm
        finding = self._make_finding(
            path="test/test_app.py",
            severity="info",
            cve=None,
            category="SECRETS",
            secret_verified="false",
            confidence=0.2,
        )
        finding.historical_fix_rate = 0.0
        results = scorer.score_findings([finding])
        # noise = 0.4*1.0 + 0.4*0.95 + 0.2*(1.0-0.0) = 0.4+0.38+0.2 = 0.98
        self.assertGreater(results[0].noise_score, 0.7)
        self.assertEqual(results[0].status, "suppressed")
        self.assertIsNotNone(results[0].suppression_reason)

    @patch("noise_scorer.AnthropicProvider")
    def test_score_findings_low_noise_not_suppressed(self, mock_provider):
        """Clean findings should not be suppressed"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        scorer.llm = None
        finding = self._make_finding(
            path="src/app.py",
            severity="high",
            cve="CVE-2023-1234",
            category="SAST",
            confidence=0.95,
        )
        results = scorer.score_findings([finding])
        self.assertNotEqual(results[0].status, "suppressed")

    @patch("noise_scorer.AnthropicProvider")
    def test_score_findings_llm_failure_graceful_degradation(self, mock_provider):
        """If LLM call fails, score_findings should still complete using heuristics only"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        mock_llm = MagicMock()
        mock_llm.analyze_code.side_effect = Exception("API Error")
        scorer.llm = mock_llm
        finding = self._make_finding(path="src/main.py", severity="high", confidence=0.9)
        # Should not raise -- _calculate_ml_noise catches the exception and returns 0.0
        results = scorer.score_findings([finding])
        self.assertEqual(len(results), 1)
        # ml_noise was 0.0 due to failure, so false_positive_probability = 0.0
        self.assertEqual(results[0].false_positive_probability, 0.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_score_findings_multiple_findings(self, mock_provider):
        """score_findings should process all findings in the list"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        scorer.llm = None
        findings = [
            self._make_finding(id="f1", path="src/a.py"),
            self._make_finding(id="f2", path="test/b.py"),
            self._make_finding(id="f3", path="src/c.py", severity="info", cve=None),
        ]
        results = scorer.score_findings(findings)
        self.assertEqual(len(results), 3)
        # All should have noise_score set
        for r in results:
            self.assertIsNotNone(r.noise_score)
            self.assertGreaterEqual(r.noise_score, 0.0)
            self.assertLessEqual(r.noise_score, 1.0)

    @patch("noise_scorer.AnthropicProvider")
    def test_score_findings_empty_list(self, mock_provider):
        """score_findings should handle empty list gracefully"""
        from noise_scorer import NoiseScorer

        scorer = NoiseScorer(history_file="/tmp/nonexistent.jsonl")
        scorer.llm = None
        results = scorer.score_findings([])
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
