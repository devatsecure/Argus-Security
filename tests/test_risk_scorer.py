#!/usr/bin/env python3
"""
Test Suite for RiskScorer

Comprehensive tests covering:
- Enum classes (Exploitability, Reachability, BusinessImpact)
- RiskScore dataclass
- RiskScorer initialization
- Single finding scoring
- Multiple findings scoring
- Finding enrichment
- CVSS extraction (direct, metadata, severity fallback)
- Exploitability classification
- Reachability classification
- Business impact classification
- Severity/priority mapping
- Edge cases and boundary values
"""

import unittest
from unittest.mock import patch

from risk_scorer import (
    BusinessImpact,
    Exploitability,
    Reachability,
    RiskScore,
    RiskScorer,
)


class TestExploitabilityEnum(unittest.TestCase):
    """Tests for Exploitability enum"""

    def test_all_values(self):
        self.assertEqual(Exploitability.CRITICAL.value, "critical")
        self.assertEqual(Exploitability.HIGH.value, "high")
        self.assertEqual(Exploitability.MEDIUM.value, "medium")
        self.assertEqual(Exploitability.LOW.value, "low")
        self.assertEqual(Exploitability.NONE.value, "none")

    def test_string_enum(self):
        self.assertIsInstance(Exploitability.CRITICAL, str)

    def test_from_value(self):
        self.assertEqual(Exploitability("critical"), Exploitability.CRITICAL)

    def test_invalid_value_raises(self):
        with self.assertRaises(ValueError):
            Exploitability("invalid")


class TestReachabilityEnum(unittest.TestCase):
    """Tests for Reachability enum"""

    def test_all_values(self):
        self.assertEqual(Reachability.DIRECT.value, "direct")
        self.assertEqual(Reachability.INDIRECT.value, "indirect")
        self.assertEqual(Reachability.UNUSED.value, "unused")

    def test_string_enum(self):
        self.assertIsInstance(Reachability.DIRECT, str)


class TestBusinessImpactEnum(unittest.TestCase):
    """Tests for BusinessImpact enum"""

    def test_all_values(self):
        self.assertEqual(BusinessImpact.CRITICAL.value, "critical")
        self.assertEqual(BusinessImpact.HIGH.value, "high")
        self.assertEqual(BusinessImpact.MEDIUM.value, "medium")
        self.assertEqual(BusinessImpact.LOW.value, "low")

    def test_from_value(self):
        self.assertEqual(BusinessImpact("high"), BusinessImpact.HIGH)


class TestRiskScoreDataclass(unittest.TestCase):
    """Tests for the RiskScore dataclass"""

    def test_create_risk_score(self):
        score = RiskScore(
            finding_id="abc123",
            raw_score=7.5,
            normalized_score=75,
            severity="high",
            factors={"cvss": 9.0, "exploitability": 0.8, "reachability": 1.0, "business_impact": 0.8},
            priority=2,
        )
        self.assertEqual(score.finding_id, "abc123")
        self.assertEqual(score.raw_score, 7.5)
        self.assertEqual(score.normalized_score, 75)
        self.assertEqual(score.severity, "high")
        self.assertEqual(score.priority, 2)
        self.assertEqual(score.factors["cvss"], 9.0)


class TestRiskScorerInit(unittest.TestCase):
    """Tests for RiskScorer initialization"""

    def test_default_business_impact(self):
        scorer = RiskScorer()
        self.assertEqual(scorer.default_business_impact, BusinessImpact.HIGH)

    def test_custom_business_impact_critical(self):
        scorer = RiskScorer(default_business_impact="critical")
        self.assertEqual(scorer.default_business_impact, BusinessImpact.CRITICAL)

    def test_custom_business_impact_low(self):
        scorer = RiskScorer(default_business_impact="low")
        self.assertEqual(scorer.default_business_impact, BusinessImpact.LOW)

    def test_custom_business_impact_medium(self):
        scorer = RiskScorer(default_business_impact="medium")
        self.assertEqual(scorer.default_business_impact, BusinessImpact.MEDIUM)

    def test_invalid_business_impact_raises(self):
        with self.assertRaises(ValueError):
            RiskScorer(default_business_impact="invalid")


class TestGetCVSS(unittest.TestCase):
    """Tests for _get_cvss"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_direct_cvss_score(self):
        finding = {"cvss_score": 9.8}
        self.assertEqual(self.scorer._get_cvss(finding), 9.8)

    def test_cvss_from_metadata(self):
        finding = {"cvss_score": 0.0, "metadata": {"cvss": 7.5}}
        self.assertEqual(self.scorer._get_cvss(finding), 7.5)

    def test_cvss_fallback_from_critical_severity(self):
        finding = {"severity": "critical"}
        self.assertEqual(self.scorer._get_cvss(finding), 9.0)

    def test_cvss_fallback_from_high_severity(self):
        finding = {"severity": "high"}
        self.assertEqual(self.scorer._get_cvss(finding), 7.0)

    def test_cvss_fallback_from_medium_severity(self):
        finding = {"severity": "medium"}
        self.assertEqual(self.scorer._get_cvss(finding), 5.0)

    def test_cvss_fallback_from_low_severity(self):
        finding = {"severity": "low"}
        self.assertEqual(self.scorer._get_cvss(finding), 3.0)

    def test_cvss_fallback_from_info_severity(self):
        finding = {"severity": "info"}
        self.assertEqual(self.scorer._get_cvss(finding), 0.0)

    def test_cvss_fallback_unknown_severity(self):
        finding = {"severity": "unknown"}
        self.assertEqual(self.scorer._get_cvss(finding), 5.0)

    def test_cvss_no_fields_default_medium(self):
        finding = {}
        # No cvss_score, no metadata, no severity -> defaults to "medium" -> 5.0
        self.assertEqual(self.scorer._get_cvss(finding), 5.0)

    def test_cvss_returns_float(self):
        finding = {"cvss_score": 8}
        result = self.scorer._get_cvss(finding)
        self.assertIsInstance(result, float)

    def test_cvss_direct_takes_priority_over_metadata(self):
        finding = {"cvss_score": 9.0, "metadata": {"cvss": 3.0}}
        self.assertEqual(self.scorer._get_cvss(finding), 9.0)


class TestGetExploitability(unittest.TestCase):
    """Tests for _get_exploitability"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_critical_active(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "active"}),
            Exploitability.CRITICAL,
        )

    def test_critical_in_the_wild(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "in-the-wild"}),
            Exploitability.CRITICAL,
        )

    def test_critical_literal(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "critical"}),
            Exploitability.CRITICAL,
        )

    def test_high_poc_exists(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "poc-exists"}),
            Exploitability.HIGH,
        )

    def test_high_easy(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "easy"}),
            Exploitability.HIGH,
        )

    def test_medium_moderate(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "moderate"}),
            Exploitability.MEDIUM,
        )

    def test_low_theoretical(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "theoretical"}),
            Exploitability.LOW,
        )

    def test_low_difficult(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "difficult"}),
            Exploitability.LOW,
        )

    def test_default_vuln_category_medium(self):
        self.assertEqual(
            self.scorer._get_exploitability({"category": "VULN"}),
            Exploitability.MEDIUM,
        )

    def test_default_non_vuln_category_low(self):
        self.assertEqual(
            self.scorer._get_exploitability({"category": "SAST"}),
            Exploitability.LOW,
        )

    def test_default_no_category_low(self):
        self.assertEqual(
            self.scorer._get_exploitability({}),
            Exploitability.LOW,
        )

    def test_case_insensitive(self):
        self.assertEqual(
            self.scorer._get_exploitability({"exploitability": "CRITICAL"}),
            Exploitability.CRITICAL,
        )


class TestGetReachability(unittest.TestCase):
    """Tests for _get_reachability"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_direct_reachable_high_confidence(self):
        finding = {"reachable": True, "reachability_confidence": "high"}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.DIRECT)

    def test_indirect_reachable_medium_confidence(self):
        finding = {"reachable": True, "reachability_confidence": "medium"}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.INDIRECT)

    def test_indirect_reachable_low_confidence(self):
        finding = {"reachable": True, "reachability_confidence": "low"}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.INDIRECT)

    def test_unused_not_reachable(self):
        finding = {"reachable": False, "reachability_confidence": "high"}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.UNUSED)

    def test_default_vuln_category_indirect(self):
        finding = {"category": "VULN"}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.INDIRECT)

    def test_default_non_vuln_category_direct(self):
        finding = {"category": "SAST"}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.DIRECT)

    def test_default_no_category_direct(self):
        finding = {}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.DIRECT)

    def test_reachable_false_without_confidence(self):
        finding = {"reachable": False}
        self.assertEqual(self.scorer._get_reachability(finding), Reachability.UNUSED)


class TestGetBusinessImpact(unittest.TestCase):
    """Tests for _get_business_impact"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_critical_production(self):
        self.assertEqual(
            self.scorer._get_business_impact({"business_impact": "production"}),
            BusinessImpact.CRITICAL,
        )

    def test_critical_literal(self):
        self.assertEqual(
            self.scorer._get_business_impact({"business_impact": "critical"}),
            BusinessImpact.CRITICAL,
        )

    def test_high_core(self):
        self.assertEqual(
            self.scorer._get_business_impact({"business_impact": "core"}),
            BusinessImpact.HIGH,
        )

    def test_medium_standard(self):
        self.assertEqual(
            self.scorer._get_business_impact({"business_impact": "standard"}),
            BusinessImpact.MEDIUM,
        )

    def test_low_dev(self):
        self.assertEqual(
            self.scorer._get_business_impact({"business_impact": "dev"}),
            BusinessImpact.LOW,
        )

    def test_low_test(self):
        self.assertEqual(
            self.scorer._get_business_impact({"business_impact": "test"}),
            BusinessImpact.LOW,
        )

    def test_default_uses_instance_default(self):
        scorer = RiskScorer(default_business_impact="low")
        self.assertEqual(
            scorer._get_business_impact({}),
            BusinessImpact.LOW,
        )

    def test_default_high(self):
        self.assertEqual(
            self.scorer._get_business_impact({}),
            BusinessImpact.HIGH,
        )

    def test_case_insensitive(self):
        self.assertEqual(
            self.scorer._get_business_impact({"business_impact": "CRITICAL"}),
            BusinessImpact.CRITICAL,
        )


class TestScoreToSeverity(unittest.TestCase):
    """Tests for _score_to_severity"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_critical_threshold_80(self):
        self.assertEqual(self.scorer._score_to_severity(80), "critical")

    def test_critical_100(self):
        self.assertEqual(self.scorer._score_to_severity(100), "critical")

    def test_high_threshold_60(self):
        self.assertEqual(self.scorer._score_to_severity(60), "high")

    def test_high_79(self):
        self.assertEqual(self.scorer._score_to_severity(79), "high")

    def test_medium_threshold_40(self):
        self.assertEqual(self.scorer._score_to_severity(40), "medium")

    def test_medium_59(self):
        self.assertEqual(self.scorer._score_to_severity(59), "medium")

    def test_low_39(self):
        self.assertEqual(self.scorer._score_to_severity(39), "low")

    def test_low_0(self):
        self.assertEqual(self.scorer._score_to_severity(0), "low")


class TestScoreToPriority(unittest.TestCase):
    """Tests for _score_to_priority"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_p1_80(self):
        self.assertEqual(self.scorer._score_to_priority(80), 1)

    def test_p1_100(self):
        self.assertEqual(self.scorer._score_to_priority(100), 1)

    def test_p2_60(self):
        self.assertEqual(self.scorer._score_to_priority(60), 2)

    def test_p2_79(self):
        self.assertEqual(self.scorer._score_to_priority(79), 2)

    def test_p3_40(self):
        self.assertEqual(self.scorer._score_to_priority(40), 3)

    def test_p3_59(self):
        self.assertEqual(self.scorer._score_to_priority(59), 3)

    def test_p4_39(self):
        self.assertEqual(self.scorer._score_to_priority(39), 4)

    def test_p4_0(self):
        self.assertEqual(self.scorer._score_to_priority(0), 4)


class TestScoreFinding(unittest.TestCase):
    """Tests for score_finding"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_max_score_critical_everything(self):
        finding = {
            "id": "f1",
            "cvss_score": 10.0,
            "exploitability": "critical",
            "reachable": True,
            "reachability_confidence": "high",
            "business_impact": "critical",
        }
        score = self.scorer.score_finding(finding)
        # 10.0 * 1.0 * 1.0 * 1.0 = 10.0 -> 100
        self.assertEqual(score.normalized_score, 100)
        self.assertEqual(score.severity, "critical")
        self.assertEqual(score.priority, 1)

    def test_none_exploitability_defaults_to_low(self):
        """'none' is not a recognized keyword, so it defaults to LOW (0.2) for non-VULN."""
        finding = {
            "id": "f2",
            "cvss_score": 10.0,
            "exploitability": "none",
        }
        score = self.scorer.score_finding(finding)
        # 'none' not in keyword lists + no category -> defaults to LOW (0.2)
        # 10.0 * 0.2 * 1.0 (direct default for non-VULN) * 0.8 (HIGH default) = 1.6 -> 16
        self.assertEqual(score.factors["exploitability"], 0.2)
        self.assertEqual(score.normalized_score, 16)
        self.assertEqual(score.severity, "low")
        self.assertEqual(score.priority, 4)

    def test_medium_score(self):
        finding = {
            "id": "f3",
            "cvss_score": 7.0,
            "exploitability": "medium",
            "category": "VULN",
        }
        score = self.scorer.score_finding(finding)
        # 7.0 * 0.5 * 0.6 * 0.8 = 1.68 -> 16
        self.assertEqual(score.raw_score, 1.68)
        self.assertEqual(score.normalized_score, 16)

    def test_normalized_score_clamped_to_100(self):
        """Ensure normalized score can't exceed 100"""
        scorer = RiskScorer()
        finding = {
            "id": "f4",
            "cvss_score": 10.0,
            "exploitability": "critical",
            "reachable": True,
            "reachability_confidence": "high",
            "business_impact": "critical",
        }
        score = scorer.score_finding(finding)
        self.assertLessEqual(score.normalized_score, 100)

    def test_normalized_score_not_negative(self):
        """Ensure normalized score can't be negative"""
        finding = {"id": "f5", "cvss_score": 0.0, "exploitability": "none"}
        score = self.scorer.score_finding(finding)
        self.assertGreaterEqual(score.normalized_score, 0)

    def test_finding_id_propagated(self):
        finding = {"id": "unique-id-xyz"}
        score = self.scorer.score_finding(finding)
        self.assertEqual(score.finding_id, "unique-id-xyz")

    def test_factors_dict_populated(self):
        finding = {"id": "f6", "cvss_score": 8.0, "exploitability": "high"}
        score = self.scorer.score_finding(finding)
        self.assertIn("cvss", score.factors)
        self.assertIn("exploitability", score.factors)
        self.assertIn("reachability", score.factors)
        self.assertIn("business_impact", score.factors)

    def test_raw_score_rounded(self):
        finding = {
            "id": "f7",
            "cvss_score": 7.3,
            "exploitability": "medium",
            "category": "SAST",
        }
        score = self.scorer.score_finding(finding)
        # Should be rounded to 2 decimal places
        self.assertEqual(score.raw_score, round(score.raw_score, 2))

    def test_severity_fallback_when_no_cvss(self):
        finding = {"id": "f8", "severity": "high"}
        score = self.scorer.score_finding(finding)
        self.assertEqual(score.factors["cvss"], 7.0)

    def test_empty_finding(self):
        finding = {"id": "f9"}
        score = self.scorer.score_finding(finding)
        # Should not crash, uses defaults
        self.assertIsNotNone(score)
        self.assertEqual(score.finding_id, "f9")

    def test_finding_without_id(self):
        finding = {}
        score = self.scorer.score_finding(finding)
        self.assertIsNone(score.finding_id)


class TestScoreFindings(unittest.TestCase):
    """Tests for score_findings"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_sorted_by_score_descending(self):
        findings = [
            {"id": "low", "cvss_score": 2.0},
            {"id": "high", "cvss_score": 9.0},
            {"id": "med", "cvss_score": 5.0},
        ]
        scores = self.scorer.score_findings(findings)
        normalized = [s.normalized_score for s in scores]
        self.assertEqual(normalized, sorted(normalized, reverse=True))

    def test_empty_findings_list(self):
        scores = self.scorer.score_findings([])
        self.assertEqual(scores, [])

    def test_single_finding(self):
        findings = [{"id": "f1", "cvss_score": 8.0}]
        scores = self.scorer.score_findings(findings)
        self.assertEqual(len(scores), 1)

    def test_returns_list_of_risk_scores(self):
        findings = [
            {"id": "f1", "cvss_score": 8.0},
            {"id": "f2", "cvss_score": 3.0},
        ]
        scores = self.scorer.score_findings(findings)
        self.assertTrue(all(isinstance(s, RiskScore) for s in scores))


class TestEnrichFindings(unittest.TestCase):
    """Tests for enrich_findings"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_enriches_with_risk_fields(self):
        findings = [{"id": "f1", "cvss_score": 8.0}]
        enriched = self.scorer.enrich_findings(findings)
        self.assertIn("risk_score", enriched[0])
        self.assertIn("risk_severity", enriched[0])
        self.assertIn("risk_priority", enriched[0])
        self.assertIn("risk_factors", enriched[0])

    def test_preserves_original_fields(self):
        findings = [{"id": "f1", "cvss_score": 8.0, "custom": "value"}]
        enriched = self.scorer.enrich_findings(findings)
        self.assertEqual(enriched[0]["custom"], "value")

    def test_sorted_by_risk_score_descending(self):
        findings = [
            {"id": "low", "cvss_score": 2.0},
            {"id": "high", "cvss_score": 9.0},
        ]
        enriched = self.scorer.enrich_findings(findings)
        scores = [f["risk_score"] for f in enriched]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_empty_findings(self):
        enriched = self.scorer.enrich_findings([])
        self.assertEqual(enriched, [])

    def test_finding_without_id_raises_in_summary(self):
        """Findings without 'id' trigger TypeError in _print_summary (finding_id[:16] on None)."""
        findings = [{"cvss_score": 5.0}]
        with self.assertRaises(TypeError):
            self.scorer.enrich_findings(findings)

    def test_multiple_findings_all_enriched(self):
        findings = [
            {"id": "f1", "cvss_score": 9.0},
            {"id": "f2", "cvss_score": 5.0},
            {"id": "f3", "cvss_score": 2.0},
        ]
        enriched = self.scorer.enrich_findings(findings)
        self.assertEqual(len(enriched), 3)
        for f in enriched:
            self.assertIn("risk_score", f)


class TestPrintSummary(unittest.TestCase):
    """Tests for _print_summary"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_empty_scores_no_output(self):
        # Should not raise
        self.scorer._print_summary([])

    def test_with_scores_no_crash(self):
        scores = [
            RiskScore(
                finding_id="f1" * 10,
                raw_score=9.0,
                normalized_score=90,
                severity="critical",
                factors={},
                priority=1,
            ),
            RiskScore(
                finding_id="f2" * 10,
                raw_score=3.0,
                normalized_score=30,
                severity="low",
                factors={},
                priority=4,
            ),
        ]
        # Should not raise
        self.scorer._print_summary(scores)


class TestRiskScorerMultipliers(unittest.TestCase):
    """Tests for multiplier constants"""

    def test_exploitability_multipliers_complete(self):
        scorer = RiskScorer()
        self.assertEqual(len(scorer.EXPLOITABILITY_MULTIPLIERS), 5)
        self.assertEqual(scorer.EXPLOITABILITY_MULTIPLIERS[Exploitability.CRITICAL], 1.0)
        self.assertEqual(scorer.EXPLOITABILITY_MULTIPLIERS[Exploitability.NONE], 0.0)

    def test_reachability_multipliers_complete(self):
        scorer = RiskScorer()
        self.assertEqual(len(scorer.REACHABILITY_MULTIPLIERS), 3)
        self.assertEqual(scorer.REACHABILITY_MULTIPLIERS[Reachability.DIRECT], 1.0)
        self.assertEqual(scorer.REACHABILITY_MULTIPLIERS[Reachability.UNUSED], 0.1)

    def test_business_impact_multipliers_complete(self):
        scorer = RiskScorer()
        self.assertEqual(len(scorer.BUSINESS_IMPACT_MULTIPLIERS), 4)
        self.assertEqual(scorer.BUSINESS_IMPACT_MULTIPLIERS[BusinessImpact.CRITICAL], 1.0)
        self.assertEqual(scorer.BUSINESS_IMPACT_MULTIPLIERS[BusinessImpact.LOW], 0.2)


class TestRiskScorerFormula(unittest.TestCase):
    """Tests verifying the risk scoring formula"""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_formula_cvss_times_exploit_times_reach_times_impact(self):
        """Verify: Raw = CVSS * Exploit * Reach * Impact"""
        finding = {
            "id": "formula_test",
            "cvss_score": 8.0,
            "exploitability": "high",  # 0.8
            "reachable": True,
            "reachability_confidence": "high",  # direct = 1.0
            "business_impact": "critical",  # 1.0
        }
        score = self.scorer.score_finding(finding)
        expected_raw = 8.0 * 0.8 * 1.0 * 1.0  # 6.4
        self.assertAlmostEqual(score.raw_score, expected_raw, places=2)

    def test_normalized_is_raw_times_10(self):
        finding = {
            "id": "norm_test",
            "cvss_score": 5.0,
            "exploitability": "medium",  # 0.5
            "reachable": False,
            "reachability_confidence": "high",  # unused = 0.1
            "business_impact": "low",  # 0.2
        }
        score = self.scorer.score_finding(finding)
        expected_raw = 5.0 * 0.5 * 0.1 * 0.2  # 0.05
        self.assertAlmostEqual(score.raw_score, expected_raw, places=2)
        self.assertEqual(score.normalized_score, int(expected_raw * 10))


if __name__ == "__main__":
    unittest.main()
