#!/usr/bin/env python3
"""
Quick integration test for verdict taxonomy implementation
Validates that all components work together correctly
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from verdict_taxonomy import (
    VerdictType,
    VerdictClassifier,
    VerdictMetadata,
    create_verdict_with_metadata
)
from agent_personas import AgentAnalysis, build_consensus


def test_verdict_classification():
    """Test basic verdict classification"""
    print("Test 1: Verdict Classification")
    print("=" * 60)

    test_cases = [
        (0.92, "critical", VerdictType.CONFIRMED),
        (0.75, "high", VerdictType.LIKELY_TRUE),
        (0.55, "medium", VerdictType.UNCERTAIN),
        (0.30, "low", VerdictType.LIKELY_FALSE_POSITIVE),
        (0.10, "medium", VerdictType.FALSE_POSITIVE),
    ]

    for conf, sev, expected in test_cases:
        result = VerdictClassifier.classify_verdict(conf, True, sev)
        status = "✓" if result == expected else "✗"
        print(f"{status} Conf={conf:.2f}, Sev={sev:8s} -> {result.get_display_name()}")
        assert result == expected, f"Expected {expected}, got {result}"

    print("✓ All classification tests passed\n")


def test_severity_adjustment():
    """Test severity-based threshold adjustment"""
    print("Test 2: Severity Threshold Adjustment")
    print("=" * 60)

    # At 0.25, medium should be likely_fp, critical should be uncertain
    medium_verdict = VerdictClassifier.classify_verdict(0.25, True, "medium")
    critical_verdict = VerdictClassifier.classify_verdict(0.25, True, "critical")

    print(f"Confidence 0.25 + Medium:   {medium_verdict.get_display_name()}")
    print(f"Confidence 0.25 + Critical: {critical_verdict.get_display_name()}")

    assert medium_verdict == VerdictType.LIKELY_FALSE_POSITIVE
    assert critical_verdict == VerdictType.UNCERTAIN

    print("✓ Severity adjustment working correctly\n")


def test_agent_analysis_integration():
    """Test AgentAnalysis with new verdict fields"""
    print("Test 3: AgentAnalysis Integration")
    print("=" * 60)

    analysis = AgentAnalysis(
        agent_name='TestAgent',
        confidence=0.62,
        verdict='uncertain',
        reasoning='Test reasoning',
        evidence=['Evidence 1'],
        recommendations=['Rec 1'],
        verdict_type=VerdictType.UNCERTAIN,
        verdict_metadata=VerdictMetadata(
            confidence=0.62,
            reasoning='Test reasoning',
            review_reason='Test review reason',
            recommended_action='Human review required'
        )
    )

    result_dict = analysis.to_dict()

    print(f"Agent: {result_dict['agent_name']}")
    print(f"Verdict Type: {result_dict['verdict_type']}")
    print(f"Display Name: {result_dict['verdict_display_name']}")
    print(f"Priority: {result_dict['verdict_priority']}")

    assert result_dict['verdict_type'] == 'uncertain'
    assert result_dict['verdict_display_name'] == 'Uncertain (Needs Review)'
    assert result_dict['verdict_priority'] == 3

    print("✓ AgentAnalysis integration working correctly\n")


def test_consensus_building():
    """Test priority-based consensus building"""
    print("Test 4: Priority-Based Consensus")
    print("=" * 60)

    analyses = [
        AgentAnalysis(
            agent_name='Agent1',
            confidence=0.85,
            verdict='confirmed',
            reasoning='High confidence',
            verdict_type=VerdictType.CONFIRMED,
            verdict_metadata=VerdictMetadata(
                confidence=0.85,
                reasoning='High confidence',
                recommended_action='Immediate remediation'
            )
        ),
        AgentAnalysis(
            agent_name='Agent2',
            confidence=0.65,
            verdict='uncertain',
            reasoning='Unclear context',
            verdict_type=VerdictType.UNCERTAIN,
            verdict_metadata=VerdictMetadata(
                confidence=0.65,
                reasoning='Unclear context',
                review_reason='Need more info',
                recommended_action='Human review required'
            )
        ),
        AgentAnalysis(
            agent_name='Agent3',
            confidence=0.15,
            verdict='false_positive',
            reasoning='Test file',
            verdict_type=VerdictType.FALSE_POSITIVE,
            verdict_metadata=VerdictMetadata(
                confidence=0.15,
                reasoning='Test file',
                recommended_action='Can suppress'
            )
        )
    ]

    consensus = build_consensus(analyses)

    print(f"Agent 1: CONFIRMED (priority 1)")
    print(f"Agent 2: UNCERTAIN (priority 3)")
    print(f"Agent 3: FALSE_POSITIVE (priority 6)")
    print(f"\nConsensus: {consensus['verdict']} (priority-based selection)")
    print(f"Agreement: {consensus['agreement_level']}")
    print(f"Avg Confidence: {consensus['confidence']:.2f}")

    # Should select CONFIRMED (highest priority)
    assert consensus['verdict'] == 'confirmed'

    print("✓ Consensus building working correctly\n")


def test_recommended_actions():
    """Test recommended action generation"""
    print("Test 5: Recommended Actions")
    print("=" * 60)

    test_cases = [
        (VerdictType.CONFIRMED, "critical", "Immediate remediation"),
        (VerdictType.LIKELY_TRUE, "high", "Manual validation"),
        (VerdictType.UNCERTAIN, "medium", "Human review required"),
        (VerdictType.FALSE_POSITIVE, "low", "can suppress"),
    ]

    for verdict, severity, expected_phrase in test_cases:
        action = VerdictClassifier.get_recommended_action(verdict, severity)
        status = "✓" if expected_phrase in action else "✗"
        print(f"{status} {verdict.value:20s} + {severity:8s} -> {action[:50]}...")
        assert expected_phrase in action

    print("✓ Recommended actions working correctly\n")


def test_deployment_blocking():
    """Test deployment blocking logic"""
    print("Test 6: Deployment Blocking Logic")
    print("=" * 60)

    # Should block
    block_cases = [
        (VerdictType.CONFIRMED, "critical", True),
        (VerdictType.CONFIRMED, "high", True),
        (VerdictType.LIKELY_TRUE, "critical", True),
    ]

    # Should NOT block
    pass_cases = [
        (VerdictType.CONFIRMED, "medium", False),
        (VerdictType.LIKELY_TRUE, "high", False),
        (VerdictType.UNCERTAIN, "critical", False),
        (VerdictType.FALSE_POSITIVE, "high", False),
    ]

    for verdict, severity, should_block in block_cases + pass_cases:
        result = VerdictClassifier.should_block_deployment(verdict, severity)
        status = "✓" if result == should_block else "✗"
        block_str = "BLOCK" if should_block else "PASS"
        print(f"{status} {verdict.value:20s} + {severity:8s} -> {block_str}")
        assert result == should_block

    print("✓ Deployment blocking logic working correctly\n")


def test_metadata_creation():
    """Test verdict metadata creation"""
    print("Test 7: Verdict Metadata Creation")
    print("=" * 60)

    verdict, metadata = create_verdict_with_metadata(
        confidence=0.62,
        analysis_complete=True,
        severity='high',
        reasoning='SQL query construction unclear',
        review_reason='Cannot determine if ORM protects'
    )

    print(f"Verdict: {verdict.get_display_name()}")
    print(f"Confidence: {metadata.confidence}")
    print(f"Review Reason: {metadata.review_reason}")
    print(f"Recommended Action: {metadata.recommended_action}")

    assert verdict == VerdictType.UNCERTAIN
    assert metadata.confidence == 0.62
    assert metadata.review_reason == 'Cannot determine if ORM protects'
    assert 'Human review' in metadata.recommended_action

    print("✓ Metadata creation working correctly\n")


def main():
    """Run all integration tests"""
    print("\n" + "=" * 60)
    print("VERDICT TAXONOMY INTEGRATION TEST")
    print("=" * 60 + "\n")

    try:
        test_verdict_classification()
        test_severity_adjustment()
        test_agent_analysis_integration()
        test_consensus_building()
        test_recommended_actions()
        test_deployment_blocking()
        test_metadata_creation()

        print("=" * 60)
        print("✓ ALL INTEGRATION TESTS PASSED")
        print("=" * 60)
        return 0

    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
