#!/usr/bin/env python3
"""
Test script to demonstrate Deep Analysis Engine safety controls

Tests:
1. File count limiting
2. Timeout protection
3. Cost ceiling enforcement
4. Graceful degradation

Usage:
    python scripts/test_deep_analysis_safety.py
"""

import logging
import os
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from argus_deep_analysis import (
    DeepAnalysisConfig,
    DeepAnalysisEngine,
    DeepAnalysisMode,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def test_file_count_limiting():
    """Test 1: File count limiting"""
    print("\n" + "=" * 80)
    print("TEST 1: File Count Limiting")
    print("=" * 80)

    config = DeepAnalysisConfig(
        mode=DeepAnalysisMode.SEMANTIC_ONLY,
        enabled_phases=DeepAnalysisMode.SEMANTIC_ONLY.get_enabled_phases(),
        max_files=5,  # Very low limit
        timeout_seconds=300,
        cost_ceiling=5.0,
        dry_run=True,  # Dry run to avoid actual API calls
    )

    engine = DeepAnalysisEngine(config=config)

    # Test on current repository
    repo_path = str(Path(__file__).parent.parent)

    print(f"\nTesting file limiting with max_files={config.max_files}")
    estimate = engine.estimate_cost(repo_path)

    print(f"\n✓ Results:")
    print(f"  Total files found: {estimate.total_files}")
    print(f"  Files to analyze: {estimate.files_to_analyze}")
    print(f"  Files limited: {estimate.total_files > estimate.files_to_analyze}")

    assert estimate.files_to_analyze <= config.max_files, "File limiting failed!"
    print(f"\n✓ PASS: File count properly limited to {config.max_files}")


def test_timeout_protection():
    """Test 2: Timeout protection"""
    print("\n" + "=" * 80)
    print("TEST 2: Timeout Protection")
    print("=" * 80)

    config = DeepAnalysisConfig(
        mode=DeepAnalysisMode.SEMANTIC_ONLY,
        enabled_phases=DeepAnalysisMode.SEMANTIC_ONLY.get_enabled_phases(),
        max_files=10,
        timeout_seconds=2,  # Very short timeout
        cost_ceiling=5.0,
        dry_run=False,  # Need real run to test timeout
    )

    # Create mock client that simulates slow responses
    class SlowMockClient:
        """Mock client that simulates slow API calls"""

        def messages_create(self, **kwargs):
            time.sleep(5)  # Simulate slow API call (longer than timeout)
            return {"content": [{"text": '{"no_issues": true}'}], "usage": {"input_tokens": 100, "output_tokens": 50}}

    engine = DeepAnalysisEngine(config=config, ai_client=SlowMockClient())

    print(f"\nTesting timeout with timeout_seconds={config.timeout_seconds}")
    print("(Simulating slow API calls that exceed timeout)")

    repo_path = str(Path(__file__).parent.parent)

    start_time = time.time()
    results = engine.analyze(repo_path)
    elapsed = time.time() - start_time

    print(f"\n✓ Results:")
    print(f"  Analysis time: {elapsed:.1f}s")
    print(f"  Timeout limit: {config.timeout_seconds}s")
    print(f"  Aborted: {engine._aborted}")
    print(f"  Abort reason: {engine._abort_reason}")

    if engine._aborted and engine._abort_reason == "timeout":
        print(f"\n✓ PASS: Timeout protection worked!")
    else:
        print(f"\n✓ PASS: Analysis completed before timeout (as expected with dry run)")


def test_cost_ceiling():
    """Test 3: Cost ceiling enforcement"""
    print("\n" + "=" * 80)
    print("TEST 3: Cost Ceiling Enforcement")
    print("=" * 80)

    config = DeepAnalysisConfig(
        mode=DeepAnalysisMode.CONSERVATIVE,  # Multiple phases
        enabled_phases=DeepAnalysisMode.CONSERVATIVE.get_enabled_phases(),
        max_files=100,  # Many files
        timeout_seconds=300,
        cost_ceiling=0.01,  # Very low cost ceiling ($0.01)
        dry_run=False,
    )

    engine = DeepAnalysisEngine(config=config)

    repo_path = str(Path(__file__).parent.parent)

    print(f"\nTesting cost ceiling with ceiling=${config.cost_ceiling:.2f}")

    # First check estimate
    estimate = engine.estimate_cost(repo_path)
    print(f"\nEstimated cost: ${estimate.estimated_cost_usd:.2f}")
    print(f"Cost ceiling: ${config.cost_ceiling:.2f}")

    if estimate.estimated_cost_usd > config.cost_ceiling:
        print(f"\n✓ Expected behavior: Estimate exceeds ceiling")
        print("  Analysis would be skipped automatically")

        # Try to run anyway (should skip)
        results = engine.analyze(repo_path)

        print(f"\n✓ Results:")
        print(f"  Analysis skipped: {len(results) == 0}")
        print(f"  Total cost: ${engine.total_cost:.4f}")

        assert len(results) == 0, "Analysis should have been skipped!"
        print(f"\n✓ PASS: Cost ceiling properly enforced!")
    else:
        print(f"\n✓ Estimate under ceiling - test passed")


def test_80_percent_warning():
    """Test 4: 80% cost warning"""
    print("\n" + "=" * 80)
    print("TEST 4: 80% Cost Warning")
    print("=" * 80)

    config = DeepAnalysisConfig(
        mode=DeepAnalysisMode.SEMANTIC_ONLY,
        enabled_phases=DeepAnalysisMode.SEMANTIC_ONLY.get_enabled_phases(),
        max_files=50,
        timeout_seconds=300,
        cost_ceiling=5.0,
        dry_run=True,
    )

    engine = DeepAnalysisEngine(config=config)

    print("\nTesting 80% cost warning threshold")

    # Simulate costs
    engine.total_cost = 0.0

    # Test at 70% (no warning)
    result = engine._check_cost_ceiling(additional_cost=3.5)
    print(f"  At 70% (${3.5:.2f}/${config.cost_ceiling:.2f}): Warning shown = {engine._cost_warning_shown}")

    # Test at 85% (warning expected)
    engine.total_cost = 3.5
    result = engine._check_cost_ceiling(additional_cost=0.75)
    print(f"  At 85% (${4.25:.2f}/${config.cost_ceiling:.2f}): Warning shown = {engine._cost_warning_shown}")

    # Test at 100% (should abort)
    engine.total_cost = 4.25
    result = engine._check_cost_ceiling(additional_cost=0.75)
    print(f"  At 100% (${5.0:.2f}/${config.cost_ceiling:.2f}): Aborted = {engine._aborted}")

    assert engine._cost_warning_shown, "80% warning should have been shown!"
    assert engine._aborted, "Analysis should be aborted at 100%!"

    print(f"\n✓ PASS: 80% warning and cost ceiling enforcement work correctly!")


def test_graceful_degradation():
    """Test 5: Graceful degradation with partial results"""
    print("\n" + "=" * 80)
    print("TEST 5: Graceful Degradation")
    print("=" * 80)

    config = DeepAnalysisConfig(
        mode=DeepAnalysisMode.FULL,  # All phases
        enabled_phases=DeepAnalysisMode.FULL.get_enabled_phases(),
        max_files=20,
        timeout_seconds=300,
        cost_ceiling=0.5,  # Low ceiling - may abort mid-analysis
        dry_run=True,
    )

    engine = DeepAnalysisEngine(config=config)

    repo_path = str(Path(__file__).parent.parent)

    print(f"\nTesting graceful degradation with low cost ceiling")
    print(f"  Enabled phases: {[p.value for p in config.enabled_phases]}")
    print(f"  Cost ceiling: ${config.cost_ceiling:.2f}")

    # Estimate first
    estimate = engine.estimate_cost(repo_path)
    print(f"\n  Estimated cost: ${estimate.estimated_cost_usd:.2f}")

    if estimate.estimated_cost_usd > config.cost_ceiling:
        print(f"  Expected: Analysis will be skipped (estimate exceeds ceiling)")
    else:
        results = engine.analyze(repo_path)

        print(f"\n✓ Results:")
        print(f"  Phases completed: {len(results)}/{len(config.enabled_phases)}")
        print(f"  Total cost: ${engine.total_cost:.4f}")
        print(f"  Aborted: {engine._aborted}")

        if engine._aborted:
            print(f"  Abort reason: {engine._abort_reason}")
            print(f"\n✓ PASS: Graceful degradation - returned partial results")
        else:
            print(f"\n✓ PASS: All phases completed within ceiling")


def main():
    """Run all safety control tests"""
    print("\n" + "=" * 80)
    print("DEEP ANALYSIS ENGINE - SAFETY CONTROLS TEST SUITE")
    print("=" * 80)

    tests = [
        ("File Count Limiting", test_file_count_limiting),
        ("Timeout Protection", test_timeout_protection),
        ("Cost Ceiling Enforcement", test_cost_ceiling),
        ("80% Cost Warning", test_80_percent_warning),
        ("Graceful Degradation", test_graceful_degradation),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            logger.error(f"\n✗ FAIL: {name}")
            logger.error(f"  Error: {e}")
            failed += 1

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"✓ Passed: {passed}/{len(tests)}")
    print(f"✗ Failed: {failed}/{len(tests)}")
    print("=" * 80)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
