#!/usr/bin/env python3
"""
Test script to validate Deep Analysis Engine feature flags
"""
import sys
sys.path.insert(0, 'scripts')

from argus_deep_analysis import DeepAnalysisConfig, DeepAnalysisMode, DeepAnalysisPhase

def test_mode_parsing():
    """Test mode parsing from strings"""
    print("=" * 60)
    print("Test 1: Mode Parsing")
    print("=" * 60)

    tests = [
        ("off", DeepAnalysisMode.OFF, []),
        ("semantic-only", DeepAnalysisMode.SEMANTIC_ONLY, [DeepAnalysisPhase.SEMANTIC_CODE_TWIN]),
        ("conservative", DeepAnalysisMode.CONSERVATIVE,
         [DeepAnalysisPhase.SEMANTIC_CODE_TWIN, DeepAnalysisPhase.PROACTIVE_SCANNER]),
        ("full", DeepAnalysisMode.FULL,
         [DeepAnalysisPhase.SEMANTIC_CODE_TWIN, DeepAnalysisPhase.PROACTIVE_SCANNER,
          DeepAnalysisPhase.TAINT_ANALYSIS, DeepAnalysisPhase.ZERO_DAY_HUNTER]),
    ]

    for mode_str, expected_mode, expected_phases in tests:
        mode = DeepAnalysisMode.from_string(mode_str)
        phases = mode.get_enabled_phases()

        assert mode == expected_mode, f"Failed: {mode_str} -> {mode} (expected {expected_mode})"
        assert phases == expected_phases, f"Failed phases for {mode_str}"

        print(f"✓ {mode_str:15s} -> {mode.value:15s} ({len(phases)} phases)")

    print()

def test_config_creation():
    """Test configuration creation"""
    print("=" * 60)
    print("Test 2: Config Creation")
    print("=" * 60)

    # Test with defaults
    config = DeepAnalysisConfig(
        mode=DeepAnalysisMode.CONSERVATIVE,
        enabled_phases=DeepAnalysisMode.CONSERVATIVE.get_enabled_phases(),
    )

    print(f"✓ Config created: mode={config.mode.value}")
    print(f"  - enabled_phases: {[p.value for p in config.enabled_phases]}")
    print(f"  - max_files: {config.max_files}")
    print(f"  - cost_ceiling: ${config.cost_ceiling}")
    print(f"  - dry_run: {config.dry_run}")
    print()

def test_environment_config():
    """Test environment variable loading"""
    import os
    print("=" * 60)
    print("Test 3: Environment Variable Config")
    print("=" * 60)

    # Set env vars
    os.environ['DEEP_ANALYSIS_MODE'] = 'conservative'
    os.environ['DEEP_ANALYSIS_MAX_FILES'] = '25'
    os.environ['DEEP_ANALYSIS_COST_CEILING'] = '3.0'

    config = DeepAnalysisConfig.from_env()

    assert config.mode == DeepAnalysisMode.CONSERVATIVE
    assert config.max_files == 25
    assert config.cost_ceiling == 3.0

    print(f"✓ Environment config loaded correctly")
    print(f"  - mode: {config.mode.value}")
    print(f"  - max_files: {config.max_files}")
    print(f"  - cost_ceiling: ${config.cost_ceiling}")

    # Clean up
    del os.environ['DEEP_ANALYSIS_MODE']
    del os.environ['DEEP_ANALYSIS_MAX_FILES']
    del os.environ['DEEP_ANALYSIS_COST_CEILING']
    print()

def test_cost_estimation():
    """Test cost estimation without AI client"""
    print("=" * 60)
    print("Test 4: Cost Estimation (Dry Run)")
    print("=" * 60)

    from argus_deep_analysis import DeepAnalysisEngine

    config = DeepAnalysisConfig(
        mode=DeepAnalysisMode.FULL,
        enabled_phases=DeepAnalysisMode.FULL.get_enabled_phases(),
        max_files=10,
        dry_run=True,
    )

    engine = DeepAnalysisEngine(config=config)
    estimate = engine.estimate_cost(".")

    print(f"✓ Cost estimation successful")
    print(f"  - Files to analyze: {estimate.files_to_analyze}/{estimate.total_files}")
    print(f"  - Estimated time: ~{int(estimate.estimated_time_seconds)}s")
    print(f"  - Estimated cost: ~${estimate.estimated_cost_usd:.2f}")
    print(f"  - Breakdown: {estimate.breakdown_by_phase}")
    print()

def test_mode_selection_logic():
    """Test mode selection decision tree"""
    print("=" * 60)
    print("Test 5: Mode Selection Guide")
    print("=" * 60)

    scenarios = [
        ("Large codebase, refactoring", "semantic-only"),
        ("Pre-merge PR check", "conservative"),
        ("Pre-release audit", "full"),
        ("Cost-conscious monitoring", "conservative"),
        ("Zero-day hunt", "full"),
    ]

    for scenario, recommended_mode in scenarios:
        mode = DeepAnalysisMode.from_string(recommended_mode)
        phases = mode.get_enabled_phases()
        print(f"  {scenario:30s} -> {recommended_mode:15s} ({len(phases)} phases)")

    print()

if __name__ == "__main__":
    print("\n🧪 Deep Analysis Engine Feature Flag Tests\n")

    try:
        test_mode_parsing()
        test_config_creation()
        test_environment_config()
        test_cost_estimation()
        test_mode_selection_logic()

        print("=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        print()

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
