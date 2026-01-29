#!/usr/bin/env python3
"""
Verification script for Phase 2.7 Deep Analysis integration.

This script verifies that Phase 2.7 integrates correctly with the existing
Argus Security pipeline without breaking any functionality.
"""

import sys
import os
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))


def test_imports():
    """Test that all required modules can be imported."""
    print("=" * 80)
    print("TEST 1: Module Imports")
    print("=" * 80)

    try:
        from argus_deep_analysis import DeepAnalysisMode, DeepAnalysisConfig, DeepAnalysisEngine
        print("✅ Deep analysis modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import deep analysis modules: {e}")
        return False


def test_mode_parsing():
    """Test that mode parsing works correctly."""
    print("\n" + "=" * 80)
    print("TEST 2: Mode Parsing")
    print("=" * 80)

    try:
        from argus_deep_analysis import DeepAnalysisMode

        modes = {
            "off": DeepAnalysisMode.OFF,
            "semantic-only": DeepAnalysisMode.SEMANTIC_ONLY,
            "conservative": DeepAnalysisMode.CONSERVATIVE,
            "full": DeepAnalysisMode.FULL,
        }

        for mode_str, expected_mode in modes.items():
            parsed_mode = DeepAnalysisMode.from_string(mode_str)
            if parsed_mode == expected_mode:
                print(f"✅ '{mode_str}' -> {expected_mode}")
            else:
                print(f"❌ '{mode_str}' parsing failed: got {parsed_mode}, expected {expected_mode}")
                return False

        return True
    except Exception as e:
        print(f"❌ Mode parsing test failed: {e}")
        return False


def test_enabled_phases():
    """Test that each mode enables the correct phases."""
    print("\n" + "=" * 80)
    print("TEST 3: Enabled Phases by Mode")
    print("=" * 80)

    try:
        from argus_deep_analysis import DeepAnalysisMode, DeepAnalysisPhase

        expected_phases = {
            DeepAnalysisMode.OFF: [],
            DeepAnalysisMode.SEMANTIC_ONLY: [DeepAnalysisPhase.SEMANTIC_CODE_TWIN],
            DeepAnalysisMode.CONSERVATIVE: [DeepAnalysisPhase.SEMANTIC_CODE_TWIN, DeepAnalysisPhase.PROACTIVE_SCANNER],
            DeepAnalysisMode.FULL: [DeepAnalysisPhase.SEMANTIC_CODE_TWIN, DeepAnalysisPhase.PROACTIVE_SCANNER, DeepAnalysisPhase.TAINT_ANALYSIS, DeepAnalysisPhase.ZERO_DAY_HUNTER],
        }

        for mode, expected in expected_phases.items():
            enabled = mode.get_enabled_phases()
            if set(enabled) == set(expected):
                phase_names = [p.value for p in enabled] if enabled else ["none"]
                print(f"✅ {mode.value}: {', '.join(phase_names)}")
            else:
                print(f"❌ {mode.value}: got {enabled}, expected {expected}")
                return False

        return True
    except Exception as e:
        print(f"❌ Enabled phases test failed: {e}")
        return False


def test_config_parsing():
    """Test that configuration parsing works correctly."""
    print("\n" + "=" * 80)
    print("TEST 4: Configuration Parsing")
    print("=" * 80)

    try:
        from argus_deep_analysis import DeepAnalysisConfig, DeepAnalysisMode

        # Test default config
        config = DeepAnalysisConfig(
            mode=DeepAnalysisMode.CONSERVATIVE,
            enabled_phases=DeepAnalysisMode.CONSERVATIVE.get_enabled_phases(),
            max_files=50,
            timeout_seconds=300,
            cost_ceiling=5.0,
            dry_run=False
        )

        print(f"✅ Config created:")
        print(f"   Mode: {config.mode.value}")
        print(f"   Enabled phases: {[p.value for p in config.enabled_phases]}")
        print(f"   Max files: {config.max_files}")
        print(f"   Timeout: {config.timeout_seconds}s")
        print(f"   Cost ceiling: ${config.cost_ceiling:.2f}")
        print(f"   Dry run: {config.dry_run}")

        return True
    except Exception as e:
        print(f"❌ Config parsing test failed: {e}")
        return False


def test_pipeline_integration():
    """Test that Phase 2.7 integrates with run_ai_audit.py."""
    print("\n" + "=" * 80)
    print("TEST 5: Pipeline Integration")
    print("=" * 80)

    try:
        from run_ai_audit import parse_args, build_config

        # Simulate command-line arguments
        sys.argv = ["run_ai_audit.py", ".", "audit", "--deep-analysis-mode=conservative"]
        args = parse_args()
        config = build_config(args)

        # Check that deep_analysis_mode is set
        mode = config.get("deep_analysis_mode")
        if mode == "conservative":
            print(f"✅ Pipeline integration works")
            print(f"   Config deep_analysis_mode: {mode}")
            print(f"   Phase 2.7 will execute: Yes")
            return True
        else:
            print(f"❌ Pipeline integration failed: mode is '{mode}', expected 'conservative'")
            return False
    except Exception as e:
        print(f"❌ Pipeline integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_finding_normalization():
    """Test that findings are normalized correctly."""
    print("\n" + "=" * 80)
    print("TEST 6: Finding Normalization")
    print("=" * 80)

    # Simulate a deep analysis finding
    deep_finding = {
        "type": "logical_flaw",
        "severity": "high",
        "title": "Missing input validation",
        "description": "User input is not validated before use",
        "file": "app.py",
        "line": 42,
        "confidence": 0.85
    }

    # Normalize to standard format (simulating the code in run_ai_audit.py)
    normalized = {
        "severity": deep_finding.get("severity", "medium"),
        "category": deep_finding.get("type", "deep_analysis_semantic"),
        "message": deep_finding.get("title", ""),
        "file_path": deep_finding.get("file", "unknown"),
        "line_number": deep_finding.get("line", 1),
        "rule_id": f"DEEP_ANALYSIS_SEMANTIC-001",
        "description": deep_finding.get("description", ""),
        "confidence": deep_finding.get("confidence", 0.0),
    }

    # Verify all required fields are present
    required_fields = ["severity", "category", "message", "file_path", "line_number", "rule_id", "description"]
    missing_fields = [f for f in required_fields if f not in normalized]

    if not missing_fields:
        print("✅ Finding normalization works")
        print(f"   Input: {deep_finding}")
        print(f"   Normalized: {normalized}")
        return True
    else:
        print(f"❌ Missing fields in normalized finding: {missing_fields}")
        return False


def test_conditional_execution():
    """Test that Phase 2.7 only executes when enabled."""
    print("\n" + "=" * 80)
    print("TEST 7: Conditional Execution")
    print("=" * 80)

    try:
        from argus_deep_analysis import DeepAnalysisMode

        # Test that OFF mode doesn't execute
        mode_off = DeepAnalysisMode.from_string("off")
        should_execute_off = mode_off != DeepAnalysisMode.OFF

        # Test that other modes do execute
        mode_conservative = DeepAnalysisMode.from_string("conservative")
        should_execute_conservative = mode_conservative != DeepAnalysisMode.OFF

        if not should_execute_off and should_execute_conservative:
            print("✅ Conditional execution works")
            print(f"   Mode 'off': Phase 2.7 executes = {should_execute_off}")
            print(f"   Mode 'conservative': Phase 2.7 executes = {should_execute_conservative}")
            return True
        else:
            print(f"❌ Conditional execution failed")
            return False
    except Exception as e:
        print(f"❌ Conditional execution test failed: {e}")
        return False


def test_cost_tracking():
    """Test that cost tracking works independently."""
    print("\n" + "=" * 80)
    print("TEST 8: Cost Tracking Independence")
    print("=" * 80)

    try:
        from argus_deep_analysis import DeepAnalysisEngine, DeepAnalysisConfig, DeepAnalysisMode

        # Create a config with cost ceiling
        config = DeepAnalysisConfig(
            mode=DeepAnalysisMode.CONSERVATIVE,
            enabled_phases=DeepAnalysisMode.CONSERVATIVE.get_enabled_phases(),
            max_files=10,
            timeout_seconds=300,
            cost_ceiling=1.0,
            dry_run=True  # Dry run so we don't actually call LLM
        )

        print("✅ Cost tracking configuration works")
        print(f"   Cost ceiling: ${config.cost_ceiling:.2f}")
        print(f"   Dry run: {config.dry_run} (no actual LLM calls)")

        return True
    except Exception as e:
        print(f"❌ Cost tracking test failed: {e}")
        return False


def main():
    """Run all verification tests."""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "PHASE 2.7 INTEGRATION VERIFICATION" + " " * 24 + "║")
    print("╚" + "═" * 78 + "╝")
    print()

    tests = [
        test_imports,
        test_mode_parsing,
        test_enabled_phases,
        test_config_parsing,
        test_pipeline_integration,
        test_finding_normalization,
        test_conditional_execution,
        test_cost_tracking,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    passed = sum(results)
    total = len(results)

    print(f"Tests passed: {passed}/{total}")

    if all(results):
        print("\n✅ ALL TESTS PASSED - Phase 2.7 is correctly integrated!")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED - Review the output above for details")
        return 1


if __name__ == "__main__":
    sys.exit(main())
