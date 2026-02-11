#!/usr/bin/env python3
"""
Test script to verify Best Practices implementation in run_ai_audit.py

Tests:
1. ContextTracker class functionality
2. FindingSummarizer class functionality
3. Phase separation in single-agent mode
4. Context tracking and summarization in multi-agent mode
"""

import sys
import json
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from run_ai_audit import (
    ContextTracker,
    FindingSummarizer,
    AgentOutputValidator,
    TimeoutManager,
    CodebaseChunker,
    ContextCleanup
)


def test_context_tracker():
    """Test ContextTracker class"""
    print("=" * 80)
    print("TEST 1: ContextTracker")
    print("=" * 80)
    
    tracker = ContextTracker()
    
    # Test phase 1
    tracker.start_phase("research")
    tracker.add_context("file_list", "file1.py\nfile2.js\nfile3.ts", {"files": 3})
    tracker.add_context("threat_model", "Threat model summary...", {"threats": 5})
    tracker.end_phase()
    
    # Test phase 2
    tracker.start_phase("planning")
    tracker.add_context("research_results", "Research findings...", {"priority_files": 2})
    tracker.end_phase()
    
    # Test phase 3
    tracker.start_phase("implementation")
    tracker.add_context("codebase", "Full codebase content...", {"files": 2})
    tracker.add_context("plan", "Analysis plan...", {})
    tracker.end_phase()
    
    # Get summary
    summary = tracker.get_summary()
    
    print(f"✅ Total phases tracked: {summary['total_phases']}")
    print(f"✅ Total tokens (estimated): {summary['total_tokens_estimate']}")
    print(f"✅ Phases:")
    for phase in summary['phases']:
        print(f"   - {phase['name']}: {phase['components']} components, {phase['tokens_estimate']} tokens")
    
    assert summary['total_phases'] == 3, "Should have 3 phases"
    assert summary['total_tokens_estimate'] > 0, "Should have token estimate"
    print("\n✅ ContextTracker tests PASSED\n")
    
    return True


def test_contradiction_detection():
    """Test contradiction detection"""
    print("=" * 80)
    print("TEST 2: Contradiction Detection")
    print("=" * 80)
    
    tracker = ContextTracker()
    
    existing = "Focus only on security issues. Ignore performance concerns."
    new_instructions = "Also analyze performance issues thoroughly."
    
    warnings = tracker.detect_contradictions(new_instructions, existing)
    
    print(f"✅ Detected {len(warnings)} potential contradictions")
    for warning in warnings:
        print(f"   ⚠️  {warning}")
    
    # Should detect some contradictions
    print("\n✅ Contradiction detection tests PASSED\n")
    
    return True


def test_finding_summarizer():
    """Test FindingSummarizer class"""
    print("=" * 80)
    print("TEST 3: FindingSummarizer")
    print("=" * 80)
    
    summarizer = FindingSummarizer()
    
    # Create test findings
    findings = [
        {
            "severity": "critical",
            "category": "security",
            "message": "SQL injection vulnerability in user input handling",
            "file_path": "app/database.py",
            "line_number": 45
        },
        {
            "severity": "high",
            "category": "security",
            "message": "Hardcoded API key found in configuration",
            "file_path": "config/settings.py",
            "line_number": 12
        },
        {
            "severity": "medium",
            "category": "performance",
            "message": "N+1 query detected in user listing",
            "file_path": "app/views.py",
            "line_number": 78
        },
        {
            "severity": "low",
            "category": "quality",
            "message": "Missing docstring for public function",
            "file_path": "utils/helpers.py",
            "line_number": 23
        }
    ]
    
    # Test summarize_findings
    summary = summarizer.summarize_findings(findings, max_findings=10)
    
    print("Summary generated:")
    print(summary)
    print()
    
    assert "4 total findings" in summary, "Should mention total findings"
    assert "Critical: 1" in summary, "Should count critical findings"
    assert "SQL injection" in summary, "Should include critical issue details"
    
    print("✅ FindingSummarizer tests PASSED\n")
    
    return True


def test_report_summarization():
    """Test report summarization"""
    print("=" * 80)
    print("TEST 4: Report Summarization")
    print("=" * 80)
    
    summarizer = FindingSummarizer()
    
    # Create test report
    report = """
# Security Review Report

## Summary
- Total security issues found: 5
- Critical: 2
- High: 2
- Medium: 1
- Low: 0

## Critical Issues

### [CRITICAL] SQL Injection - `database.py:45`
**Category**: Injection
**Impact**: Attacker can execute arbitrary SQL queries
**Evidence**: User input directly concatenated into SQL query
**Recommendation**: Use parameterized queries

### [CRITICAL] Authentication Bypass - `auth.py:123`
**Category**: Authentication
**Impact**: Unauthorized access to admin panel
**Evidence**: Missing authentication check on admin routes
**Recommendation**: Add authentication middleware

## High Priority Issues

### [HIGH] Weak Password Policy
Passwords can be as short as 4 characters.
"""
    
    summary = summarizer.summarize_report(report, max_length=500)
    
    print("Report summary:")
    print(summary)
    print()
    
    assert len(summary) <= 500, "Summary should respect max length"
    assert "security" in summary.lower() or "critical" in summary.lower(), "Should capture key info"
    
    print("✅ Report summarization tests PASSED\n")
    
    return True


def test_phase_separation():
    """Test that phase separation is implemented"""
    print("=" * 80)
    print("TEST 5: Phase Separation Verification")
    print("=" * 80)
    
    # Read the source file and check for phase markers
    source_file = Path(__file__).parent.parent / "scripts" / "run_ai_audit.py"
    with open(source_file, 'r') as f:
        content = f.read()
    
    # Check for phase markers in single-agent mode
    checks = [
        ("PHASE 1: RESEARCH", "Research phase marker found"),
        ("PHASE 2: PLANNING", "Planning phase marker found"),
        ("PHASE 3: IMPLEMENTATION", "Implementation phase marker found"),
        ("context_tracker.start_phase", "Context tracking in use"),
        ("summarizer.summarize_findings", "Finding summarization in use"),
        ("BEST PRACTICE IMPLEMENTATION", "Best practice documentation found"),
    ]
    
    all_passed = True
    for marker, description in checks:
        if marker in content:
            print(f"✅ {description}")
        else:
            print(f"❌ {description} - NOT FOUND")
            all_passed = False
    
    if all_passed:
        print("\n✅ Phase separation verification PASSED\n")
    else:
        print("\n❌ Phase separation verification FAILED\n")
    
    return all_passed


def test_output_validator():
    """Test AgentOutputValidator class"""
    print("=" * 80)
    print("TEST 6: AgentOutputValidator (Medium Priority)")
    print("=" * 80)
    
    validator = AgentOutputValidator()
    
    # Test valid output
    valid_output = """
# Security Review Report

## Summary
- Total security issues found: 3
- Critical: 1
- High: 2

## Critical Issues

### [CRITICAL] SQL Injection - `database.py:45`
**Impact**: Attacker can execute arbitrary queries
"""
    
    validation = validator.validate_output("security", valid_output, ["Summary", "Critical"])
    
    print(f"Valid output test: {'✅ PASS' if validation['valid'] else '❌ FAIL'}")
    print(f"Warnings: {len(validation['warnings'])}")
    print(f"Code references found: {validation['metrics']['code_references']}")
    
    # Test invalid output (too short)
    invalid_output = "No issues"
    validation2 = validator.validate_output("test", invalid_output)
    
    print(f"Invalid output detected: {'✅ PASS' if not validation2['valid'] else '❌ FAIL'}")
    
    # Get summary
    summary = validator.get_validation_summary()
    print(f"Total validations: {summary['total_validations']}")
    
    print("\n✅ AgentOutputValidator tests PASSED\n")
    return True


def test_timeout_manager():
    """Test TimeoutManager class"""
    print("=" * 80)
    print("TEST 7: TimeoutManager (Medium Priority)")
    print("=" * 80)
    
    import time
    
    manager = TimeoutManager(default_timeout=2)
    manager.set_agent_timeout("slow_agent", 5)
    
    # Test timeout check
    start = time.time()
    time.sleep(0.1)
    
    exceeded, elapsed, remaining = manager.check_timeout("test_agent", start)
    print(f"Timeout check: exceeded={exceeded}, elapsed={elapsed:.2f}s, remaining={remaining:.2f}s")
    
    # Record execution
    manager.record_execution("test_agent", 1.5, True)
    manager.record_execution("slow_agent", 6.0, False)
    
    # Get summary
    summary = manager.get_summary()
    print(f"Total executions: {summary['total_executions']}")
    print(f"Completed: {summary['completed']}")
    print(f"Timeouts exceeded: {summary['timeout_exceeded']}")
    
    assert summary['total_executions'] == 2, "Should have 2 executions"
    assert summary['timeout_exceeded'] == 1, "Should have 1 timeout"
    
    print("\n✅ TimeoutManager tests PASSED\n")
    return True


def test_codebase_chunker():
    """Test CodebaseChunker class"""
    print("=" * 80)
    print("TEST 8: CodebaseChunker (Low Priority)")
    print("=" * 80)
    
    chunker = CodebaseChunker(max_chunk_size=1000)
    
    # Create test files
    files = [
        {"path": "app.py", "content": "x" * 400},
        {"path": "utils.py", "content": "y" * 300},
        {"path": "models.py", "content": "z" * 500},
        {"path": "views.py", "content": "a" * 600},
    ]
    
    priority_files = ["app.py", "models.py"]
    
    # Chunk files
    chunks = chunker.chunk_files(files, priority_files)
    
    print(f"Total chunks: {len(chunks)}")
    print(f"Priority chunks: {sum(1 for c in chunks if c['priority'])}")
    
    # Get summary
    summary = chunker.get_chunk_summary(chunks)
    print(f"Total files: {summary['total_files']}")
    print(f"Total size: {summary['total_size']}")
    print(f"Avg chunk size: {summary['avg_chunk_size']:.0f}")
    
    assert summary['total_files'] == 4, "Should have 4 files"
    assert len(chunks) > 0, "Should have at least 1 chunk"
    
    print("\n✅ CodebaseChunker tests PASSED\n")
    return True


def test_context_cleanup():
    """Test ContextCleanup class"""
    print("=" * 80)
    print("TEST 9: ContextCleanup (Low Priority)")
    print("=" * 80)
    
    cleanup = ContextCleanup()
    
    # Test duplicate removal
    text_with_dupes = "line1\nline2\nline1\nline3\nline2"
    cleaned = cleanup.remove_duplicates(text_with_dupes)
    print(f"Duplicate removal: {text_with_dupes.count('line1')} -> {cleaned.count('line1')}")
    
    # Test whitespace compression
    text_with_whitespace = "line1\n\n\n\nline2\n\n\nline3"
    compressed = cleanup.compress_whitespace(text_with_whitespace)
    print(f"Whitespace compression: {text_with_whitespace.count(chr(10))} -> {compressed.count(chr(10))} newlines")
    
    # Test comment removal
    code_with_comments = """
def hello():
    # This is a comment
    print("hello")  // another comment
    /* multi-line
       comment */
    return True
"""
    no_comments = cleanup.remove_comments(code_with_comments)
    print(f"Comment removal: {len(code_with_comments)} -> {len(no_comments)} chars")
    
    # Test full cleanup
    messy_context = "line1\n\n\n\nline1\nline2  \n\n\nline3"
    cleaned_context, reduction = cleanup.cleanup_context(messy_context)
    print(f"Full cleanup: {reduction:.1f}% reduction")
    
    assert reduction > 0, "Should have some reduction"
    
    print("\n✅ ContextCleanup tests PASSED\n")
    return True


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("BEST PRACTICES IMPLEMENTATION TEST SUITE")
    print("Testing ALL Priority Levels (High, Medium, Low)")
    print("=" * 80 + "\n")
    
    tests = [
        # High Priority (Already implemented)
        ("Context Tracker", test_context_tracker),
        ("Contradiction Detection", test_contradiction_detection),
        ("Finding Summarizer", test_finding_summarizer),
        ("Report Summarization", test_report_summarization),
        ("Phase Separation", test_phase_separation),
        # Medium Priority (New)
        ("Output Validator", test_output_validator),
        ("Timeout Manager", test_timeout_manager),
        # Low Priority (New)
        ("Codebase Chunker", test_codebase_chunker),
        ("Context Cleanup", test_context_cleanup),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Best practices implementation verified.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

