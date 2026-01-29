#!/usr/bin/env python3
"""
Performance Benchmark for AST-based Deduplication
Compares old line-bucket approach vs. new AST-based approach
"""

import json
import tempfile
import time
from pathlib import Path
from typing import List, Dict

from ast_deduplicator import ASTDeduplicator


def create_test_python_file(num_functions: int = 10) -> str:
    """Create a test Python file with multiple functions"""
    lines = ['"""Test module for benchmarking"""', '']

    for i in range(num_functions):
        lines.extend([
            f'def function_{i}():',
            f'    """Function {i} with multiple lines"""',
            f'    x = {i}',
            '    y = x * 2',
            '    z = y + 1',
            '    result = process(z)',
            '    formatted = format_result(result)',
            '    validated = validate(formatted)',
            '    logged = log_result(validated)',
            '    return logged',
            '',
        ])

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('\n'.join(lines))
        return f.name


def create_test_findings(file_path: str, num_findings: int = 100) -> List[Dict]:
    """Create test findings spread across the file"""
    findings = []

    for i in range(num_findings):
        # Distribute findings across different lines
        # Some in same function (lines 3-12, 14-23, etc.)
        line_number = (i % 10) * 11 + 3 + (i // 10)

        findings.append({
            "file_path": file_path,
            "line_number": line_number,
            "rule_id": f"rule-{i % 5}",  # 5 different rule types
            "severity": "high",
            "message": f"Test finding {i}",
            "code_snippet": f"line {line_number} code"
        })

    return findings


def benchmark_line_bucket_dedup(findings: List[Dict]) -> Dict:
    """Benchmark old line bucket deduplication"""
    start_time = time.time()

    grouped = {}
    for finding in findings:
        file_path = finding.get("file_path", "unknown")
        line = finding.get("line_number", 0)
        rule_id = finding.get("rule_id", "unknown")

        # Old approach: 10-line buckets
        line_bucket = (line // 10) * 10
        key = f"{file_path}:{rule_id}:L{line_bucket}"

        if key not in grouped:
            grouped[key] = []
        grouped[key].append(finding)

    elapsed = time.time() - start_time

    return {
        "method": "line_bucket",
        "num_findings": len(findings),
        "num_groups": len(grouped),
        "time_seconds": elapsed,
        "findings_per_second": len(findings) / elapsed if elapsed > 0 else 0
    }


def benchmark_ast_dedup(findings: List[Dict]) -> Dict:
    """Benchmark new AST-based deduplication"""
    deduplicator = ASTDeduplicator()
    start_time = time.time()

    grouped = {}
    for finding in findings:
        # New approach: AST-based
        key = deduplicator.create_dedup_key(finding)

        if key not in grouped:
            grouped[key] = []
        grouped[key].append(finding)

    elapsed = time.time() - start_time

    return {
        "method": "ast_based",
        "num_findings": len(findings),
        "num_groups": len(grouped),
        "time_seconds": elapsed,
        "findings_per_second": len(findings) / elapsed if elapsed > 0 else 0
    }


def benchmark_dedup_accuracy(findings: List[Dict]) -> Dict:
    """Compare deduplication accuracy between methods"""
    deduplicator = ASTDeduplicator()

    # Line bucket grouping
    line_bucket_groups = {}
    for finding in findings:
        file_path = finding.get("file_path", "unknown")
        line = finding.get("line_number", 0)
        rule_id = finding.get("rule_id", "unknown")
        line_bucket = (line // 10) * 10
        key = f"{file_path}:{rule_id}:L{line_bucket}"

        if key not in line_bucket_groups:
            line_bucket_groups[key] = []
        line_bucket_groups[key].append(finding)

    # AST-based grouping
    ast_groups = {}
    for finding in findings:
        key = deduplicator.create_dedup_key(finding)
        if key not in ast_groups:
            ast_groups[key] = []
        ast_groups[key].append(finding)

    # Calculate statistics
    line_bucket_sizes = [len(g) for g in line_bucket_groups.values()]
    ast_sizes = [len(g) for g in ast_groups.values()]

    return {
        "line_bucket_groups": len(line_bucket_groups),
        "ast_groups": len(ast_groups),
        "line_bucket_avg_size": sum(line_bucket_sizes) / len(line_bucket_sizes) if line_bucket_sizes else 0,
        "ast_avg_size": sum(ast_sizes) / len(ast_sizes) if ast_sizes else 0,
        "improvement_pct": (len(line_bucket_groups) - len(ast_groups)) / len(line_bucket_groups) * 100 if line_bucket_groups else 0
    }


def run_benchmark_suite():
    """Run complete benchmark suite"""
    print("=" * 70)
    print("AST-based Deduplication Performance Benchmark")
    print("=" * 70)
    print()

    # Create test file
    print("Creating test file...")
    test_file = create_test_python_file(num_functions=50)
    print(f"Test file: {test_file}")
    print()

    # Test with different numbers of findings
    test_sizes = [10, 50, 100, 500, 1000]
    results = []

    for size in test_sizes:
        print(f"Benchmarking with {size} findings...")

        findings = create_test_findings(test_file, num_findings=size)

        # Benchmark line bucket
        lb_result = benchmark_line_bucket_dedup(findings)
        print(f"  Line Bucket: {lb_result['num_groups']} groups, "
              f"{lb_result['time_seconds']:.4f}s, "
              f"{lb_result['findings_per_second']:.0f} findings/sec")

        # Benchmark AST-based
        ast_result = benchmark_ast_dedup(findings)
        print(f"  AST-based:   {ast_result['num_groups']} groups, "
              f"{ast_result['time_seconds']:.4f}s, "
              f"{ast_result['findings_per_second']:.0f} findings/sec")

        # Calculate improvement
        speedup = lb_result['time_seconds'] / ast_result['time_seconds'] if ast_result['time_seconds'] > 0 else 0
        group_reduction = (lb_result['num_groups'] - ast_result['num_groups']) / lb_result['num_groups'] * 100 if lb_result['num_groups'] > 0 else 0

        print(f"  Speedup: {speedup:.2f}x, Group reduction: {group_reduction:.1f}%")
        print()

        results.append({
            "size": size,
            "line_bucket": lb_result,
            "ast_based": ast_result,
            "speedup": speedup,
            "group_reduction_pct": group_reduction
        })

    # Accuracy comparison
    print("\nAccuracy Comparison (1000 findings):")
    print("-" * 70)
    findings = create_test_findings(test_file, num_findings=1000)
    accuracy = benchmark_dedup_accuracy(findings)

    print(f"Line Bucket Groups: {accuracy['line_bucket_groups']}")
    print(f"AST-based Groups:   {accuracy['ast_groups']}")
    print(f"Average Group Size (Line Bucket): {accuracy['line_bucket_avg_size']:.2f}")
    print(f"Average Group Size (AST-based):   {accuracy['ast_avg_size']:.2f}")
    print(f"Reduction in Groups: {accuracy['improvement_pct']:.1f}%")
    print()

    # Save results
    output_file = Path(__file__).parent.parent / "benchmark_results.json"
    with open(output_file, 'w') as f:
        json.dump({
            "benchmark_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_file": test_file,
            "results": results,
            "accuracy": accuracy
        }, f, indent=2)

    print(f"Results saved to: {output_file}")
    print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    avg_speedup = sum(r['speedup'] for r in results) / len(results)
    avg_reduction = sum(r['group_reduction_pct'] for r in results) / len(results)

    print(f"Average Speedup:       {avg_speedup:.2f}x")
    print(f"Average Group Reduction: {avg_reduction:.1f}%")
    print()

    if avg_speedup < 0.8:
        print("⚠️  WARNING: AST-based approach is slower than line bucket")
        print("   This may be acceptable given improved accuracy")
    elif avg_speedup > 1.2:
        print("✓ AST-based approach is faster than line bucket")
    else:
        print("✓ Performance is comparable between approaches")

    if avg_reduction > 10:
        print(f"✓ Significant improvement in grouping accuracy ({avg_reduction:.0f}% fewer groups)")
    else:
        print("⚠️  Limited improvement in grouping accuracy")

    print()

    # Cleanup
    Path(test_file).unlink(missing_ok=True)


if __name__ == "__main__":
    run_benchmark_suite()
