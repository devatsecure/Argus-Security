#!/usr/bin/env python3
"""
Performance Benchmark Script for Argus Caching and Progress Tracking

This script provides a comprehensive benchmark of:
1. Cache manager performance (hits vs misses)
2. Progress tracker in different environments (terminal vs CI)
3. Real-world scanner workflow performance with caching
4. Performance metrics and analysis
"""

import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cache_manager import CacheManager, print_cache_stats
from progress_tracker import ProgressTracker


def create_test_files(count: int = 5) -> List[str]:
    """Create test Python files"""
    files = []
    for i in range(count):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py") as f:
            f.write(f"# Test file {i}\n")
            f.write("# Python code\n" * 50)
            f.flush()
            files.append(f.name)
    return files


def cleanup_files(files: List[str]) -> None:
    """Clean up test files"""
    for f in files:
        if os.path.exists(f):
            os.unlink(f)


class PerformanceBenchmark:
    """Main benchmark suite"""

    def __init__(self, verbose: bool = True):
        """Initialize benchmark"""
        self.verbose = verbose
        self.results: Dict[str, any] = {}
        self.temp_cache_dir = tempfile.mkdtemp(prefix="benchmark_cache_")

    def cleanup(self) -> None:
        """Clean up resources"""
        if os.path.exists(self.temp_cache_dir):
            shutil.rmtree(self.temp_cache_dir)

    def log(self, message: str) -> None:
        """Log message if verbose"""
        if self.verbose:
            print(message)

    def print_section(self, title: str) -> None:
        """Print a section header"""
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}\n")

    def benchmark_cache_hit_performance(self) -> Dict[str, float]:
        """Benchmark cache hit vs miss performance"""
        self.print_section("1. Cache Hit Performance Benchmark")

        cache_manager = CacheManager(cache_dir=self.temp_cache_dir)

        # Create test file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py") as f:
            f.write("# Test file\n" * 100)
            f.flush()
            test_file = f.name

        try:
            test_results = {
                "findings": [{"id": i, "severity": "high"} for i in range(20)],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            # Measure cache miss (set operation)
            self.log("Measuring cache miss (set operation)...")
            times_miss = []
            for _ in range(5):
                start = time.perf_counter()
                cache_manager.set_cached_result(
                    test_file,
                    "benchmark-scanner",
                    test_results
                )
                times_miss.append(time.perf_counter() - start)

            avg_miss = sum(times_miss) / len(times_miss)
            self.log(f"  Average miss time: {avg_miss*1000:.2f}ms")

            # Measure cache hit (get operation)
            self.log("Measuring cache hit (get operation)...")
            times_hit = []
            for _ in range(100):  # More iterations for hit
                start = time.perf_counter()
                cached = cache_manager.get_cached_result(
                    test_file,
                    "benchmark-scanner"
                )
                times_hit.append(time.perf_counter() - start)

            avg_hit = sum(times_hit) / len(times_hit)
            self.log(f"  Average hit time:  {avg_hit*1000:.2f}ms")

            speedup = avg_miss / avg_hit
            self.log(f"  Speedup: {speedup:.1f}x faster for cache hits")

            stats = cache_manager.get_cache_stats()
            self.log(f"\nCache Statistics:")
            self.log(f"  Hits: {stats['hits']}")
            self.log(f"  Misses: {stats['misses']}")
            self.log(f"  Hit Rate: {stats['hit_rate']:.1%}")
            self.log(f"  Cache Size: {stats['total_size_mb']:.2f} MB")

            return {
                "avg_miss_ms": avg_miss * 1000,
                "avg_hit_ms": avg_hit * 1000,
                "speedup": speedup,
                "hit_rate": stats['hit_rate'],
                "cache_size_mb": stats['total_size_mb']
            }

        finally:
            os.unlink(test_file)

    def benchmark_cache_directory_structure(self) -> Dict[str, any]:
        """Benchmark and verify cache directory structure"""
        self.print_section("2. Cache Directory Structure Verification")

        cache_manager = CacheManager(cache_dir=self.temp_cache_dir)
        test_files = create_test_files(3)

        try:
            # Create cache entries for different scanners
            scanners = ["semgrep", "trivy", "trufflehog"]
            test_results = {"data": "test", "timestamp": datetime.now(timezone.utc).isoformat()}

            for test_file in test_files:
                for scanner in scanners:
                    cache_manager.set_cached_result(test_file, scanner, test_results)

            # Check directory structure
            cache_dir = Path(self.temp_cache_dir)
            self.log(f"Cache directory: {cache_dir}")
            self.log(f"Structure:")

            total_files = 0
            for scanner_dir in cache_dir.glob("*"):
                if scanner_dir.is_dir():
                    cache_files = list(scanner_dir.glob("*.json"))
                    count = len(cache_files)
                    total_files += count
                    self.log(f"  {scanner_dir.name}/: {count} files")

            self.log(f"\nTotal cache entries: {total_files}")

            stats = cache_manager.get_cache_stats()
            return {
                "total_entries": stats["total_entries"],
                "total_size_mb": stats["total_size_mb"],
                "scanners": list(stats["scanners"].keys())
            }

        finally:
            cleanup_files(test_files)

    def benchmark_progress_tracker_modes(self) -> Dict[str, float]:
        """Benchmark progress tracker in different modes"""
        self.print_section("3. Progress Tracker Mode Comparison")

        # Terminal mode (rich enabled)
        self.log("Testing Terminal Mode (rich enabled)...")
        tracker_terminal = ProgressTracker(enable_rich=True)
        tracker_terminal.start()

        start = time.perf_counter()
        scan_id = tracker_terminal.start_scan("TestScanner", total_files=50)
        for i in range(50):
            tracker_terminal.update_progress(scan_id, advance=1)
            time.sleep(0.005)
        tracker_terminal.complete_scan(scan_id)
        tracker_terminal.stop()
        time_terminal = time.perf_counter() - start

        self.log(f"  Time: {time_terminal:.2f}s")
        self.log(f"  Files scanned: {tracker_terminal.stats['files_scanned']}")

        # CI mode (rich disabled)
        self.log("\nTesting CI Mode (rich disabled)...")
        tracker_ci = ProgressTracker(enable_rich=False)
        tracker_ci.start()

        start = time.perf_counter()
        scan_id = tracker_ci.start_scan("TestScanner", total_files=50)
        for i in range(50):
            tracker_ci.update_progress(scan_id, advance=1)
            time.sleep(0.005)
        tracker_ci.complete_scan(scan_id)
        tracker_ci.stop()
        time_ci = time.perf_counter() - start

        self.log(f"  Time: {time_ci:.2f}s")
        self.log(f"  Files scanned: {tracker_ci.stats['files_scanned']}")

        overhead = (time_terminal - time_ci) / time_ci * 100
        self.log(f"\nTerminal mode overhead: {overhead:.1f}%")

        return {
            "terminal_time_s": time_terminal,
            "ci_time_s": time_ci,
            "overhead_percent": overhead
        }

    def benchmark_progress_tracker_environment_detection(self) -> Dict[str, str]:
        """Benchmark environment detection"""
        self.print_section("4. Progress Tracker Environment Detection")

        # Test auto-detection
        tracker = ProgressTracker()
        self.log(f"Auto-detected rich mode: {tracker.use_rich}")

        # Test with CI environment variable
        os.environ["CI"] = "true"
        tracker_ci = ProgressTracker()
        self.log(f"With CI=true: {tracker_ci.use_rich} (should be False)")

        del os.environ["CI"]

        # Test with GitHub Actions
        os.environ["GITHUB_ACTIONS"] = "true"
        tracker_gh = ProgressTracker()
        self.log(f"With GITHUB_ACTIONS=true: {tracker_gh.use_rich} (should be False)")

        del os.environ["GITHUB_ACTIONS"]

        return {
            "auto_detected": str(tracker.use_rich),
            "ci_detected": str(tracker_ci.use_rich),
            "github_actions_detected": str(tracker_gh.use_rich)
        }

    def benchmark_real_world_workflow(self) -> Dict[str, any]:
        """Benchmark a real-world scanner workflow"""
        self.print_section("5. Real-World Workflow Benchmark (2 Runs with Caching)")

        cache_manager = CacheManager(cache_dir=self.temp_cache_dir)
        test_files = create_test_files(3)

        try:
            results = {}

            for run in range(1, 3):
                self.log(f"\nRun {run}:")
                tracker = ProgressTracker(enable_rich=False)
                tracker.start()

                run_start = time.perf_counter()
                scanners = ["semgrep", "trivy", "trufflehog"]

                for scanner in scanners:
                    scan_id = tracker.start_scan(scanner.title(), total_files=len(test_files))

                    for test_file in test_files:
                        # Try cache
                        cached = cache_manager.get_cached_result(test_file, scanner)

                        if cached is None:
                            # Cache miss - simulate scan
                            time.sleep(0.02)
                            scan_results = {
                                "scanner": scanner,
                                "findings": [{"id": i} for i in range(5)],
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                            cache_manager.set_cached_result(test_file, scanner, scan_results)
                        else:
                            # Cache hit - fast
                            time.sleep(0.001)

                        tracker.update_progress(scan_id, advance=1)

                    tracker.complete_scan(scan_id)

                run_time = time.perf_counter() - run_start
                results[f"run_{run}_time_s"] = run_time

                self.log(f"  Time: {run_time:.2f}s")

                tracker.stop()

            speedup = results["run_1_time_s"] / results["run_2_time_s"]
            results["speedup"] = speedup

            self.log(f"\nSpeedup (Run 1 → Run 2): {speedup:.1f}x")

            cache_stats = cache_manager.get_cache_stats()
            self.log(f"\nCache Statistics:")
            self.log(f"  Hits: {cache_stats['hits']}")
            self.log(f"  Misses: {cache_stats['misses']}")
            self.log(f"  Hit Rate: {cache_stats['hit_rate']:.1%}")

            results["cache_hits"] = cache_stats["hits"]
            results["cache_misses"] = cache_stats["misses"]
            results["cache_hit_rate"] = cache_stats["hit_rate"]

            return results

        finally:
            cleanup_files(test_files)

    def benchmark_multi_scanner_scenario(self) -> Dict[str, any]:
        """Benchmark multiple scanners in parallel"""
        self.print_section("6. Multi-Scanner Scenario (5 Files × 4 Scanners)")

        cache_manager = CacheManager(cache_dir=self.temp_cache_dir)
        test_files = create_test_files(5)
        tracker = ProgressTracker(enable_rich=False)

        try:
            tracker.start()
            start_time = time.perf_counter()

            scanners = ["semgrep", "trivy", "trufflehog", "checkov"]

            for scanner in scanners:
                scan_id = tracker.start_scan(scanner.title(), total_files=len(test_files))

                for test_file in test_files:
                    cached = cache_manager.get_cached_result(test_file, scanner)

                    if cached is None:
                        time.sleep(0.015)
                        results = {
                            "findings": [],
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        cache_manager.set_cached_result(test_file, scanner, results)
                    else:
                        time.sleep(0.001)

                    tracker.update_progress(scan_id, advance=1)

                tracker.complete_scan(scan_id)

            total_time = time.perf_counter() - start_time
            tracker.stop()

            self.log(f"Total time: {total_time:.2f}s")
            self.log(f"Files scanned: {tracker.stats['files_scanned']}")
            self.log(f"Scanners completed: {tracker.stats['scanners_completed']}")

            cache_stats = cache_manager.get_cache_stats()
            self.log(f"Cache entries: {cache_stats['total_entries']}")

            return {
                "total_time_s": total_time,
                "files_scanned": tracker.stats["files_scanned"],
                "scanners_completed": tracker.stats["scanners_completed"],
                "cache_entries": cache_stats["total_entries"]
            }

        finally:
            cleanup_files(test_files)

    def run_all_benchmarks(self) -> Dict[str, any]:
        """Run all benchmarks"""
        print("\n" + "="*70)
        print("  ARGUS PERFORMANCE BENCHMARK")
        print("="*70)
        print(f"  Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Cache Directory: {self.temp_cache_dir}")
        print("="*70)

        try:
            results = {}

            results["cache_hit_performance"] = self.benchmark_cache_hit_performance()
            results["cache_directory"] = self.benchmark_cache_directory_structure()
            results["progress_tracker_modes"] = self.benchmark_progress_tracker_modes()
            results["environment_detection"] = self.benchmark_progress_tracker_environment_detection()
            results["real_world_workflow"] = self.benchmark_real_world_workflow()
            results["multi_scanner"] = self.benchmark_multi_scanner_scenario()

            # Print summary
            self.print_section("BENCHMARK SUMMARY")

            print("Cache Hit Performance:")
            print(f"  Miss time: {results['cache_hit_performance']['avg_miss_ms']:.2f}ms")
            print(f"  Hit time: {results['cache_hit_performance']['avg_hit_ms']:.2f}ms")
            print(f"  Speedup: {results['cache_hit_performance']['speedup']:.1f}x")
            print(f"  Hit rate: {results['cache_hit_performance']['hit_rate']:.1%}")

            print("\nProgress Tracker Modes:")
            print(f"  Terminal mode: {results['progress_tracker_modes']['terminal_time_s']:.2f}s")
            print(f"  CI mode: {results['progress_tracker_modes']['ci_time_s']:.2f}s")
            print(f"  Overhead: {results['progress_tracker_modes']['overhead_percent']:.1f}%")

            print("\nReal-World Workflow:")
            print(f"  Run 1 (cache misses): {results['real_world_workflow']['run_1_time_s']:.2f}s")
            print(f"  Run 2 (cache hits): {results['real_world_workflow']['run_2_time_s']:.2f}s")
            print(f"  Speedup: {results['real_world_workflow']['speedup']:.1f}x")

            print("\nMulti-Scanner Scenario:")
            print(f"  Total time: {results['multi_scanner']['total_time_s']:.2f}s")
            print(f"  Files scanned: {results['multi_scanner']['files_scanned']}")
            print(f"  Scanners: {results['multi_scanner']['scanners_completed']}")

            print("\n" + "="*70)
            print(f"  End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("="*70 + "\n")

            return results

        finally:
            self.cleanup()


def main() -> int:
    """Main entry point"""
    benchmark = PerformanceBenchmark(verbose=True)
    results = benchmark.run_all_benchmarks()

    # Save results to JSON
    output_file = "performance_benchmark_results.json"
    with open(output_file, "w") as f:
        # Convert non-serializable types
        json_results = {}
        for key, value in results.items():
            if isinstance(value, dict):
                json_results[key] = {}
                for k, v in value.items():
                    if isinstance(v, (int, float, str, bool, list, dict)):
                        json_results[key][k] = v
                    else:
                        json_results[key][k] = str(v)
            else:
                json_results[key] = value

        json.dump(json_results, f, indent=2)

    print(f"\nResults saved to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
