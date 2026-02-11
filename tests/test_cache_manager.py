#!/usr/bin/env python3
"""
Test Suite for CacheManager

Comprehensive tests for the intelligent caching system:
- Cache hit/miss scenarios
- File content change detection
- Scanner version invalidation
- TTL expiration
- Thread safety
- Error handling (corrupt cache)
- Statistics tracking
"""

import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from cache_manager import CacheManager


class TestCacheManager(unittest.TestCase):
    """Test suite for CacheManager class"""

    def setUp(self):
        """Set up test fixtures"""
        # Create temporary directory for cache
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = os.path.join(self.temp_dir, ".test-cache")

        # Create temporary test file
        self.test_file = os.path.join(self.temp_dir, "test_file.py")
        with open(self.test_file, "w") as f:
            f.write("print('hello world')\n")

        # Initialize cache manager
        self.cache_manager = CacheManager(
            cache_dir=self.cache_dir,
            default_ttl_days=7
        )

    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary directory
        import shutil

        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_cache_initialization(self):
        """Test cache directory initialization"""
        self.assertTrue(os.path.exists(self.cache_dir))
        self.assertTrue(os.path.isdir(self.cache_dir))

    def test_file_hash_computation(self):
        """Test SHA256 hash computation"""
        hash1 = self.cache_manager._compute_file_hash(self.test_file)
        self.assertIsNotNone(hash1)
        self.assertEqual(len(hash1), 64)  # SHA256 hex digest length

        # Hash should be deterministic
        hash2 = self.cache_manager._compute_file_hash(self.test_file)
        self.assertEqual(hash1, hash2)

    def test_cache_miss(self):
        """Test cache miss scenario"""
        result = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )
        self.assertIsNone(result)

        # Check stats
        stats = self.cache_manager.get_cache_stats()
        self.assertEqual(stats["misses"], 1)
        self.assertEqual(stats["hits"], 0)

    def test_cache_hit(self):
        """Test cache hit scenario"""
        test_results = {"findings": [], "count": 0}

        # Set cache
        success = self.cache_manager.set_cached_result(
            self.test_file,
            "test-scanner",
            test_results
        )
        self.assertTrue(success)

        # Get cached result
        cached = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )
        self.assertIsNotNone(cached)
        self.assertEqual(cached, test_results)

        # Check stats
        stats = self.cache_manager.get_cache_stats()
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["sets"], 1)

    def test_cache_invalidation_on_file_change(self):
        """Test cache invalidation when file content changes"""
        test_results = {"findings": [], "count": 0}

        # Set cache for original file
        self.cache_manager.set_cached_result(
            self.test_file,
            "test-scanner",
            test_results
        )

        # Verify cache hit
        cached = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )
        self.assertIsNotNone(cached)

        # Modify file
        with open(self.test_file, "w") as f:
            f.write("print('modified content')\n")

        # Cache should be invalid now (miss because file hash changed)
        cached = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )
        self.assertIsNone(cached)

        # Check that we got a cache miss
        stats = self.cache_manager.get_cache_stats()
        self.assertGreaterEqual(stats["misses"], 1)

    def test_scanner_version_invalidation(self):
        """Test cache invalidation when scanner version changes"""
        test_results = {"findings": [], "count": 0}

        # Set cache with version 1.0
        self.cache_manager.set_cached_result(
            self.test_file,
            "test-scanner",
            test_results,
            scanner_version="1.0"
        )

        # Cache hit with same version
        cached = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner",
            scanner_version="1.0"
        )
        self.assertIsNotNone(cached)

        # Cache miss with different version
        cached = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner",
            scanner_version="2.0"
        )
        self.assertIsNone(cached)

    def test_ttl_expiration(self):
        """Test cache expiration based on TTL"""
        test_results = {"findings": [], "count": 0}

        # Set cache with 1 second TTL
        self.cache_manager.set_cached_result(
            self.test_file,
            "test-scanner",
            test_results,
            ttl_seconds=1
        )

        # Immediate cache hit
        cached = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )
        self.assertIsNotNone(cached)

        # Wait for expiration
        time.sleep(2)

        # Cache should be expired
        cached = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )
        self.assertIsNone(cached)

    def test_cache_validation_check(self):
        """Test is_cache_valid method"""
        test_results = {"findings": [], "count": 0}

        # Initially no cache
        self.assertFalse(
            self.cache_manager.is_cache_valid(
                self.test_file,
                "test-scanner"
            )
        )

        # Set cache
        self.cache_manager.set_cached_result(
            self.test_file,
            "test-scanner",
            test_results
        )

        # Should be valid
        self.assertTrue(
            self.cache_manager.is_cache_valid(
                self.test_file,
                "test-scanner"
            )
        )

    def test_clear_specific_scanner_cache(self):
        """Test clearing cache for specific scanner"""
        # Cache results for two scanners
        self.cache_manager.set_cached_result(
            self.test_file,
            "scanner-a",
            {"results": "a"}
        )
        self.cache_manager.set_cached_result(
            self.test_file,
            "scanner-b",
            {"results": "b"}
        )

        # Clear scanner-a only
        deleted = self.cache_manager.clear_cache(scanner_name="scanner-a")
        self.assertEqual(deleted, 1)

        # scanner-a should be cleared
        self.assertIsNone(
            self.cache_manager.get_cached_result(
                self.test_file,
                "scanner-a"
            )
        )

        # scanner-b should still exist
        self.assertIsNotNone(
            self.cache_manager.get_cached_result(
                self.test_file,
                "scanner-b"
            )
        )

    def test_clear_all_cache(self):
        """Test clearing all cache"""
        # Cache results for two scanners
        self.cache_manager.set_cached_result(
            self.test_file,
            "scanner-a",
            {"results": "a"}
        )
        self.cache_manager.set_cached_result(
            self.test_file,
            "scanner-b",
            {"results": "b"}
        )

        # Clear all
        deleted = self.cache_manager.clear_cache()
        self.assertEqual(deleted, 2)

        # Both should be cleared
        self.assertIsNone(
            self.cache_manager.get_cached_result(
                self.test_file,
                "scanner-a"
            )
        )
        self.assertIsNone(
            self.cache_manager.get_cached_result(
                self.test_file,
                "scanner-b"
            )
        )

    def test_clear_expired_entries(self):
        """Test clearing only expired cache entries"""
        # Create entry with short TTL
        self.cache_manager.set_cached_result(
            self.test_file,
            "short-ttl",
            {"results": "short"},
            ttl_seconds=1
        )

        # Create entry with long TTL
        test_file_2 = os.path.join(self.temp_dir, "test_file_2.py")
        with open(test_file_2, "w") as f:
            f.write("print('test 2')\n")

        self.cache_manager.set_cached_result(
            test_file_2,
            "long-ttl",
            {"results": "long"},
            ttl_seconds=3600
        )

        # Wait for short TTL to expire
        time.sleep(2)

        # Clear expired
        deleted = self.cache_manager.clear_expired()
        self.assertEqual(deleted, 1)

        # Short TTL should be gone
        self.assertIsNone(
            self.cache_manager.get_cached_result(
                self.test_file,
                "short-ttl"
            )
        )

        # Long TTL should still exist
        self.assertIsNotNone(
            self.cache_manager.get_cached_result(
                test_file_2,
                "long-ttl"
            )
        )

    def test_corrupt_cache_handling(self):
        """Test handling of corrupt cache files"""
        # Create cache entry
        cache_path = self.cache_manager._get_cache_path(
            self.test_file,
            "test-scanner"
        )

        # Write corrupt JSON
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w") as f:
            f.write("{invalid json")

        # Should handle gracefully and return None
        result = self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )
        self.assertIsNone(result)

        # Should have logged error
        stats = self.cache_manager.get_cache_stats()
        self.assertGreater(stats["errors"], 0)

    def test_cache_statistics(self):
        """Test cache statistics tracking"""
        # Perform various operations
        self.cache_manager.set_cached_result(
            self.test_file,
            "test-scanner",
            {"results": "test"}
        )

        self.cache_manager.get_cached_result(
            self.test_file,
            "test-scanner"
        )

        self.cache_manager.get_cached_result(
            self.test_file,
            "nonexistent"
        )

        # Check stats
        stats = self.cache_manager.get_cache_stats()

        self.assertEqual(stats["sets"], 1)
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)
        self.assertGreater(stats["total_entries"], 0)
        self.assertGreater(stats["total_size_bytes"], 0)

        # Check hit rate
        self.assertAlmostEqual(stats["hit_rate"], 0.5, places=2)

    def test_per_scanner_statistics(self):
        """Test per-scanner statistics"""
        # Cache for multiple scanners
        self.cache_manager.set_cached_result(
            self.test_file,
            "scanner-a",
            {"results": "a"}
        )

        test_file_2 = os.path.join(self.temp_dir, "test_file_2.py")
        with open(test_file_2, "w") as f:
            f.write("print('test 2')\n")

        self.cache_manager.set_cached_result(
            test_file_2,
            "scanner-a",
            {"results": "a2"}
        )

        self.cache_manager.set_cached_result(
            self.test_file,
            "scanner-b",
            {"results": "b"}
        )

        # Check per-scanner stats
        stats = self.cache_manager.get_cache_stats()
        self.assertIn("scanners", stats)
        self.assertIn("scanner-a", stats["scanners"])
        self.assertIn("scanner-b", stats["scanners"])

        self.assertEqual(stats["scanners"]["scanner-a"]["entries"], 2)
        self.assertEqual(stats["scanners"]["scanner-b"]["entries"], 1)

    def test_thread_safety(self):
        """Test thread-safe operations"""
        num_threads = 10
        results_per_thread = 5

        def cache_operations(thread_id):
            """Perform cache operations in thread"""
            for i in range(results_per_thread):
                # Create unique test file
                file_path = os.path.join(
                    self.temp_dir,
                    f"thread_{thread_id}_file_{i}.py"
                )

                with open(file_path, "w") as f:
                    f.write(f"# Thread {thread_id}, File {i}\n")

                # Set cache
                self.cache_manager.set_cached_result(
                    file_path,
                    "thread-test",
                    {"thread": thread_id, "file": i}
                )

                # Get cache
                self.cache_manager.get_cached_result(
                    file_path,
                    "thread-test"
                )

        # Run concurrent threads
        threads = []
        for tid in range(num_threads):
            thread = threading.Thread(target=cache_operations, args=(tid,))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Check final stats
        stats = self.cache_manager.get_cache_stats()
        expected_sets = num_threads * results_per_thread

        self.assertEqual(stats["sets"], expected_sets)
        self.assertEqual(stats["hits"], expected_sets)

    def test_context_manager(self):
        """Test context manager interface"""
        with CacheManager(cache_dir=self.cache_dir) as cache_mgr:
            cache_mgr.set_cached_result(
                self.test_file,
                "test-scanner",
                {"results": "test"}
            )

            result = cache_mgr.get_cached_result(
                self.test_file,
                "test-scanner"
            )
            self.assertIsNotNone(result)

        # Stats should be saved after context exit
        # (We can't easily verify this without reinitializing)

    def test_nonexistent_file(self):
        """Test handling of nonexistent file"""
        nonexistent = os.path.join(self.temp_dir, "nonexistent.py")

        # Should handle gracefully
        result = self.cache_manager.get_cached_result(
            nonexistent,
            "test-scanner"
        )
        self.assertIsNone(result)

    def test_large_file_hashing(self):
        """Test efficient hashing of large files"""
        # Create large file (1 MB)
        large_file = os.path.join(self.temp_dir, "large_file.py")
        with open(large_file, "w") as f:
            for i in range(10000):
                f.write(f"# Line {i}: " + "x" * 100 + "\n")

        # Hash should work efficiently
        hash1 = self.cache_manager._compute_file_hash(large_file)
        self.assertIsNotNone(hash1)

        # Should be deterministic
        hash2 = self.cache_manager._compute_file_hash(large_file)
        self.assertEqual(hash1, hash2)

    def test_custom_ttl(self):
        """Test custom TTL per cache entry"""
        # Set with 2 second TTL
        self.cache_manager.set_cached_result(
            self.test_file,
            "test-scanner",
            {"results": "test"},
            ttl_seconds=2
        )

        # Should be valid immediately
        self.assertTrue(
            self.cache_manager.is_cache_valid(
                self.test_file,
                "test-scanner"
            )
        )

        # Wait for expiration
        time.sleep(3)

        # Should be invalid
        self.assertFalse(
            self.cache_manager.is_cache_valid(
                self.test_file,
                "test-scanner"
            )
        )


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestCacheManager)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    exit(run_tests())
