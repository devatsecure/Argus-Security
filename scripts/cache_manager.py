#!/usr/bin/env python3
"""
Intelligent Caching System for Agent OS Action
Speeds up repeated scans by caching results with smart invalidation

Features:
- File-based caching (no external dependencies)
- Content-hash based cache keys (SHA256)
- Scanner version tracking
- Configurable TTL (default 7 days)
- Thread-safe operations
- Cache statistics tracking
- Automatic cleanup of stale entries
"""

import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manages file-based caching for security scan results

    Cache Structure:
        .argus-cache/
            {scanner_name}/
                {file_hash}.json
            metadata.json (cache stats)

    Each cache entry contains:
        - file_hash: SHA256 of file content
        - scanner_name: Name of scanner (semgrep, trivy, etc.)
        - scanner_version: Version string for invalidation
        - timestamp: When cached
        - ttl_seconds: Time to live
        - results: Actual scan results
    """

    def __init__(
        self,
        cache_dir: str = ".argus-cache",
        default_ttl_days: int = 7,
        enable_stats: bool = True
    ):
        """
        Initialize cache manager

        Args:
            cache_dir: Directory for cache storage (default: .argus-cache)
            default_ttl_days: Default TTL in days (default: 7)
            enable_stats: Enable statistics tracking (default: True)
        """
        self.cache_dir = Path(cache_dir).resolve()
        self.default_ttl_seconds = default_ttl_days * 24 * 3600
        self.enable_stats = enable_stats

        # Thread safety
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "invalidations": 0,
            "errors": 0,
            "total_size_bytes": 0
        }

        # Decision log path
        self.decision_log_path = self.cache_dir / "decisions.jsonl"

        # Initialize cache directory
        self._initialize_cache()

        # Load existing stats
        if self.enable_stats:
            self._load_stats()

    def _initialize_cache(self) -> None:
        """Create cache directory structure if it doesn't exist"""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Cache directory initialized: {self.cache_dir}")
        except Exception as e:
            logger.error(f"Failed to initialize cache directory: {e}")
            raise

    def _get_scanner_cache_dir(self, scanner_name: str) -> Path:
        """Get cache directory for specific scanner"""
        scanner_dir = self.cache_dir / scanner_name
        scanner_dir.mkdir(parents=True, exist_ok=True)
        return scanner_dir

    def _compute_file_hash(self, file_path: str) -> Optional[str]:
        """
        Compute SHA256 hash of file content

        Args:
            file_path: Path to file

        Returns:
            SHA256 hex digest or None if error
        """
        try:
            file_path = Path(file_path).resolve()

            if not file_path.exists():
                logger.warning(f"File not found for hashing: {file_path}")
                return None

            if not file_path.is_file():
                logger.warning(f"Not a file: {file_path}")
                return None

            # Efficient streaming hash for large files
            sha256_hash = hashlib.sha256()

            with open(file_path, "rb") as f:
                # Read in 64KB chunks for efficiency
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(chunk)

            return sha256_hash.hexdigest()

        except Exception as e:
            logger.error(f"Failed to hash file {file_path}: {e}")
            with self._lock:
                self._stats["errors"] += 1
            return None

    def _get_cache_key(self, file_path: str, scanner_name: str) -> Optional[str]:
        """
        Generate cache key (filename) for a scan result

        Args:
            file_path: Path to scanned file
            scanner_name: Name of scanner

        Returns:
            Cache key (file hash) or None if error
        """
        return self._compute_file_hash(file_path)

    def _get_cache_path(self, file_path: str, scanner_name: str) -> Optional[Path]:
        """
        Get full path to cache file

        Args:
            file_path: Path to scanned file
            scanner_name: Name of scanner

        Returns:
            Path to cache file or None if error
        """
        cache_key = self._get_cache_key(file_path, scanner_name)
        if not cache_key:
            return None

        scanner_dir = self._get_scanner_cache_dir(scanner_name)
        return scanner_dir / f"{cache_key}.json"

    def get_cached_result(
        self,
        file_path: str,
        scanner_name: str,
        scanner_version: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached scan result if valid

        Args:
            file_path: Path to file being scanned
            scanner_name: Name of scanner (e.g., 'semgrep', 'trivy')
            scanner_version: Current scanner version for invalidation

        Returns:
            Cached results dict or None if not found/invalid
        """
        try:
            cache_path = self._get_cache_path(file_path, scanner_name)

            if not cache_path or not cache_path.exists():
                with self._lock:
                    self._stats["misses"] += 1
                logger.debug(f"Cache miss: {file_path} (scanner: {scanner_name})")
                return None

            # Read cache entry
            with open(cache_path, "r") as f:
                cache_entry = json.load(f)

            # Validate cache entry
            if not self._is_cache_entry_valid(
                cache_entry,
                file_path,
                scanner_version
            ):
                with self._lock:
                    self._stats["misses"] += 1
                    self._stats["invalidations"] += 1
                logger.debug(f"Cache invalid: {file_path} (scanner: {scanner_name})")

                # Remove invalid cache
                cache_path.unlink(missing_ok=True)
                return None

            # Cache hit!
            with self._lock:
                self._stats["hits"] += 1

            logger.info(
                f"Cache hit: {file_path} (scanner: {scanner_name}, "
                f"age: {self._format_age(cache_entry['timestamp'])})"
            )

            return cache_entry["results"]

        except json.JSONDecodeError as e:
            logger.warning(f"Corrupt cache file: {cache_path} - {e}")
            with self._lock:
                self._stats["errors"] += 1

            # Remove corrupt cache
            if cache_path and cache_path.exists():
                cache_path.unlink(missing_ok=True)

            return None

        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            with self._lock:
                self._stats["errors"] += 1
            return None

    def set_cached_result(
        self,
        file_path: str,
        scanner_name: str,
        results: Dict[str, Any],
        scanner_version: Optional[str] = None,
        ttl_seconds: Optional[int] = None
    ) -> bool:
        """
        Store scan results in cache

        Args:
            file_path: Path to scanned file
            scanner_name: Name of scanner
            results: Scan results to cache
            scanner_version: Scanner version string
            ttl_seconds: Custom TTL in seconds (default: use default_ttl)

        Returns:
            True if cached successfully, False otherwise
        """
        try:
            cache_path = self._get_cache_path(file_path, scanner_name)

            if not cache_path:
                return False

            # Compute file hash for validation
            file_hash = self._compute_file_hash(file_path)
            if not file_hash:
                return False

            # Create cache entry
            cache_entry = {
                "file_hash": file_hash,
                "file_path": str(Path(file_path).resolve()),
                "scanner_name": scanner_name,
                "scanner_version": scanner_version or "unknown",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": ttl_seconds or self.default_ttl_seconds,
                "results": results
            }

            # Write atomically (write to temp, then rename)
            temp_path = cache_path.with_suffix(".tmp")

            with open(temp_path, "w") as f:
                json.dump(cache_entry, f, indent=2)

            # Atomic rename
            temp_path.rename(cache_path)

            with self._lock:
                self._stats["sets"] += 1

            logger.debug(f"Cached result: {file_path} (scanner: {scanner_name})")

            return True

        except Exception as e:
            logger.error(f"Failed to cache result: {e}")
            with self._lock:
                self._stats["errors"] += 1
            return False

    def is_cache_valid(
        self,
        file_path: str,
        scanner_name: str,
        scanner_version: Optional[str] = None
    ) -> bool:
        """
        Check if cache entry exists and is valid

        Args:
            file_path: Path to file
            scanner_name: Name of scanner
            scanner_version: Current scanner version

        Returns:
            True if valid cache exists, False otherwise
        """
        try:
            cache_path = self._get_cache_path(file_path, scanner_name)

            if not cache_path or not cache_path.exists():
                return False

            with open(cache_path, "r") as f:
                cache_entry = json.load(f)

            return self._is_cache_entry_valid(
                cache_entry,
                file_path,
                scanner_version
            )

        except Exception:
            return False

    def _is_cache_entry_valid(
        self,
        cache_entry: Dict[str, Any],
        file_path: str,
        scanner_version: Optional[str] = None
    ) -> bool:
        """
        Validate cache entry against current file and scanner state

        Validation checks:
        1. File content hasn't changed (hash match)
        2. Cache hasn't expired (TTL check)
        3. Scanner version hasn't changed (if provided)

        Args:
            cache_entry: Cached entry to validate
            file_path: Current file path
            scanner_version: Current scanner version

        Returns:
            True if valid, False otherwise
        """
        try:
            # Check 1: File content hash
            current_hash = self._compute_file_hash(file_path)
            if not current_hash or current_hash != cache_entry.get("file_hash"):
                logger.debug("Cache invalid: file content changed")
                return False

            # Check 2: TTL expiration
            cached_time = datetime.fromisoformat(cache_entry["timestamp"])
            ttl_seconds = cache_entry.get("ttl_seconds", self.default_ttl_seconds)
            expiry_time = cached_time + timedelta(seconds=ttl_seconds)

            if datetime.now(timezone.utc) > expiry_time:
                logger.debug("Cache invalid: TTL expired")
                return False

            # Check 3: Scanner version (if provided)
            if scanner_version:
                cached_version = cache_entry.get("scanner_version")
                if cached_version and cached_version != scanner_version:
                    logger.debug(
                        f"Cache invalid: scanner version changed "
                        f"({cached_version} -> {scanner_version})"
                    )
                    return False

            return True

        except Exception as e:
            logger.debug(f"Cache validation error: {e}")
            return False

    def clear_cache(self, scanner_name: Optional[str] = None) -> int:
        """
        Clear cache entries

        Args:
            scanner_name: If provided, only clear this scanner's cache.
                         If None, clear all caches.

        Returns:
            Number of cache entries deleted
        """
        deleted_count = 0

        try:
            with self._lock:
                if scanner_name:
                    # Clear specific scanner cache
                    scanner_dir = self.cache_dir / scanner_name
                    if scanner_dir.exists():
                        for cache_file in scanner_dir.glob("*.json"):
                            cache_file.unlink()
                            deleted_count += 1

                        # Remove directory if empty
                        if not any(scanner_dir.iterdir()):
                            scanner_dir.rmdir()

                    logger.info(f"Cleared {deleted_count} cache entries for {scanner_name}")
                else:
                    # Clear all caches
                    for scanner_dir in self.cache_dir.glob("*"):
                        if scanner_dir.is_dir():
                            for cache_file in scanner_dir.glob("*.json"):
                                cache_file.unlink()
                                deleted_count += 1

                            # Remove directory if empty
                            if not any(scanner_dir.iterdir()):
                                scanner_dir.rmdir()

                    logger.info(f"Cleared all {deleted_count} cache entries")

                # Reset stats
                self._stats["hits"] = 0
                self._stats["misses"] = 0
                self._stats["sets"] = 0
                self._stats["invalidations"] = 0

            return deleted_count

        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return deleted_count

    def clear_expired(self) -> int:
        """
        Remove expired cache entries

        Returns:
            Number of expired entries removed
        """
        deleted_count = 0

        try:
            with self._lock:
                for scanner_dir in self.cache_dir.glob("*"):
                    if not scanner_dir.is_dir():
                        continue

                    for cache_file in scanner_dir.glob("*.json"):
                        try:
                            with open(cache_file, "r") as f:
                                cache_entry = json.load(f)

                            # Check expiration
                            cached_time = datetime.fromisoformat(
                                cache_entry["timestamp"]
                            )
                            ttl_seconds = cache_entry.get(
                                "ttl_seconds",
                                self.default_ttl_seconds
                            )
                            expiry_time = cached_time + timedelta(seconds=ttl_seconds)

                            if datetime.now(timezone.utc) > expiry_time:
                                cache_file.unlink()
                                deleted_count += 1

                        except Exception as e:
                            logger.debug(f"Error checking expiry for {cache_file}: {e}")
                            # Remove corrupt cache files
                            cache_file.unlink()
                            deleted_count += 1

            if deleted_count > 0:
                logger.info(f"Removed {deleted_count} expired cache entries")

            return deleted_count

        except Exception as e:
            logger.error(f"Error clearing expired cache: {e}")
            return deleted_count

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache statistics:
            - hits: Number of cache hits
            - misses: Number of cache misses
            - sets: Number of cache writes
            - invalidations: Number of invalidated entries
            - errors: Number of errors
            - hit_rate: Cache hit rate (0.0 - 1.0)
            - total_entries: Total cached entries
            - total_size_bytes: Total cache size in bytes
            - total_size_mb: Total cache size in MB
            - scanners: Per-scanner statistics
        """
        try:
            with self._lock:
                stats = self._stats.copy()

                # Calculate hit rate
                total_accesses = stats["hits"] + stats["misses"]
                stats["hit_rate"] = (
                    stats["hits"] / total_accesses if total_accesses > 0 else 0.0
                )

                # Count entries and calculate size
                total_entries = 0
                total_size = 0
                scanner_stats = {}

                for scanner_dir in self.cache_dir.glob("*"):
                    if not scanner_dir.is_dir():
                        continue

                    scanner_name = scanner_dir.name
                    scanner_entries = 0
                    scanner_size = 0

                    for cache_file in scanner_dir.glob("*.json"):
                        scanner_entries += 1
                        scanner_size += cache_file.stat().st_size

                    total_entries += scanner_entries
                    total_size += scanner_size

                    scanner_stats[scanner_name] = {
                        "entries": scanner_entries,
                        "size_bytes": scanner_size,
                        "size_mb": round(scanner_size / (1024 * 1024), 2)
                    }

                stats["total_entries"] = total_entries
                stats["total_size_bytes"] = total_size
                stats["total_size_mb"] = round(total_size / (1024 * 1024), 2)
                stats["scanners"] = scanner_stats

                return stats

        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return self._stats.copy()

    def _load_stats(self) -> None:
        """Load statistics from metadata file"""
        try:
            metadata_path = self.cache_dir / "metadata.json"

            if metadata_path.exists():
                with open(metadata_path, "r") as f:
                    saved_stats = json.load(f)

                # Merge with current stats (preserve runtime stats)
                for key in ["hits", "misses", "sets", "invalidations", "errors"]:
                    if key in saved_stats:
                        self._stats[key] = saved_stats[key]

        except Exception as e:
            logger.debug(f"Could not load stats: {e}")

    def _save_stats(self) -> None:
        """Save statistics to metadata file"""
        try:
            metadata_path = self.cache_dir / "metadata.json"

            with self._lock:
                with open(metadata_path, "w") as f:
                    json.dump(self._stats, f, indent=2)

        except Exception as e:
            logger.debug(f"Could not save stats: {e}")

    def _format_age(self, timestamp_str: str) -> str:
        """Format cache entry age in human-readable format"""
        try:
            cached_time = datetime.fromisoformat(timestamp_str)
            age_seconds = (datetime.now(timezone.utc) - cached_time).total_seconds()

            if age_seconds < 60:
                return f"{int(age_seconds)}s"
            elif age_seconds < 3600:
                return f"{int(age_seconds / 60)}m"
            elif age_seconds < 86400:
                return f"{int(age_seconds / 3600)}h"
            else:
                return f"{int(age_seconds / 86400)}d"

        except Exception:
            return "unknown"

    def log_decision(self, decision_entry: Dict[str, Any]) -> bool:
        """
        Log AI triage decision for analysis and improvement

        Args:
            decision_entry: Dictionary containing decision details:
                - finding_id: Unique finding identifier
                - finding_type: Type of finding (e.g., "secret", "vulnerability")
                - scanner: Scanner that generated the finding
                - decision: "suppress" or "escalate"
                - reasoning: AI's explanation for the decision
                - confidence: Confidence score (0.0-1.0)
                - noise_score: Noise score from heuristic filters
                - model: AI model used (e.g., "claude-sonnet-4-5")
                - timestamp: ISO 8601 timestamp

        Returns:
            True if logged successfully, False otherwise
        """
        try:
            with self._lock:
                # Ensure cache directory exists
                self.cache_dir.mkdir(parents=True, exist_ok=True)

                # Append to decisions log (JSONL format)
                with open(self.decision_log_path, "a") as f:
                    f.write(json.dumps(decision_entry) + "\n")

                logger.debug(
                    f"Logged decision: {decision_entry.get('decision')} "
                    f"for {decision_entry.get('finding_type')} "
                    f"(confidence: {decision_entry.get('confidence', 0):.2f})"
                )

                return True

        except Exception as e:
            logger.error(f"Failed to log decision: {e}")
            with self._lock:
                self._stats["errors"] += 1
            return False

    def get_decision_log(self, limit: Optional[int] = None) -> list:
        """
        Retrieve logged decisions

        Args:
            limit: Maximum number of recent decisions to retrieve (None = all)

        Returns:
            List of decision entries (most recent first)
        """
        try:
            if not self.decision_log_path.exists():
                return []

            decisions = []
            with open(self.decision_log_path, "r") as f:
                for line in f:
                    try:
                        decisions.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.debug(f"Skipping corrupt decision log line: {line[:50]}")
                        continue

            # Return most recent first
            decisions.reverse()

            if limit:
                return decisions[:limit]

            return decisions

        except Exception as e:
            logger.error(f"Failed to read decision log: {e}")
            return []

    def clear_decision_log(self) -> bool:
        """
        Clear all logged decisions

        Returns:
            True if cleared successfully, False otherwise
        """
        try:
            if self.decision_log_path.exists():
                self.decision_log_path.unlink()
                logger.info("Cleared decision log")

            return True

        except Exception as e:
            logger.error(f"Failed to clear decision log: {e}")
            return False

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - save stats"""
        if self.enable_stats:
            self._save_stats()


def print_cache_stats(cache_manager: CacheManager) -> None:
    """Print formatted cache statistics"""
    stats = cache_manager.get_cache_stats()

    print("\n" + "=" * 60)
    print("CACHE STATISTICS")
    print("=" * 60)
    print(f"Hits:           {stats['hits']}")
    print(f"Misses:         {stats['misses']}")
    print(f"Sets:           {stats['sets']}")
    print(f"Invalidations:  {stats['invalidations']}")
    print(f"Errors:         {stats['errors']}")
    print(f"Hit Rate:       {stats['hit_rate']:.1%}")
    print(f"\nTotal Entries:  {stats['total_entries']}")
    print(f"Total Size:     {stats['total_size_mb']} MB")

    if stats['scanners']:
        print(f"\nPer-Scanner Stats:")
        for scanner, scanner_stats in stats['scanners'].items():
            print(f"  {scanner}:")
            print(f"    Entries: {scanner_stats['entries']}")
            print(f"    Size:    {scanner_stats['size_mb']} MB")

    print("=" * 60 + "\n")


def main():
    """CLI interface for cache management"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage Agent OS Action cache"
    )
    parser.add_argument(
        "--cache-dir",
        default=".argus-cache",
        help="Cache directory path (default: .argus-cache)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Stats command
    subparsers.add_parser("stats", help="Show cache statistics")

    # Clear command
    clear_parser = subparsers.add_parser("clear", help="Clear cache")
    clear_parser.add_argument(
        "--scanner",
        help="Only clear this scanner's cache"
    )

    # Clean command
    subparsers.add_parser("clean", help="Remove expired cache entries")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test cache functionality")
    test_parser.add_argument(
        "file_path",
        help="File to test cache with"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize cache manager
    cache_manager = CacheManager(cache_dir=args.cache_dir)

    if args.command == "stats":
        print_cache_stats(cache_manager)

    elif args.command == "clear":
        deleted = cache_manager.clear_cache(scanner_name=args.scanner)
        print(f"Cleared {deleted} cache entries")

    elif args.command == "clean":
        deleted = cache_manager.clear_expired()
        print(f"Removed {deleted} expired entries")

    elif args.command == "test":
        # Test cache functionality
        if not os.path.exists(args.file_path):
            print(f"Error: File not found: {args.file_path}")
            return 1

        scanner_name = "test-scanner"
        test_results = {"test": "data", "timestamp": datetime.now(timezone.utc).isoformat()}

        print(f"\nTesting cache with file: {args.file_path}")
        print(f"Scanner: {scanner_name}\n")

        # Test set
        print("1. Setting cache...")
        success = cache_manager.set_cached_result(
            args.file_path,
            scanner_name,
            test_results
        )
        print(f"   Result: {'Success' if success else 'Failed'}")

        # Test get
        print("\n2. Getting cached result...")
        cached = cache_manager.get_cached_result(args.file_path, scanner_name)
        print(f"   Result: {'Found' if cached else 'Not found'}")

        if cached:
            print(f"   Data: {json.dumps(cached, indent=2)}")

        # Test validation
        print("\n3. Checking if cache is valid...")
        valid = cache_manager.is_cache_valid(args.file_path, scanner_name)
        print(f"   Result: {'Valid' if valid else 'Invalid'}")

        # Show stats
        print("\n4. Cache statistics:")
        print_cache_stats(cache_manager)

    return 0


if __name__ == "__main__":
    exit(main())
