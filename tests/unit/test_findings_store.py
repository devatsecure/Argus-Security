#!/usr/bin/env python3
"""Dedicated unit tests for FindingsStore (edge cases and API stability)."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from findings_store import FindingsStore, ScanSummary


class TestFindingsStoreEdgeCases:
    """Edge cases: empty inputs, missing keys, get_finding for unknown id."""

    def test_record_scan_empty_findings(self, tmp_path):
        """record_scan with empty list returns summary with zeros."""
        db_path = str(tmp_path / "store.db")
        store = FindingsStore(db_path=db_path)
        summary = store.record_scan("scan-empty", [], commit_sha="abc")
        assert isinstance(summary, ScanSummary)
        assert summary.scan_id == "scan-empty"
        assert summary.total_findings == 0
        assert summary.new_findings == 0
        assert summary.regressions == 0
        store.close()

    def test_get_finding_nonexistent_returns_none(self, tmp_path):
        """get_finding for unknown id returns None."""
        db_path = str(tmp_path / "store.db")
        store = FindingsStore(db_path=db_path)
        assert store.get_finding("no-such-id") is None
        store.close()

    def test_fingerprint_minimal_finding(self):
        """fingerprint_finding with minimal keys still produces stable hash."""
        minimal = {"file_path": "a.py", "vuln_type": "xss"}
        fp = FindingsStore.fingerprint_finding(minimal)
        assert len(fp) == 16
        assert fp == FindingsStore.fingerprint_finding(minimal)

    def test_fingerprint_ignores_id_field(self):
        """Fingerprint should not depend on finding id (content-based)."""
        a = {"id": "f1", "file_path": "x.py", "vuln_type": "sqli", "cwe": "CWE-89"}
        b = {"id": "f2", "file_path": "x.py", "vuln_type": "sqli", "cwe": "CWE-89"}
        assert FindingsStore.fingerprint_finding(a) == FindingsStore.fingerprint_finding(b)
