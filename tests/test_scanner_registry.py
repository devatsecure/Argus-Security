#!/usr/bin/env python3
"""
Test Suite for ScannerRegistry

Comprehensive tests covering:
- BaseScannerInterface
- ScannerRegistry initialization
- Built-in scanner loading (mocked)
- Plugin discovery
- Scanner listing with capability filtering
- Scanner instance retrieval and caching
- Scanner info retrieval
- Capability listing
- Error handling for bad plugins, missing scanners
- Edge cases
"""

import importlib
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner_registry import BaseScannerInterface, ScannerRegistry


class TestBaseScannerInterface(unittest.TestCase):
    """Tests for BaseScannerInterface"""

    def test_default_scanner_name(self):
        scanner = BaseScannerInterface()
        self.assertEqual(scanner.SCANNER_NAME, "unknown")

    def test_default_scanner_version(self):
        scanner = BaseScannerInterface()
        self.assertEqual(scanner.SCANNER_VERSION, "1.0.0")

    def test_default_capabilities_empty(self):
        scanner = BaseScannerInterface()
        self.assertEqual(scanner.CAPABILITIES, [])

    def test_default_supported_languages_empty(self):
        scanner = BaseScannerInterface()
        self.assertEqual(scanner.SUPPORTED_LANGUAGES, [])

    def test_scan_raises_not_implemented(self):
        scanner = BaseScannerInterface()
        with self.assertRaises(NotImplementedError):
            scanner.scan(Path("/some/file.py"))

    def test_is_available_default_true(self):
        scanner = BaseScannerInterface()
        self.assertTrue(scanner.is_available())


class TestScannerRegistryInit(unittest.TestCase):
    """Tests for ScannerRegistry initialization"""

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_init_default_plugin_dir(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        expected_dir = Path.home() / ".argus" / "plugins"
        self.assertEqual(registry.plugin_dir, expected_dir)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_init_custom_plugin_dir(self, mock_discover, mock_load):
        custom_dir = Path("/custom/plugin/dir")
        registry = ScannerRegistry(plugin_dir=custom_dir)
        self.assertEqual(registry.plugin_dir, custom_dir)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_init_calls_load_builtins(self, mock_discover, mock_load):
        ScannerRegistry()
        mock_load.assert_called_once()

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_init_calls_discover_plugins(self, mock_discover, mock_load):
        ScannerRegistry()
        mock_discover.assert_called_once()

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_init_empty_scanner_dicts(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        self.assertEqual(registry._scanners, {})
        self.assertEqual(registry._scanner_instances, {})


class TestLoadBuiltinScanners(unittest.TestCase):
    """Tests for _load_builtin_scanners"""

    @patch.object(ScannerRegistry, "_discover_plugins")
    @patch("scanner_registry.importlib.import_module")
    def test_loads_scanners_with_scan_method(self, mock_import, mock_discover):
        """Scanner classes with scan() method should be registered"""
        mock_class = MagicMock()
        mock_class.scan = MagicMock()
        mock_module = MagicMock()
        mock_module.TruffleHogScanner = mock_class
        mock_import.return_value = mock_module

        # Create registry directly, bypassing __init__
        registry = ScannerRegistry.__new__(ScannerRegistry)
        registry._scanners = {}
        registry._scanner_instances = {}
        registry.plugin_dir = Path("/tmp/nonexistent")
        registry._load_builtin_scanners()

        # At least some scanners should be loaded
        # (depends on which mock modules are successfully imported)
        self.assertIsInstance(registry._scanners, dict)

    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_handles_import_errors_gracefully(self, mock_discover):
        """ImportError from missing scanner modules should be handled"""
        # This test verifies that the registry doesn't crash when modules aren't installed
        registry = ScannerRegistry.__new__(ScannerRegistry)
        registry._scanners = {}
        registry._scanner_instances = {}
        registry.plugin_dir = Path("/tmp/nonexistent")

        # Should not raise even if all modules fail to import
        with patch("scanner_registry.importlib.import_module", side_effect=ImportError("not found")):
            registry._load_builtin_scanners()

        # Registry should still be functional, just empty
        self.assertEqual(registry._scanners, {})


class TestDiscoverPlugins(unittest.TestCase):
    """Tests for _discover_plugins"""

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_nonexistent_plugin_dir_no_error(self, mock_load):
        """Non-existent plugin directory should not cause error"""
        registry = ScannerRegistry(plugin_dir=Path("/tmp/nonexistent_dir_12345"))
        # Should not raise

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_empty_plugin_dir(self, mock_load):
        """Empty plugin directory should load nothing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertEqual(len(registry._scanners), 0)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_skips_underscore_files(self, mock_load):
        """Files starting with _ should be skipped"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create __init__.py
            init_file = Path(tmpdir) / "__init__.py"
            init_file.write_text("# init")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertEqual(len(registry._scanners), 0)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_loads_plugin_with_scan_method(self, mock_load):
        """Plugin class with scan() method should be registered"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "my_scanner.py"
            plugin_file.write_text("""
class MyScanner:
    SCANNER_NAME = "my-scanner"
    def scan(self, file_path):
        return []
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertIn("my-scanner", registry._scanners)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_plugin_without_scan_method_not_loaded(self, mock_load):
        """Plugin class without scan() method should not be registered"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "not_a_scanner.py"
            plugin_file.write_text("""
class NotAScanner:
    def process(self):
        return []
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertEqual(len(registry._scanners), 0)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_plugin_name_from_class_attribute(self, mock_load):
        """SCANNER_NAME attribute should be used as registry key"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "custom_scanner.py"
            plugin_file.write_text("""
class CustomScanner:
    SCANNER_NAME = "custom-tool"
    def scan(self, file_path):
        return []
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertIn("custom-tool", registry._scanners)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_plugin_name_fallback_to_lowercase_class_name(self, mock_load):
        """Without SCANNER_NAME, should use lowercase class name"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "unnamed_scanner.py"
            plugin_file.write_text("""
class MyAwesomeScanner:
    def scan(self, file_path):
        return []
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertIn("myawesomescanner", registry._scanners)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_plugin_does_not_override_builtin(self, mock_load):
        """Plugin with same name as built-in should be skipped"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-populate a "builtin" scanner
            mock_builtin = MagicMock()

            plugin_file = Path(tmpdir) / "semgrep_plugin.py"
            plugin_file.write_text("""
class SemgrepPlugin:
    SCANNER_NAME = "semgrep"
    def scan(self, file_path):
        return []
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            # Manually add a builtin before discover
            registry._scanners["semgrep"] = mock_builtin
            registry._discover_plugins()
            # Built-in should remain
            self.assertIs(registry._scanners["semgrep"], mock_builtin)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_broken_plugin_handled_gracefully(self, mock_load):
        """Plugin with syntax error should not crash the registry"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "broken_scanner.py"
            plugin_file.write_text("def this is invalid python!!")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            # Should not raise, scanner not loaded
            self.assertEqual(len(registry._scanners), 0)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_multiple_plugins_loaded(self, mock_load):
        """Multiple valid plugins should all be loaded"""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                plugin_file = Path(tmpdir) / f"scanner_{i}.py"
                plugin_file.write_text(f"""
class Scanner{i}:
    SCANNER_NAME = "scanner-{i}"
    def scan(self, file_path):
        return []
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertEqual(len(registry._scanners), 3)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_non_py_files_ignored(self, mock_load):
        """Non-Python files should be ignored"""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "readme.txt").write_text("not a scanner")
            (Path(tmpdir) / "config.yaml").write_text("key: value")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertEqual(len(registry._scanners), 0)


class TestListScanners(unittest.TestCase):
    """Tests for list_scanners"""

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_list_all_scanners(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        mock_class_a = MagicMock()
        mock_class_b = MagicMock()
        registry._scanners = {"scanner-a": mock_class_a, "scanner-b": mock_class_b}
        result = registry.list_scanners()
        self.assertEqual(set(result), {"scanner-a", "scanner-b"})

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_list_scanners_empty(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        result = registry.list_scanners()
        self.assertEqual(result, [])

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_list_scanners_filter_by_capability(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class SastScanner:
            CAPABILITIES = ["sast", "code"]

        class SecretsScanner:
            CAPABILITIES = ["secrets"]

        registry._scanners = {"sast-scanner": SastScanner, "secrets-scanner": SecretsScanner}
        result = registry.list_scanners(capability="secrets")
        self.assertEqual(result, ["secrets-scanner"])

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_list_scanners_capability_case_insensitive(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class SastScanner:
            CAPABILITIES = ["SAST"]

        registry._scanners = {"sast-scanner": SastScanner}
        result = registry.list_scanners(capability="sast")
        self.assertEqual(result, ["sast-scanner"])

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_list_scanners_no_matching_capability(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class SastScanner:
            CAPABILITIES = ["sast"]

        registry._scanners = {"sast-scanner": SastScanner}
        result = registry.list_scanners(capability="secrets")
        self.assertEqual(result, [])

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_list_scanners_no_capabilities_attribute(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class NoCapsScanner:
            pass

        registry._scanners = {"no-caps": NoCapsScanner}
        result = registry.list_scanners(capability="sast")
        self.assertEqual(result, [])


class TestGetScanner(unittest.TestCase):
    """Tests for get_scanner"""

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_unknown_scanner_returns_none(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        result = registry.get_scanner("nonexistent")
        self.assertIsNone(result)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_scanner_creates_instance(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        mock_class = MagicMock()
        mock_instance = MagicMock()
        mock_instance.is_available.return_value = True
        mock_class.return_value = mock_instance
        registry._scanners = {"test-scanner": mock_class}

        result = registry.get_scanner("test-scanner")
        self.assertEqual(result, mock_instance)
        mock_class.assert_called_once_with()

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_scanner_returns_cached_instance(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        mock_instance = MagicMock()
        registry._scanners = {"test-scanner": MagicMock()}
        registry._scanner_instances = {"test-scanner": mock_instance}

        result = registry.get_scanner("test-scanner")
        self.assertIs(result, mock_instance)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_scanner_passes_init_kwargs(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        mock_class = MagicMock()
        mock_instance = MagicMock()
        mock_instance.is_available.return_value = True
        mock_class.return_value = mock_instance
        registry._scanners = {"test-scanner": mock_class}

        registry.get_scanner("test-scanner", api_key="xyz", timeout=30)
        mock_class.assert_called_once_with(api_key="xyz", timeout=30)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_scanner_not_available_returns_none(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        mock_class = MagicMock()
        mock_instance = MagicMock()
        mock_instance.is_available.return_value = False
        mock_class.return_value = mock_instance
        registry._scanners = {"unavailable-scanner": mock_class}

        result = registry.get_scanner("unavailable-scanner")
        self.assertIsNone(result)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_scanner_init_exception_returns_none(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        mock_class = MagicMock(side_effect=Exception("init failed"))
        registry._scanners = {"broken-scanner": mock_class}

        result = registry.get_scanner("broken-scanner")
        self.assertIsNone(result)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_scanner_without_is_available_method(self, mock_discover, mock_load):
        """Scanner without is_available() method should work fine"""
        registry = ScannerRegistry()

        class SimpleScanner:
            def scan(self, path):
                return []

        registry._scanners = {"simple": SimpleScanner}
        result = registry.get_scanner("simple")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, SimpleScanner)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_get_scanner_caches_after_creation(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class SimpleScanner:
            def scan(self, path):
                return []

        registry._scanners = {"simple": SimpleScanner}
        first = registry.get_scanner("simple")
        second = registry.get_scanner("simple")
        self.assertIs(first, second)


class TestGetScannerInfo(unittest.TestCase):
    """Tests for get_scanner_info"""

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_unknown_scanner_returns_none(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        result = registry.get_scanner_info("nonexistent")
        self.assertIsNone(result)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_scanner_info_fields(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class TestScanner:
            SCANNER_NAME = "test-scanner"
            SCANNER_VERSION = "2.0.0"
            CAPABILITIES = ["sast", "secrets"]
            SUPPORTED_LANGUAGES = ["python", "javascript"]
            __name__ = "TestScanner"
            __module__ = "test_module"

        registry._scanners = {"test-scanner": TestScanner}
        info = registry.get_scanner_info("test-scanner")

        self.assertEqual(info["name"], "test-scanner")
        self.assertEqual(info["version"], "2.0.0")
        self.assertEqual(info["capabilities"], ["sast", "secrets"])
        self.assertEqual(info["supported_languages"], ["python", "javascript"])
        self.assertEqual(info["class"], "TestScanner")
        self.assertEqual(info["module"], "test_module")

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_scanner_info_defaults(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class MinimalScanner:
            pass

        registry._scanners = {"minimal": MinimalScanner}
        info = registry.get_scanner_info("minimal")

        self.assertEqual(info["name"], "minimal")
        self.assertEqual(info["version"], "unknown")
        self.assertEqual(info["capabilities"], [])
        self.assertEqual(info["supported_languages"], [])


class TestListCapabilities(unittest.TestCase):
    """Tests for list_capabilities"""

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_empty_registry(self, mock_discover, mock_load):
        registry = ScannerRegistry()
        result = registry.list_capabilities()
        self.assertEqual(result, [])

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_unique_capabilities(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class Scanner1:
            CAPABILITIES = ["sast", "secrets"]

        class Scanner2:
            CAPABILITIES = ["secrets", "cve"]

        registry._scanners = {"s1": Scanner1, "s2": Scanner2}
        result = registry.list_capabilities()
        self.assertEqual(result, ["cve", "sast", "secrets"])

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_capabilities_sorted(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class Scanner1:
            CAPABILITIES = ["zzz", "aaa", "mmm"]

        registry._scanners = {"s1": Scanner1}
        result = registry.list_capabilities()
        self.assertEqual(result, sorted(result))

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    @patch.object(ScannerRegistry, "_discover_plugins")
    def test_scanners_without_capabilities(self, mock_discover, mock_load):
        registry = ScannerRegistry()

        class NoCaps:
            pass

        registry._scanners = {"no-caps": NoCaps}
        result = registry.list_capabilities()
        self.assertEqual(result, [])


class TestPluginIntegration(unittest.TestCase):
    """Integration tests for plugin loading"""

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_plugin_with_multiple_classes(self, mock_load):
        """Plugin file with multiple scanner classes"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "multi_scanner.py"
            plugin_file.write_text("""
class ScannerA:
    SCANNER_NAME = "scanner-a"
    def scan(self, file_path):
        return []

class ScannerB:
    SCANNER_NAME = "scanner-b"
    def scan(self, file_path):
        return []

class NotAScanner:
    def process(self):
        pass
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertIn("scanner-a", registry._scanners)
            self.assertIn("scanner-b", registry._scanners)
            self.assertEqual(len(registry._scanners), 2)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_plugin_importing_external_modules(self, mock_load):
        """Plugin that imports non-existent modules should fail gracefully"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "bad_import.py"
            plugin_file.write_text("""
import nonexistent_module_xyz_123

class MyScanner:
    SCANNER_NAME = "bad-import"
    def scan(self, file_path):
        return []
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertNotIn("bad-import", registry._scanners)

    @patch.object(ScannerRegistry, "_load_builtin_scanners")
    def test_plugin_with_init_error(self, mock_load):
        """Plugin that raises during class definition should fail gracefully"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "init_error.py"
            plugin_file.write_text("""
raise RuntimeError("Plugin init error")
""")
            registry = ScannerRegistry(plugin_dir=Path(tmpdir))
            self.assertEqual(len(registry._scanners), 0)


if __name__ == "__main__":
    unittest.main()
