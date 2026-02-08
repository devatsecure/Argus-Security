#!/usr/bin/env python3
"""
Scanner Registry for Argus
Discover and load security scanners dynamically (built-in + plugins)

Features:
- Auto-discovery of built-in scanners
- Plugin loading from ~/.argus/plugins/
- Scanner capability filtering
- Version tracking and compatibility
- Graceful failure handling
"""

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BaseScannerInterface:
    """
    Base interface that all scanners must implement

    This is a minimal interface - scanners can have additional methods
    """

    # Scanner metadata (subclasses should override)
    SCANNER_NAME = "unknown"
    SCANNER_VERSION = "1.0.0"
    CAPABILITIES = []  # e.g., ["secrets", "sast", "cve", "iac"]
    SUPPORTED_LANGUAGES = []  # e.g., ["python", "javascript", "go"]

    def scan(self, file_path: Path) -> List[Dict]:
        """
        Scan a file and return findings

        Args:
            file_path: Path to file to scan

        Returns:
            List of finding dictionaries
        """
        raise NotImplementedError("Scanners must implement scan() method")

    def is_available(self) -> bool:
        """
        Check if scanner is available (binary installed, etc.)

        Returns:
            True if scanner can be used, False otherwise
        """
        return True


class ScannerRegistry:
    """Discover and load security scanners dynamically"""

    def __init__(self, plugin_dir: Optional[Path] = None):
        """
        Initialize scanner registry

        Args:
            plugin_dir: Directory for plugin scanners (default: ~/.argus/plugins)
        """
        self._scanners: Dict[str, Type[BaseScannerInterface]] = {}
        self._scanner_instances: Dict[str, BaseScannerInterface] = {}

        # Default plugin directory
        if plugin_dir is None:
            plugin_dir = Path.home() / ".argus" / "plugins"

        self.plugin_dir = Path(plugin_dir)

        # Load scanners
        self._load_builtin_scanners()
        self._discover_plugins()

    def _load_builtin_scanners(self):
        """Load built-in scanners from scripts/scanners/ directory"""
        try:
            import sys
            scripts_dir = Path(__file__).parent
            if str(scripts_dir) not in sys.path:
                sys.path.insert(0, str(scripts_dir))

            # Import built-in scanners
            builtin_scanners = {
                "trufflehog": ("trufflehog_scanner", "TruffleHogScanner"),
                "semgrep": ("semgrep_scanner", "SemgrepScanner"),
                "trivy": ("trivy_scanner", "TrivyScanner"),
                "checkov": ("checkov_scanner", "CheckovScanner"),
                "api-security": ("api_security_scanner", "APISecurityScanner"),
                "dast": ("dast_scanner", "DASTScanner"),
                "supply-chain": ("supply_chain_analyzer", "SupplyChainAnalyzer"),
                "fuzzing": ("fuzzing_engine", "FuzzingEngine"),
                "threat-intel": ("threat_intel_enricher", "ThreatIntelEnricher"),
                "remediation": ("remediation_engine", "RemediationEngine"),
                "runtime-security": ("runtime_security_monitor", "RuntimeSecurityMonitor"),
                "regression-testing": ("regression_tester", "RegressionTester"),
            }

            for scanner_name, (module_name, class_name) in builtin_scanners.items():
                try:
                    module = importlib.import_module(module_name)
                    scanner_class = getattr(module, class_name)

                    # Accept scanners with scan(), analyze(), or any scan-like method
                    scan_methods = ("scan", "scan_file", "scan_filesystem", "scan_container_image",
                                    "analyze", "analyze_project", "analyze_package_behavior",
                                    "fuzz_function", "fuzz_api", "enrich_findings", "enrich_cve",
                                    "suggest_fix", "generate_batch_fixes",
                                    "monitor_realtime", "analyze_log_file",
                                    "generate_regression_test", "run_all_tests",
                                    "check_typosquatting", "check_openssf_scorecard")
                    if any(hasattr(scanner_class, m) for m in scan_methods):
                        self._scanners[scanner_name] = scanner_class
                        logger.debug(f"Loaded built-in scanner: {scanner_name}")
                    else:
                        logger.warning(f"Scanner {scanner_name} missing scan-like method")

                except (ImportError, AttributeError) as e:
                    logger.debug(f"Could not load built-in scanner {scanner_name}: {e}")
                    continue

            logger.info(f"Loaded {len(self._scanners)} built-in scanners")

        except Exception as e:
            logger.error(f"Error loading built-in scanners: {e}")

    def _discover_plugins(self):
        """Load scanner plugins from filesystem"""
        if not self.plugin_dir.exists():
            logger.debug(f"Plugin directory does not exist: {self.plugin_dir}")
            return

        plugin_count = 0

        for plugin_file in self.plugin_dir.glob("*.py"):
            try:
                # Skip __init__.py and hidden files
                if plugin_file.name.startswith("_"):
                    continue

                # Load module from file
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem,
                    plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find classes that look like scanners
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Skip imports and base classes
                    if obj.__module__ != module.__name__:
                        continue

                    # Check if it has scan method
                    if hasattr(obj, 'scan') and callable(getattr(obj, 'scan')):
                        scanner_name = getattr(obj, "SCANNER_NAME", name.lower())

                        # Don't override built-in scanners
                        if scanner_name in self._scanners:
                            logger.warning(
                                f"Plugin scanner '{scanner_name}' conflicts with built-in, skipping"
                            )
                            continue

                        self._scanners[scanner_name] = obj
                        logger.info(f"Loaded plugin scanner: {scanner_name} from {plugin_file.name}")
                        plugin_count += 1

            except Exception as e:
                logger.warning(f"Failed to load plugin {plugin_file.name}: {e}")
                continue

        if plugin_count > 0:
            logger.info(f"Loaded {plugin_count} plugin scanners")

    def list_scanners(self, capability: Optional[str] = None) -> List[str]:
        """
        List available scanners, optionally filtered by capability

        Args:
            capability: Filter by capability (e.g., "secrets", "sast", "cve")

        Returns:
            List of scanner names
        """
        scanners = list(self._scanners.keys())

        if capability:
            # Filter by capability
            filtered = []
            for name in scanners:
                scanner_class = self._scanners[name]
                capabilities = getattr(scanner_class, "CAPABILITIES", [])
                if capability.lower() in [c.lower() for c in capabilities]:
                    filtered.append(name)
            return filtered

        return scanners

    def get_scanner(self, name: str, **init_kwargs) -> Optional[BaseScannerInterface]:
        """
        Get scanner instance by name

        Args:
            name: Scanner name
            **init_kwargs: Arguments to pass to scanner constructor

        Returns:
            Scanner instance or None if not found
        """
        if name not in self._scanners:
            logger.error(f"Unknown scanner: {name}")
            return None

        # Return cached instance if available
        if name in self._scanner_instances:
            return self._scanner_instances[name]

        # Create new instance
        try:
            scanner_class = self._scanners[name]
            instance = scanner_class(**init_kwargs)

            # Check if scanner is available
            if hasattr(instance, 'is_available') and not instance.is_available():
                logger.warning(f"Scanner {name} is not available (missing dependencies or binary)")
                return None

            # Cache instance
            self._scanner_instances[name] = instance
            return instance

        except Exception as e:
            logger.error(f"Failed to instantiate scanner {name}: {e}")
            return None

    def get_scanner_info(self, name: str) -> Optional[Dict]:
        """
        Get scanner metadata

        Args:
            name: Scanner name

        Returns:
            Dictionary with scanner info or None if not found
        """
        if name not in self._scanners:
            return None

        scanner_class = self._scanners[name]

        return {
            "name": getattr(scanner_class, "SCANNER_NAME", name),
            "version": getattr(scanner_class, "SCANNER_VERSION", "unknown"),
            "capabilities": getattr(scanner_class, "CAPABILITIES", []),
            "supported_languages": getattr(scanner_class, "SUPPORTED_LANGUAGES", []),
            "class": scanner_class.__name__,
            "module": scanner_class.__module__,
        }

    def list_capabilities(self) -> List[str]:
        """
        List all available capabilities across all scanners

        Returns:
            List of unique capability strings
        """
        capabilities = set()

        for scanner_class in self._scanners.values():
            caps = getattr(scanner_class, "CAPABILITIES", [])
            capabilities.update(caps)

        return sorted(list(capabilities))


def main():
    """CLI interface for scanner registry"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage Argus scanner registry"
    )
    parser.add_argument(
        "--plugin-dir",
        help="Plugin directory path"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List scanners
    list_parser = subparsers.add_parser("list", help="List available scanners")
    list_parser.add_argument(
        "--capability",
        help="Filter by capability (e.g., secrets, sast, cve)"
    )

    # Show scanner info
    info_parser = subparsers.add_parser("info", help="Show scanner information")
    info_parser.add_argument("scanner_name", help="Scanner name")

    # List capabilities
    subparsers.add_parser("capabilities", help="List all capabilities")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize registry
    registry = ScannerRegistry(plugin_dir=args.plugin_dir)

    if args.command == "list":
        scanners = registry.list_scanners(capability=args.capability)

        if args.capability:
            print(f"\nScanners with capability '{args.capability}':")
        else:
            print("\nAvailable scanners:")

        if not scanners:
            print("  (none)")
        else:
            for scanner in scanners:
                info = registry.get_scanner_info(scanner)
                caps = ", ".join(info.get("capabilities", []))
                print(f"  • {scanner:15s} - {caps}")

        print(f"\nTotal: {len(scanners)} scanners\n")

    elif args.command == "info":
        info = registry.get_scanner_info(args.scanner_name)

        if not info:
            print(f"❌ Scanner not found: {args.scanner_name}")
            return 1

        print(f"\n{'='*60}")
        print(f"SCANNER INFORMATION: {args.scanner_name}")
        print("=" * 60)
        print(f"Name:                {info['name']}")
        print(f"Version:             {info['version']}")
        print(f"Capabilities:        {', '.join(info['capabilities'])}")
        print(f"Supported Languages: {', '.join(info['supported_languages'])}")
        print(f"Class:               {info['class']}")
        print(f"Module:              {info['module']}")
        print("=" * 60 + "\n")

    elif args.command == "capabilities":
        capabilities = registry.list_capabilities()

        print("\nAvailable capabilities:")
        for cap in capabilities:
            scanners = registry.list_scanners(capability=cap)
            print(f"  • {cap:15s} - {len(scanners)} scanners ({', '.join(scanners)})")

        print(f"\nTotal: {len(capabilities)} capabilities\n")

    return 0


if __name__ == "__main__":
    exit(main())
